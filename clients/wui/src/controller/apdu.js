// Low-level APDU exchange over a Ledger HID transport.
//
// `transport.exchange(buffer)` sends one full APDU and returns the raw
// response (data bytes followed by the 2-byte status word). On top of that we
// add the OpenPGP smartcard (T=0) semantics that the generic transport does
// NOT handle on its own, mirroring pytools/gpgapp/gpgcard.py `_exchange`:
//
//   - Command chaining (CLA | 0x10): outgoing data longer than APDU_MAX_SIZE
//     is split into 0xFE-byte frames, the last frame carrying the original CLA.
//   - GET RESPONSE (SW1 == 0x61): the card signals SW2 more bytes are
//     available; we issue `00 C0 00 00 <le>` until the response is drained
//     (e.g. to read RSA-4096 public keys).

export const SW_SUCCESS = 0x9000;
export const SW_CONDITIONS_NOT_SATISFIED = 0x6985;
export const SW_INS_NOT_SUPPORTED = 0x6d00;
export const SW1_MORE_DATA = 0x61;

// Largest data chunk per command-chaining frame (matches the python tool).
export const APDU_MAX_SIZE = 0xfe;
// CLA bit flagging an intermediate command-chaining frame.
export const APDU_CHAINING_MODE = 0x10;
// Size of the device buffer receiving a whole command chain.
export const CHAIN_MAX_SIZE = 1512;
// Bounds of a response received through GET RESPONSE.
export const RESPONSE_MAX_SIZE = 0x4000;
export const RESPONSE_MAX_CHUNKS = 64;

// Map of the OpenPGP status words we want to surface with a readable message.
const ERROR_MESSAGES = Object.freeze({
  0x6285: "Selected file in termination state",
  0x6581: "Memory failure",
  0x6700: "Wrong length (Lc and/or Le)",
  0x6982: "Security status not satisfied (PIN required?)",
  0x6983: "Authentication method blocked",
  0x6985: "Condition of use not satisfied",
  0x6a80: "Incorrect parameters in the data field",
  0x6a82: "File or application not found",
  0x6a86: "Incorrect P1-P2",
  0x6a88: "Referenced data not found",
  0x6d00: "Instruction (INS) not supported",
  0x6e00: "Class (CLA) not supported",
});

export function statusMessage(sw) {
  const hex = sw.toString(16).padStart(4, "0");
  return ERROR_MESSAGES[sw] || `SW=0x${hex}`;
}

// Split a raw response into its data and its 2-byte status word.
function parseResponse(response) {
  if (response.length < 2) {
    throw new Error("Truncated response from the device");
  }
  return {
    data: response.slice(0, response.length - 2),
    sw: response.readUInt16BE(response.length - 2),
  };
}

function toBuffer(value) {
  return typeof value === "string" ? Buffer.from(value, "hex") : Buffer.from(value);
}

// Send an APDU and return { data: Buffer, sw: number }.
//
// `apdu` is the command bytes (hex string or Buffer). For read commands it
// already includes Le (e.g. "00CA004F00"); for write commands it is the bare
// 4-byte header (CLA INS P1 P2) and `data` carries the payload, whose length
// (with command chaining when needed) is appended here.
export async function exchange(transport, apdu, data = Buffer.alloc(0)) {
  const header = toBuffer(apdu);
  const payload = toBuffer(data);

  if (payload.length > CHAIN_MAX_SIZE) {
    throw new Error(`Data too long for the device (${payload.length} bytes)`);
  }

  // The command copies may carry PINs or private data: overwrite them once sent
  const send = async (frame) => {
    try {
      return parseResponse(await transport.exchange(frame));
    } finally {
      frame.fill(0);
    }
  };

  let response;
  try {
    let frame = header;
    if (payload.length > 0) {
      let rest = payload;
      if (rest.length > APDU_MAX_SIZE) {
        const chained = Buffer.from([
          header[0] | APDU_CHAINING_MODE,
          header[1],
          header[2],
          header[3],
          APDU_MAX_SIZE,
        ]);
        while (rest.length > APDU_MAX_SIZE) {
          const { sw } = await send(Buffer.concat([chained, rest.slice(0, APDU_MAX_SIZE)]));
          // A refused frame aborts the chain: the rest must not be sent alone
          if (sw !== SW_SUCCESS) {
            return { data: Buffer.alloc(0), sw };
          }
          rest = rest.slice(APDU_MAX_SIZE);
        }
      }
      frame = Buffer.concat([header, Buffer.from([rest.length]), rest]);
    }
    response = await send(frame);
  } finally {
    header.fill(0);
    payload.fill(0);
  }

  let { data: respData, sw } = response;

  let chunks = 0;
  while (sw >> 8 === SW1_MORE_DATA) {
    chunks += 1;
    if (chunks > RESPONSE_MAX_CHUNKS || respData.length > RESPONSE_MAX_SIZE) {
      throw new Error("Response from the device is too long");
    }
    const le = sw & 0xff;
    const next = parseResponse(
      await transport.exchange(Buffer.from([0x00, 0xc0, 0x00, 0x00, le]))
    );
    respData = Buffer.concat([respData, next.data]);
    sw = next.sw;
  }
  return { data: respData, sw };
}

// GET DATA (INS 0xCA, or 0xCC for the next occurrence). Returns the value
// bytes, and throws on any status word other than success, except those listed
// in `missing`, which mean an absent value and return an empty buffer.
export async function getData(transport, tag, bnext = false, missing = []) {
  const ins = bnext ? 0xcc : 0xca;
  const header = Buffer.from([0x00, ins, (tag >> 8) & 0xff, tag & 0xff, 0x00]);
  const { data, sw } = await exchange(transport, header);
  if (missing.includes(sw)) {
    return Buffer.alloc(0);
  }
  if (sw !== SW_SUCCESS) {
    const hex = tag.toString(16).padStart(4, "0");
    throw new Error(`Unable to read data object ${hex} (${statusMessage(sw)})`);
  }
  return data;
}

// SELECT DATA (INS 0xA5) of occurrence `occurrence` of `tag`. Returns false
// when the device does not support it, and throws on any other error.
export async function selectData(transport, tag, occurrence) {
  const header = Buffer.from([0x00, 0xa5, occurrence, 0x04]);
  const data = Buffer.from([0x60, 0x04, 0x5c, 0x02, (tag >> 8) & 0xff, tag & 0xff]);
  const { sw } = await exchange(transport, header, data);
  if (sw === SW_INS_NOT_SUPPORTED) {
    return false;
  }
  if (sw !== SW_SUCCESS) {
    throw new Error(`Unable to select occurrence ${occurrence} (${statusMessage(sw)})`);
  }
  return true;
}

// PUT DATA (INS 0xDA). Returns the status word, like the python `_put_data`.
export async function putData(transport, tag, data) {
  const header = Buffer.from([0x00, 0xda, (tag >> 8) & 0xff, tag & 0xff]);
  const { sw } = await exchange(transport, header, data);
  return sw;
}
