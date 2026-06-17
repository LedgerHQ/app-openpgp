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
export const SW1_MORE_DATA = 0x61;

// Largest data chunk per command-chaining frame (matches the python tool).
export const APDU_MAX_SIZE = 0xfe;
// CLA bit flagging an intermediate command-chaining frame.
export const APDU_CHAINING_MODE = 0x10;

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
        await transport.exchange(
          Buffer.concat([chained, rest.slice(0, APDU_MAX_SIZE)])
        );
        rest = rest.slice(APDU_MAX_SIZE);
      }
    }
    frame = Buffer.concat([header, Buffer.from([rest.length]), rest]);
  }

  let response = await transport.exchange(frame);
  let respData = response.slice(0, response.length - 2);
  let sw = response.readUInt16BE(response.length - 2);

  while (sw >> 8 === SW1_MORE_DATA) {
    const le = sw & 0xff;
    response = await transport.exchange(Buffer.from([0x00, 0xc0, 0x00, 0x00, le]));
    respData = Buffer.concat([respData, response.slice(0, response.length - 2)]);
    sw = response.readUInt16BE(response.length - 2);
  }
  return { data: respData, sw };
}

// GET DATA (INS 0xCA, or 0xCC for the next occurrence). Returns the value
// bytes; the status word is ignored, like the python `_get_data`.
export async function getData(transport, tag, bnext = false) {
  const ins = bnext ? 0xcc : 0xca;
  const header = Buffer.from([0x00, ins, (tag >> 8) & 0xff, tag & 0xff, 0x00]);
  const { data } = await exchange(transport, header);
  return data;
}

// PUT DATA (INS 0xDA). Returns the status word, like the python `_put_data`.
export async function putData(transport, tag, data) {
  const header = Buffer.from([0x00, 0xda, (tag >> 8) & 0xff, tag & 0xff]);
  const { sw } = await exchange(transport, header, data);
  return sw;
}
