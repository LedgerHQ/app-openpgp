import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import {
  exchange,
  getData,
  putData,
  selectData,
  statusMessage,
  SW_CONDITIONS_NOT_SATISFIED,
  SW_SUCCESS,
} from "./apdu.js";
import { checkLength, decodeTLV, getInt } from "./tlv.js";
import { DO, USER_SALUTATION, doName } from "./dataObjects.js";
import { buildBackup, FINGERPRINT_SIZE, parseBackup, securityChanges } from "./backupFormat.js";
import { keyFingerprint } from "./pubkeyPacket.js";

// OpenPGP application identifier: RID D2:76:00:01:24 + application 01.
// (matches `00A4040006D27600012401` used by the python backup tool)
const OPENPGP_AID = "D27600012401";
const SELECT_APDU = "00A4040006" + OPENPGP_AID;
// GET DATA on tag 0x4F (full Application Identifier).
const GET_DATA_AID = "00CA004F00";
// Full AID length, including the manufacturer and the serial number
const AID_LENGTH = 16;
// Number of key slots of the app
const SLOT_COUNT = 3;
// Algorithm identifiers of the key attributes: RSA, ECDH, ECDSA, EdDSA
const KEY_ALGORITHMS = [0x01, 0x12, 0x13, 0x16];
// Largest key attributes value
const KEY_ATTRIBUTES_MAX_SIZE = 12;
// Longest wait, on a disconnection, for the running operation to clear the PINs
const DISCONNECT_TIMEOUT_MS = 2000;

// Key attributes read from the card, with a known algorithm
function checkAttribute(name, value) {
  if (!value || value.length === 0 || value.length > KEY_ATTRIBUTES_MAX_SIZE || !KEY_ALGORITHMS.includes(value[0])) {
    throw new Error(`Unexpected ${name} key attributes from the device`);
  }
  return value;
}

// Nonce size of the key backup formats 2 and 3
const KEY_BACKUP_NONCE_SIZE = 12;
// AES-GCM tag of the key backup formats 1 to 3; AES block of the legacy format, padded (ISO 9797-1 M2)
const KEY_BACKUP_TAG_SIZE = 16;
const AES_BLOCK_SIZE = 16;
// Sizes of the SDK key structures in a key backup: EC public and private keys, RSA public exponent
const EC_PUBLIC_KEY_SIZE = 172;
const EC_PRIVATE_KEY_SIZE = 88;
const RSA_PUBLIC_EXPONENT_SIZE = 4;

// Public key and private key structure sizes of a key, from its attributes
function keyBlobSizes(attribute) {
  if (attribute[0] !== 0x01) return [EC_PUBLIC_KEY_SIZE, EC_PRIVATE_KEY_SIZE];
  if (attribute.length < 3) return null;
  // size, private exponent and modulus
  const modulusSize = attribute.readUInt16BE(1) / 8;
  return [RSA_PUBLIC_EXPONENT_SIZE, 4 + 2 * modulusSize];
}

// Encrypted key read for a backup: a header, then the public key and the encrypted private key,
// each with a 4-byte length and the size the device writes for the key attributes. The format 3
// header binds the key reference and attributes; a blob without format byte (legacy) starts with
// the 4-byte TARGET_ID.
function checkKeyBlob(name, blob, ref, attribute) {
  if (blob.length === 0) return blob;
  const invalid = new Error(`Unexpected ${name} key backup from the device`);
  const sizes = keyBlobSizes(attribute);
  if (!sizes) throw invalid;
  const [publicSize, privateSize] = sizes;
  let encryptedSize = privateSize + KEY_BACKUP_TAG_SIZE;
  let offset;
  switch (blob[0]) {
    case 0x01:
      offset = 1 + 4 + 4;
      break;
    case 0x02:
      offset = 1 + 4 + 4 + KEY_BACKUP_NONCE_SIZE;
      break;
    case 0x03: {
      offset = 1 + KEY_BACKUP_NONCE_SIZE;
      if (blob.length < offset + 3 || blob.readUInt16BE(offset) !== ref) throw invalid;
      const end = offset + 3 + blob[offset + 2];
      if (end > blob.length || !blob.subarray(offset + 3, end).equals(attribute)) throw invalid;
      offset = end;
      break;
    }
    default:
      offset = 4 + 4;
      encryptedSize = (Math.floor(privateSize / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
      break;
  }
  for (const size of [publicSize, encryptedSize]) {
    if (offset + 4 > blob.length || blob.readUInt32BE(offset) !== size) throw invalid;
    offset += 4 + size;
  }
  if (offset !== blob.length) throw invalid;
  return blob;
}

// Password references (ISO 7816 / OpenPGP).
export const PW = Object.freeze({
  PW1: 0x81, // user PIN, single PSO:CDS
  PW2: 0x82, // user PIN, multiple attempts
  PW3: 0x83, // admin PIN
});

function emptyKey() {
  return {
    attribute: Buffer.alloc(0),
    fingerprint: Buffer.alloc(0),
    ca_fingerprint: Buffer.alloc(0),
    cert: Buffer.alloc(0),
    date: 0,
    uif: 0,
    key: Buffer.alloc(0),
  };
}

function newCardInfo() {
  return {
    AID: "",
    extLength: Buffer.alloc(0),
    extCapabilities: Buffer.alloc(0),
    histoBytes: Buffer.alloc(0),
    PWStatus: Buffer.alloc(0),
    hwFeatures: 0,
    name: "",
    login: "",
    url: "",
    lang: "",
    salutation: "",
    rsaPubExp: 0,
    digitalCounter: 0,
    sig: emptyKey(),
    dec: emptyKey(),
    aut: emptyKey(),
    private_01: Buffer.alloc(0),
    private_02: Buffer.alloc(0),
    private_03: Buffer.alloc(0),
    private_04: Buffer.alloc(0),
  };
}

// Revoke the WebHID permission of the device, which is granted to the whole
// origin and would otherwise stay usable by any page of that origin.
async function forgetDevice(transport) {
  try {
    await transport.device?.forget?.();
  } catch (e) {
    // ignore: best effort, the permission may already be revoked
  }
}

// GEN ASYM KEYPAIR P2 of a seeded key: current derivation, and legacy one of app 2.x
const SEED_V2 = 0x02;
const SEED_LEGACY = 0x01;

// Algorithm attributes DO of each key
const ATTRIBUTE_TAGS = { [DO.SIG_KEY]: DO.SIG_ATTR, [DO.DEC_KEY]: DO.DEC_ATTR, [DO.AUT_KEY]: DO.AUT_ATTR };
const KEY_ROLES = [
  ["sig", DO.SIG_KEY],
  ["dec", DO.DEC_KEY],
  ["aut", DO.AUT_KEY],
];

// Overwrite the Buffers of a card snapshot, key slots included, once it is no longer needed
function wipeBuffers(object) {
  for (const value of Object.values(object)) {
    if (Buffer.isBuffer(value)) {
      value.fill(0);
    } else if (value && typeof value === "object") {
      wipeBuffers(value);
    }
  }
}

// A backup key slot holds a key when its fingerprint is set
function hasKey(slot) {
  return slot.fingerprint.length === FINGERPRINT_SIZE && slot.fingerprint.some((b) => b !== 0);
}

class GpgManager {
  constructor() {
    this.transport = null;
    this.connected = false;
    this.busy = false;
    // Resolved when the running operation releases its lock
    this._idle = Promise.resolve();
    this._release = null;
    this.aid = null;
    this.serial = null;
    // Pause after a key generation, before the next command, for the device to settle
    this.generationDelay = 2000;
    // Optional callback fired when the device vanishes unexpectedly (e.g. the
    // app crashes and the USB interface drops mid-operation).
    this.onDisconnect = null;
    // Set when we drop the connection on purpose (Disconnect / Quit), so the
    // disconnect handler doesn't raise a spurious "device disconnected" alert.
    this._intentionalClose = false;
  }

  async isSupported() {
    return TransportWebHID.isSupported();
  }

  async connect() {
    if (this.connected) return;
    this._intentionalClose = false;
    if (!(await TransportWebHID.isSupported())) {
      throw new Error(
        "WebHID is not available in this browser. Use Chrome, Edge or Brave."
      );
    }
    if (!this.transport) {
      // request() prompts the device picker (filtered on the Ledger vendor id).
      const transport = await TransportWebHID.request();
      this.transport = transport;
      // The OpenPGP app can crash and drop its USB interface during heavy
      // operations (e.g. key regeneration); surface that instead of hanging.
      // A running operation keeps the lock until it fails on its own transport.
      transport.on("disconnect", () => {
        forgetDevice(transport);
        if (this.transport !== transport) return;
        this.connected = false;
        this.transport = null;
        if (!this._intentionalClose && this.onDisconnect) this.onDisconnect();
      });
    }
    try {
      const select = await exchange(this.transport, SELECT_APDU);
      if (select.sw !== SW_SUCCESS) {
        throw new Error(
          `The OpenPGP app is not opened on the device (${statusMessage(
            select.sw
          )})`
        );
      }
      const aid = await exchange(this.transport, GET_DATA_AID);
      if (aid.sw !== SW_SUCCESS) {
        throw new Error(`Unable to read the AID (${statusMessage(aid.sw)})`);
      }
      this.aid = checkLength("AID", aid.data, AID_LENGTH).toString("hex").toUpperCase();
      if (!this.aid.startsWith(OPENPGP_AID)) {
        throw new Error(`Unexpected AID from the device (${this.aid})`);
      }
      // OpenPGP AID layout: RID[0:10] App[10:12] Version[12:16]
      // Manufacturer[16:20] Serial[20:28] RFU[28:32].
      this.serial = this.aid.slice(20, 28);
      this.connected = true;
    } catch (error) {
      await this.disconnect();
      throw error;
    }
  }

  async disconnect() {
    this._intentionalClose = true;
    this.connected = false;
    this.aid = null;
    this.serial = null;
    if (this.busy) {
      // Let the running operation clear the PINs on the transport before closing it
      let timer;
      const timeout = new Promise((resolve) => {
        timer = setTimeout(resolve, DISCONNECT_TIMEOUT_MS);
      });
      await Promise.race([this._idle, timeout]);
      clearTimeout(timer);
    }
    if (this.transport) {
      try {
        await this.transport.close();
      } catch (e) {
        // ignore: device may already be gone
      }
      await forgetDevice(this.transport);
    }
    this.transport = null;
  }

  // Take the operation lock and return the transport the operation must use.
  _lock() {
    if (this.busy) throw new Error("Device is busy");
    if (!this.transport) throw new Error("Device not connected");
    this.busy = true;
    this._idle = new Promise((resolve) => {
      this._release = resolve;
    });
    return this.transport;
  }

  _unlock() {
    this.busy = false;
    this._release?.();
    this._release = null;
  }

  // Leave PW1, PW2 and PW3 not verified (VERIFY with P1=FF). Best effort: a
  // failure must not hide the result of the operation.
  async _logout(t) {
    for (const pw of [PW.PW1, PW.PW2, PW.PW3]) {
      try {
        await exchange(t, Buffer.from([0x00, 0x20, 0xff, pw, 0x00]));
      } catch (e) {
        // ignore: the device may be gone
      }
    }
  }

  // PIN verification (00 20 00 <pw> Lc <pin>). Returns success boolean.
  async verifyPin(pw, value, t = this.transport) {
    const pin = Buffer.from(value || "", "utf-8");
    const apdu = Buffer.concat([Buffer.from([0x00, 0x20, 0x00, pw, pin.length]), pin]);
    try {
      const { sw } = await exchange(t, apdu);
      return sw === SW_SUCCESS;
    } finally {
      pin.fill(0);
      apdu.fill(0);
    }
  }

  // Read every data object needed for a backup, ported from gpgcard.py
  // `get_all`. Returns the CardInfo structure consumed by buildBackup().
  async getAll(t = this.transport) {
    const data = newCardInfo();

    data.AID = checkLength("AID", await getData(t, DO.AID), AID_LENGTH).toString("hex").toUpperCase();
    if (!data.AID.startsWith(OPENPGP_AID)) {
      throw new Error(`Unexpected AID from the device (${data.AID})`);
    }
    data.login = (await getData(t, DO.LOGIN)).toString("utf-8");
    data.url = (await getData(t, DO.URL)).toString("utf-8");
    data.histoBytes = await getData(t, DO.HIST);
    const features = await getData(t, DO.GEN_FEATURES);
    if (features.length) data.hwFeatures = features[0];

    // Cardholder Related Data (0x65)
    let tags = decodeTLV(await getData(t, DO.CARDHOLDER_DATA));
    if (tags[DO.CARD_NAME]) data.name = tags[DO.CARD_NAME].toString("utf-8");
    if (tags[DO.CARD_SALUTATION]) {
      const s = tags[DO.CARD_SALUTATION].toString("utf-8");
      for (const [key, value] of Object.entries(USER_SALUTATION)) {
        if (value === s) {
          data.salutation = key;
          break;
        }
      }
    }
    if (tags[DO.CARD_LANG]) data.lang = tags[DO.CARD_LANG].toString("utf-8");

    // Application Related Data (0x6E) -> discretionary data objects (0x73)
    tags = decodeTLV(await getData(t, DO.APP_DATA));
    if (tags[DO.EXT_LEN]) data.extLength = tags[DO.EXT_LEN];
    if (!tags[DO.DISCRET_DATA]) {
      throw new Error("Missing discretionary data objects from the device");
    }
    const d = decodeTLV(tags[DO.DISCRET_DATA]);
    if (d[DO.EXT_CAP]) data.extCapabilities = d[DO.EXT_CAP];
    data.sig.attribute = checkAttribute("signature", d[DO.SIG_ATTR]);
    data.dec.attribute = checkAttribute("decryption", d[DO.DEC_ATTR]);
    data.aut.attribute = checkAttribute("authentication", d[DO.AUT_ATTR]);
    data.PWStatus = checkLength("PW status", d[DO.PW_STATUS], 7);

    const fp = checkLength("fingerprints", d[DO.FINGERPRINTS], 60);
    data.sig.fingerprint = fp.slice(0, 20);
    data.dec.fingerprint = fp.slice(20, 40);
    data.aut.fingerprint = fp.slice(40, 60);
    const ca = checkLength("CA fingerprints", d[DO.CA_FINGERPRINTS], 60);
    data.sig.ca_fingerprint = ca.slice(0, 20);
    data.dec.ca_fingerprint = ca.slice(20, 40);
    data.aut.ca_fingerprint = ca.slice(40, 60);
    const dates = checkLength("key dates", d[DO.KEY_DATES], 12);
    data.sig.date = getInt(dates, 4, 0);
    data.dec.date = getInt(dates, 4, 4);
    data.aut.date = getInt(dates, 4, 8);

    data.rsaPubExp = getInt(checkLength("RSA exponent", await getData(t, DO.RSA_EXP), 4), 4);
    // Certificate occurrences: 0 AUT, 1 DEC, 2 SIG
    for (const [occurrence, slot] of [data.aut, data.dec, data.sig].entries()) {
      const selected = await selectData(t, DO.CERT, occurrence);
      slot.cert = await getData(t, DO.CERT, !selected && occurrence > 0);
    }

    data.sig.uif = checkLength("signature UIF", await getData(t, DO.UIF_SIG), 2)[0];
    data.dec.uif = checkLength("decryption UIF", await getData(t, DO.UIF_DEC), 2)[0];
    data.aut.uif = checkLength("authentication UIF", await getData(t, DO.UIF_AUT), 2)[0];

    // Security support template (0x7A) -> digital signature counter (0x93)
    tags = decodeTLV(await getData(t, DO.SEC_TEMPL));
    if (tags[DO.SIG_COUNT]) {
      data.digitalCounter = getInt(checkLength("signature counter", tags[DO.SIG_COUNT], 3), 3);
    }

    // Private DOs are only present when supported by the extended capabilities.
    if (data.extCapabilities.length && data.extCapabilities[0] & 0x08) {
      data.private_01 = await getData(t, DO.PRIVATE_01);
      data.private_02 = await getData(t, DO.PRIVATE_02);
      data.private_03 = await getData(t, DO.PRIVATE_03);
      data.private_04 = await getData(t, DO.PRIVATE_04);
    }

    // Encrypted private key material (only readable in SEED mode with PW3).
    // A slot without key has no key blob to read
    const noKey = [SW_CONDITIONS_NOT_SATISFIED];
    for (const [slot, name, ref] of [
      [data.sig, "signature", DO.SIG_KEY],
      [data.dec, "decryption", DO.DEC_KEY],
      [data.aut, "authentication", DO.AUT_KEY],
    ]) {
      slot.key = checkKeyBlob(name, await getData(t, ref, false, noKey), ref, slot.attribute);
    }

    return data;
  }

  // Verify the user and admin PINs needed for backup/restore. PW1 (0x81) and
  // PW2 (0x82) share the user PIN but gate different operations: PW2 is
  // required to read/write private DOs 0x0101/0x0103 (see the firmware's
  // gpg_check_access_*_DO). Verifying only PW1+PW3 — as the python tool does —
  // silently loses those DOs.
  async verifyPins(userPin, adminPin, t = this.transport) {
    if (!(await this.verifyPin(PW.PW1, userPin, t))) {
      throw new Error("User PIN verification failed");
    }
    if (!(await this.verifyPin(PW.PW2, userPin, t))) {
      throw new Error("User PIN verification failed");
    }
    if (!(await this.verifyPin(PW.PW3, adminPin, t))) {
      throw new Error("Admin PIN verification failed");
    }
  }

  // Read the active key slot (GET DATA 0x01F2, 0-based index), readable without PIN.
  async readSlot(t = this.transport) {
    const index = checkLength("active slot", await getData(t, DO.SLOT_CUR), 1)[0];
    if (index >= SLOT_COUNT) {
      throw new Error(`Unexpected active slot (${index})`);
    }
    return index;
  }

  // Active key slot of the card, 0-based.
  async activeSlot() {
    const t = this._lock();
    try {
      return await this.readSlot(t);
    } finally {
      this._unlock();
    }
  }

  // Select the active key slot (PUT DATA 0x01F2, 0-based index). Requires PW2
  // verified and "Selection by APDU" enabled on the card.
  async selectSlot(index, t = this.transport) {
    const sw = await putData(t, DO.SLOT_CUR, Buffer.from([index]));
    if (sw !== SW_SUCCESS) {
      throw new Error(
        `Slot selection failed (${statusMessage(sw)}) — is "Selection by APDU" enabled on the card?`
      );
    }
  }

  // Read the security settings a restore can change: PW status, and the UIF
  // and algorithm attributes of each key.
  async readSecuritySettings(t = this.transport) {
    const tags = decodeTLV(await getData(t, DO.APP_DATA));
    const d = decodeTLV(tags[DO.DISCRET_DATA] || Buffer.alloc(0));
    const settings = { PWStatus: checkLength("PW status", d[DO.PW_STATUS], 7) };
    for (const [slot, attrTag, uifTag] of [
      ["sig", DO.SIG_ATTR, DO.UIF_SIG],
      ["dec", DO.DEC_ATTR, DO.UIF_DEC],
      ["aut", DO.AUT_ATTR, DO.UIF_AUT],
    ]) {
      settings[slot] = {
        attribute: d[attrTag] || Buffer.alloc(0),
        uif: checkLength(`${slot} UIF`, await getData(t, uifTag), 2)[0],
      };
    }
    return settings;
  }

  // Verify PINs, select the slot, and read the full card state into a backup.
  // The slot active before the backup is selected again afterwards.
  async backup(userPin, adminPin, slot = 0) {
    const t = this._lock();
    try {
      await this.verifyPins(userPin, adminPin, t);
      const active = await this.readSlot(t);
      await this.selectSlot(slot, t);
      try {
        const data = await this.getAll(t);
        try {
          const backup = buildBackup(data);
          // Only save a backup the restore accepts
          try {
            wipeBuffers(parseBackup(backup));
          } catch (e) {
            throw new Error(`Unexpected data from the device: ${e.message}`);
          }
          return backup;
        } finally {
          wipeBuffers(data);
        }
      } finally {
        if (slot !== active) {
          await this.selectSlot(active, t);
        }
      }
    } finally {
      await this._logout(t);
      this._unlock();
    }
  }

  // Regenerate a key deterministically from the device seed (GEN ASYM KEYPAIR,
  // P1=Generate), trying the `derivations` (GEN ASYM KEYPAIR P2) in turn: the
  // backup fingerprint tells which one built the key. Requires the same
  // recovery phrase. Returns the failure, or null, with the matching derivation.
  async seedKey(name, slot, tag, derivations, t = this.transport) {
    const GENERATE = 0x80;
    let failure = null;
    for (const p2 of derivations) {
      // CRT key template: <tag> 00
      const { sw } = await exchange(t, Buffer.from([0x00, 0x47, GENERATE, p2]), Buffer.from([tag, 0x00]));
      await new Promise((resolve) => setTimeout(resolve, this.generationDelay));
      if (sw !== SW_SUCCESS) {
        failure = { tag, name: `${name} (regenerate)`, sw, message: statusMessage(sw) };
        continue;
      }
      const message = await this.checkKey(slot, tag, t);
      if (!message) {
        return { failure: null, derivation: p2 };
      }
      failure = { tag, name: `${name} (fingerprint)`, sw: SW_SUCCESS, message, keyMismatch: true };
    }
    return { failure, derivation: null };
  }

  // Read the public key of a card key (GEN ASYM KEYPAIR, P1=Read): the
  // decoded 7F49 template, and the status word.
  async readPublicKey(tag, t = this.transport) {
    const READ_PUBLIC_KEY = 0x81;
    const header = Buffer.from([0x00, 0x47, READ_PUBLIC_KEY, 0x00]);
    const { data: resp, sw } = await exchange(t, header, Buffer.from([tag, 0x00]));
    const pubkey = sw === SW_SUCCESS ? decodeTLV(decodeTLV(resp)[DO.PUB_KEY] || Buffer.alloc(0)) : null;
    return { pubkey, sw };
  }

  // Check the card key against the fingerprint the backup gives it, computed
  // from its public key, attributes and creation date. Returns the failure
  // message, or null when the key matches.
  async checkKey(slot, tag, t = this.transport) {
    const { pubkey, sw } = await this.readPublicKey(tag, t);
    if (sw !== SW_SUCCESS) {
      return `no key on the card (${statusMessage(sw)})`;
    }
    const fp = await keyFingerprint(slot.attribute, pubkey, slot.date);
    if (fp === null) {
      return "fingerprint cannot be computed for this key algorithm";
    }
    if (!fp.equals(slot.fingerprint)) {
      return "the key on the card does not match the backup (other recovery phrase or modified backup)";
    }
    return null;
  }

  // Factory-reset the app: TERMINATE DF then ACTIVATE FILE, which wipes every
  // key and data object and resets the PINs to their defaults (123456 /
  // 12345678). Requires the admin PIN (PW3). DESTRUCTIVE.
  async factoryReset(adminPin) {
    const t = this._lock();
    try {
      if (!(await this.verifyPin(PW.PW3, adminPin, t))) {
        throw new Error("Admin PIN verification failed");
      }
      let r = await exchange(t, "00E60000"); // TERMINATE DF
      if (r.sw !== SW_SUCCESS) {
        throw new Error(`Terminate failed (${statusMessage(r.sw)})`);
      }
      r = await exchange(t, "00440000"); // ACTIVATE FILE
      if (r.sw !== SW_SUCCESS) {
        throw new Error(`Activate failed (${statusMessage(r.sw)})`);
      }
      // The card is now blank; refresh the AID/serial we display.
      await exchange(t, SELECT_APDU);
      const aid = await exchange(t, GET_DATA_AID);
      if (aid.sw === SW_SUCCESS) {
        this.aid = aid.data.toString("hex").toUpperCase();
        this.serial = this.aid.length >= 28 ? this.aid.slice(20, 28) : null;
      }
    } finally {
      await this._logout(t);
      this._unlock();
    }
  }

  // Write a parsed backup back to the card, ported from gpgcard.py `restore`.
  // Individual PUT DATA failures are collected (not thrown) so a partial
  // restore still completes. The private keys are NOT written from the backup
  // blob (the firmware rejects that on a wiped card); pass regenerateKeys to
  // rebuild them from the device seed instead. Before any write, the security
  // settings the backup changes, and the card keys it erases, are passed to
  // `confirm`, which resolves to true to proceed. Returns the list of failures,
  // or null when not confirmed.
  async restore(userPin, adminPin, json, regenerateKeys = false, slot = 0, confirm = async () => true) {
    const t = this._lock();
    let data = null;
    try {
      data = parseBackup(json);

      await this.verifyPins(userPin, adminPin, t);
      await this.selectSlot(slot, t);

      // Writing the key attributes erases the key: only the changed ones are
      // written, and a key they erase is not restored without regeneration.
      const current = await this.readSecuritySettings(t);
      const changed = {};
      const kept = {};
      const erased = [];
      for (const [role, tag] of KEY_ROLES) {
        changed[role] = !current[role].attribute.equals(data[role].attribute);
        const regenerated = regenerateKeys && hasKey(data[role]);
        const onCard = !regenerated && (await this.readPublicKey(tag, t)).sw === SW_SUCCESS;
        kept[role] = onCard && !changed[role];
        if (onCard && changed[role]) {
          erased.push(role);
        }
      }
      const changes = securityChanges(current, data, erased);
      if (changes.length > 0 && !(await confirm(changes))) {
        return null;
      }

      const failures = [];
      const put = async (tag, value) => {
        const sw = await putData(t, tag, value);
        if (sw !== SW_SUCCESS) {
          failures.push({ tag, name: doName(tag), sw, message: statusMessage(sw) });
        }
      };

      const enc = (s) => Buffer.from(s, "utf-8");
      const u16le = (n) => Buffer.from([n & 0xff, (n >> 8) & 0xff]);
      const u32be = (n) => {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(n >>> 0, 0);
        return b;
      };
      const u32le = (n) => {
        const b = Buffer.alloc(4);
        b.writeUInt32LE(n >>> 0, 0);
        return b;
      };

      // Card serial number lives in AID bytes [10:14] (hex chars [20:28]).
      await put(DO.AID, Buffer.from(data.AID.slice(20, 28), "hex"));
      await put(DO.PW_STATUS, data.PWStatus);

      await put(DO.PRIVATE_01, data.private_01);
      await put(DO.PRIVATE_02, data.private_02);
      await put(DO.PRIVATE_03, data.private_03);
      await put(DO.PRIVATE_04, data.private_04);

      await put(DO.CARD_NAME, enc(data.name));
      await put(DO.LOGIN, enc(data.login));
      await put(DO.CARD_LANG, enc(data.lang));
      await put(DO.URL, enc(data.url));
      // Salutation DO (ISO 5218) holds an ASCII digit: "0" none, "1" male,
      // "2" female. (The python tool hex-parses this, which is a latent bug.)
      if (data.salutation.length === 0) {
        await put(DO.CARD_SALUTATION, Buffer.from([0x30]));
      } else {
        await put(DO.CARD_SALUTATION, enc(USER_SALUTATION[data.salutation]));
      }

      for (const [role, tag] of KEY_ROLES) {
        if (changed[role]) {
          await put(ATTRIBUTE_TAGS[tag], data[role].attribute);
        }
      }

      await put(DO.UIF_SIG, u16le(data.sig.uif));
      await put(DO.UIF_DEC, u16le(data.dec.uif));
      await put(DO.UIF_AUT, u16le(data.aut.uif));

      // The digital signature counter (DO 0x93) is read-only on the card (no
      // write access path in the firmware), so it is kept in the backup for
      // reference but not written back here.
      await put(DO.RSA_EXP, u32le(data.rsaPubExp));

      for (const [occurrence, slot] of [data.aut, data.dec, data.sig].entries()) {
        await selectData(t, DO.CERT, occurrence);
        await put(DO.CERT, slot.cert);
      }

      const keys = [
        ["sig", "Signature key", DO.SIG_KEY, DO.CA_FINGERPRINT_WR_SIG, DO.FINGERPRINT_WR_SIG, DO.DATES_WR_SIG],
        ["dec", "Decryption key", DO.DEC_KEY, DO.CA_FINGERPRINT_WR_DEC, DO.FINGERPRINT_WR_DEC, DO.DATES_WR_DEC],
        ["aut", "Authentication key", DO.AUT_KEY, DO.CA_FINGERPRINT_WR_AUT, DO.FINGERPRINT_WR_AUT, DO.DATES_WR_AUT],
      ];

      // Keys are recovered by regenerating them from the device seed, not by
      // writing back the encrypted blob (which the firmware rejects on a
      // wiped card). Only the keys the backup holds are regenerated, and a key
      // fingerprint and date are only written once the card key matches them.
      // The current derivation comes first, then the legacy one of app 2.x; the
      // derivation of a matching key is tried first for the next ones.
      let derivations = [SEED_V2, SEED_LEGACY];
      for (const [role, name, tag, caTag, fpTag, dateTag] of keys) {
        const slot = data[role];
        await put(caTag, slot.ca_fingerprint);
        if (!hasKey(slot)) {
          // A key kept on the card keeps its fingerprint and date
          if (!kept[role]) {
            await put(fpTag, slot.fingerprint);
            await put(dateTag, u32be(slot.date));
          }
          continue;
        }
        let failure = null;
        if (regenerateKeys) {
          const result = await this.seedKey(name, slot, tag, derivations, t);
          failure = result.failure;
          if (result.derivation !== null) {
            derivations = [result.derivation, result.derivation === SEED_V2 ? SEED_LEGACY : SEED_V2];
          }
        } else {
          const message = await this.checkKey(slot, tag, t);
          if (message) {
            failure = { tag, name: `${name} (fingerprint)`, sw: SW_SUCCESS, message, keyMismatch: true };
          }
        }
        if (failure) {
          failures.push(failure);
          if (regenerateKeys) {
            // Writing the key attributes erases the regenerated key
            await put(ATTRIBUTE_TAGS[tag], slot.attribute);
          }
          if (!kept[role]) {
            await put(fpTag, Buffer.alloc(FINGERPRINT_SIZE));
            await put(dateTag, u32be(0));
          }
        } else {
          await put(fpTag, slot.fingerprint);
          await put(dateTag, u32be(slot.date));
        }
      }

      return failures;
    } finally {
      if (data) {
        wipeBuffers(data);
      }
      await this._logout(t);
      this._unlock();
    }
  }
}

export default GpgManager;
