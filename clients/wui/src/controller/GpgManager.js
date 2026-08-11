import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import { exchange, getData, putData, statusMessage, SW_SUCCESS } from "./apdu.js";
import { decodeTLV, getInt } from "./tlv.js";
import { DO, USER_SALUTATION, doName } from "./dataObjects.js";
import { buildBackup, parseBackup } from "./backupFormat.js";

// OpenPGP application identifier: RID D2:76:00:01:24 + application 01.
// (matches `00A4040006D27600012401` used by the python backup tool)
const OPENPGP_AID = "D27600012401";
const SELECT_APDU = "00A4040006" + OPENPGP_AID;
// GET DATA on tag 0x4F (full Application Identifier).
const GET_DATA_AID = "00CA004F00";

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
    cert: "",
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

class GpgManager {
  constructor() {
    this.transport = null;
    this.connected = false;
    this.busy = false;
    this.aid = null;
    this.serial = null;
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
      this.transport = await TransportWebHID.request();
      // The OpenPGP app can crash and drop its USB interface during heavy
      // operations (e.g. key regeneration); surface that instead of hanging.
      this.transport.on("disconnect", () => {
        this.connected = false;
        this.busy = false;
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
      this.aid = aid.data.toString("hex").toUpperCase();
      // OpenPGP AID layout: RID[0:10] App[10:12] Version[12:16]
      // Manufacturer[16:20] Serial[20:28] RFU[28:32].
      this.serial = this.aid.length >= 28 ? this.aid.slice(20, 28) : null;
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
    if (this.transport) {
      try {
        await this.transport.close();
      } catch (e) {
        // ignore: device may already be gone
      }
    }
    this.transport = null;
  }

  _lock() {
    if (this.busy) throw new Error("Device is busy");
    this.busy = true;
  }

  _unlock() {
    this.busy = false;
  }

  // PIN verification (00 20 00 <pw> Lc <pin>). Returns success boolean.
  async verifyPin(pw, value) {
    const pin = Buffer.from(value || "", "utf-8");
    const header = Buffer.from([0x00, 0x20, 0x00, pw, pin.length]);
    const { sw } = await exchange(
      this.transport,
      Buffer.concat([header, pin])
    );
    return sw === SW_SUCCESS;
  }

  // Read every data object needed for a backup, ported from gpgcard.py
  // `get_all`. Returns the CardInfo structure consumed by buildBackup().
  async getAll() {
    const t = this.transport;
    const data = newCardInfo();

    data.AID = (await getData(t, DO.AID)).toString("hex").toUpperCase();
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
    if (tags[DO.DISCRET_DATA]) {
      const d = decodeTLV(tags[DO.DISCRET_DATA]);
      if (d[DO.EXT_CAP]) data.extCapabilities = d[DO.EXT_CAP];
      if (d[DO.SIG_ATTR]) data.sig.attribute = d[DO.SIG_ATTR];
      if (d[DO.DEC_ATTR]) data.dec.attribute = d[DO.DEC_ATTR];
      if (d[DO.AUT_ATTR]) data.aut.attribute = d[DO.AUT_ATTR];
      if (d[DO.PW_STATUS]) data.PWStatus = d[DO.PW_STATUS];

      const fp = d[DO.FINGERPRINTS];
      if (fp) {
        data.sig.fingerprint = fp.slice(0, 20);
        data.dec.fingerprint = fp.slice(20, 40);
        data.aut.fingerprint = fp.slice(40, 60);
      }
      const ca = d[DO.CA_FINGERPRINTS];
      if (ca) {
        data.sig.ca_fingerprint = ca.slice(0, 20);
        data.dec.ca_fingerprint = ca.slice(20, 40);
        data.aut.ca_fingerprint = ca.slice(40, 60);
      }
      const dates = d[DO.KEY_DATES];
      if (dates) {
        data.sig.date = getInt(dates, 4, 0);
        data.dec.date = getInt(dates, 4, 4);
        data.aut.date = getInt(dates, 4, 8);
      }
    }

    data.rsaPubExp = getInt(await getData(t, DO.RSA_EXP), 4);
    data.aut.cert = (await getData(t, DO.CERT)).toString("utf-8");
    data.dec.cert = (await getData(t, DO.CERT, true)).toString("utf-8");
    data.sig.cert = (await getData(t, DO.CERT, true)).toString("utf-8");

    const uifSig = await getData(t, DO.UIF_SIG);
    const uifDec = await getData(t, DO.UIF_DEC);
    const uifAut = await getData(t, DO.UIF_AUT);
    data.sig.uif = uifSig.length ? uifSig[0] : 0;
    data.dec.uif = uifDec.length ? uifDec[0] : 0;
    data.aut.uif = uifAut.length ? uifAut[0] : 0;

    // Security support template (0x7A) -> digital signature counter (0x93)
    tags = decodeTLV(await getData(t, DO.SEC_TEMPL));
    if (tags[DO.SIG_COUNT]) data.digitalCounter = getInt(tags[DO.SIG_COUNT], 3);

    // Private DOs are only present when supported by the extended capabilities.
    if (data.extCapabilities.length && data.extCapabilities[0] & 0x08) {
      data.private_01 = await getData(t, DO.PRIVATE_01);
      data.private_02 = await getData(t, DO.PRIVATE_02);
      data.private_03 = await getData(t, DO.PRIVATE_03);
      data.private_04 = await getData(t, DO.PRIVATE_04);
    }

    // Encrypted private key material (only readable in SEED mode with PW3).
    data.sig.key = await getData(t, DO.SIG_KEY);
    data.dec.key = await getData(t, DO.DEC_KEY);
    data.aut.key = await getData(t, DO.AUT_KEY);

    this.data = data;
    return data;
  }

  // Verify the user and admin PINs needed for backup/restore. PW1 (0x81) and
  // PW2 (0x82) share the user PIN but gate different operations: PW2 is
  // required to read/write private DOs 0x0101/0x0103 (see the firmware's
  // gpg_check_access_*_DO). Verifying only PW1+PW3 — as the python tool does —
  // silently loses those DOs.
  async verifyPins(userPin, adminPin) {
    if (!(await this.verifyPin(PW.PW1, userPin))) {
      throw new Error("User PIN verification failed");
    }
    if (!(await this.verifyPin(PW.PW2, userPin))) {
      throw new Error("User PIN verification failed");
    }
    if (!(await this.verifyPin(PW.PW3, adminPin))) {
      throw new Error("Admin PIN verification failed");
    }
  }

  // Select the active key slot (PUT DATA 0x01F2, 0-based index). Requires PW2
  // verified and "Selection by APDU" enabled on the card.
  async selectSlot(index) {
    const sw = await putData(this.transport, DO.SLOT_CUR, Buffer.from([index]));
    if (sw !== SW_SUCCESS) {
      throw new Error(
        `Slot selection failed (${statusMessage(sw)}) — is "Selection by APDU" enabled on the card?`
      );
    }
  }

  // Verify PINs, select the slot, and read the full card state into a backup.
  async backup(userPin, adminPin, slot = 0) {
    this._lock();
    try {
      await this.verifyPins(userPin, adminPin);
      await this.selectSlot(slot);
      return buildBackup(await this.getAll());
    } finally {
      this._unlock();
    }
  }

  // Regenerate the three keys deterministically from the device seed
  // (GEN ASYM KEYPAIR, P1=Generate, P2=SEED). This rebuilds the exact same
  // keys from the master seed; it requires SEED mode enabled on the device
  // and the same recovery phrase. Returns the list of failures.
  async seedKeys() {
    const GENERATE = 0x80;
    const SEEDED_MODE = 0x01;
    const header = Buffer.from([0x00, 0x47, GENERATE, SEEDED_MODE]);
    const failures = [];
    for (const [name, tag] of [
      ["Signature key", DO.SIG_KEY],
      ["Decryption key", DO.DEC_KEY],
      ["Authentication key", DO.AUT_KEY],
    ]) {
      // CRT key template: <tag> 00
      const { sw } = await exchange(this.transport, header, Buffer.from([tag, 0x00]));
      if (sw !== SW_SUCCESS) {
        failures.push({
          tag,
          name: `${name} (regenerate)`,
          sw,
          message: statusMessage(sw),
        });
      }
    }
    return failures;
  }

  // Factory-reset the app: TERMINATE DF then ACTIVATE FILE, which wipes every
  // key and data object and resets the PINs to their defaults (123456 /
  // 12345678). Requires the admin PIN (PW3). DESTRUCTIVE.
  async factoryReset(adminPin) {
    this._lock();
    try {
      if (!(await this.verifyPin(PW.PW3, adminPin))) {
        throw new Error("Admin PIN verification failed");
      }
      let r = await exchange(this.transport, "00E60000"); // TERMINATE DF
      if (r.sw !== SW_SUCCESS) {
        throw new Error(`Terminate failed (${statusMessage(r.sw)})`);
      }
      r = await exchange(this.transport, "00440000"); // ACTIVATE FILE
      if (r.sw !== SW_SUCCESS) {
        throw new Error(`Activate failed (${statusMessage(r.sw)})`);
      }
      // The card is now blank; refresh the AID/serial we display.
      await exchange(this.transport, SELECT_APDU);
      const aid = await exchange(this.transport, GET_DATA_AID);
      if (aid.sw === SW_SUCCESS) {
        this.aid = aid.data.toString("hex").toUpperCase();
        this.serial = this.aid.length >= 28 ? this.aid.slice(20, 28) : null;
      }
    } finally {
      this._unlock();
    }
  }

  // Write a parsed backup back to the card, ported from gpgcard.py `restore`.
  // Individual PUT DATA failures are collected (not thrown) so a partial
  // restore still completes. The private keys are NOT written from the backup
  // blob (the firmware rejects that on a wiped card); pass regenerateKeys to
  // rebuild them from the device seed instead. Returns the list of failures.
  async restore(userPin, adminPin, json, regenerateKeys = false, slot = 0) {
    this._lock();
    try {
      const data = parseBackup(json);

      await this.verifyPins(userPin, adminPin);
      await this.selectSlot(slot);

      const t = this.transport;
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

      await put(DO.SIG_ATTR, data.sig.attribute);
      await put(DO.DEC_ATTR, data.dec.attribute);
      await put(DO.AUT_ATTR, data.aut.attribute);

      await put(DO.UIF_SIG, u16le(data.sig.uif));
      await put(DO.UIF_DEC, u16le(data.dec.uif));
      await put(DO.UIF_AUT, u16le(data.aut.uif));

      // The digital signature counter (DO 0x93) is read-only on the card (no
      // write access path in the firmware), so it is kept in the backup for
      // reference but not written back here.
      await put(DO.RSA_EXP, u32le(data.rsaPubExp));

      // Certificates share one DO with an internal pointer; written AUT, DEC,
      // SIG to match the read order in getAll().
      await put(DO.CERT, enc(data.aut.cert));
      await put(DO.CERT, enc(data.dec.cert));
      await put(DO.CERT, enc(data.sig.cert));

      for (const [slot, caTag, fpTag, dateTag] of [
        [data.sig, DO.CA_FINGERPRINT_WR_SIG, DO.FINGERPRINT_WR_SIG, DO.DATES_WR_SIG],
        [data.dec, DO.CA_FINGERPRINT_WR_DEC, DO.FINGERPRINT_WR_DEC, DO.DATES_WR_DEC],
        [data.aut, DO.CA_FINGERPRINT_WR_AUT, DO.FINGERPRINT_WR_AUT, DO.DATES_WR_AUT],
      ]) {
        await put(caTag, slot.ca_fingerprint);
        await put(fpTag, slot.fingerprint);
        await put(dateTag, u32be(slot.date));
      }

      // Keys are recovered by regenerating them from the device seed, not by
      // writing back the encrypted blob (which the firmware rejects on a
      // wiped card).
      if (regenerateKeys) {
        failures.push(...(await this.seedKeys()));
      }

      return failures;
    } finally {
      this._unlock();
    }
  }
}

export default GpgManager;
