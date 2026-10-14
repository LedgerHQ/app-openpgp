// Pure (device-free) serialization of the OpenPGP card data into the backup
// JSON, kept byte-for-byte compatible with pytools/gpgapp/gpgcard.py `backup`
// (version 1) so the CLI tool and this web UI can read each other's files.

// Format a UTC timestamp (seconds since epoch) as "YYYY-MM-DD HH:MM:SS",
// matching Python's `str(datetime.utcfromtimestamp(n))`.
export function formatDate(seconds) {
  const d = new Date(seconds * 1000);
  const pad = (n, width = 2) => String(n).padStart(width, "0");
  return (
    `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
  );
}

function b64(bytes) {
  return Buffer.from(bytes || []).toString("base64");
}

// `data` is the structure filled by GpgManager.getAll(): Buffers for binary
// fields, numbers for counters, "date" being a UTC timestamp in seconds.
export function buildBackup(data) {
  const keySlot = (slot) => ({
    key: b64(slot.key),
    uif: slot.uif,
    attribute: b64(slot.attribute),
    date: formatDate(slot.date),
    fingerprint: b64(slot.fingerprint),
    ca_fingerprint: b64(slot.ca_fingerprint),
    // "cert" is kept for older tools, which cannot hold binary certificates
    cert: Buffer.from(slot.cert || []).toString("utf-8"),
    cert_b64: b64(slot.cert),
  });

  return {
    version: 1,
    AID: data.AID,
    PW_status: b64(data.PWStatus),
    rsa_pub_exp: data.rsaPubExp,
    digital_counter: data.digitalCounter,
    private_01: b64(data.private_01),
    private_02: b64(data.private_02),
    private_03: b64(data.private_03),
    private_04: b64(data.private_04),
    name: data.name,
    login: data.login,
    salutation: data.salutation,
    url: data.url,
    lang: data.lang,
    sig: keySlot(data.sig),
    dec: keySlot(data.dec),
    aut: keySlot(data.aut),
  };
}

// Parse "YYYY-MM-DD HH:MM:SS" (UTC) back into epoch seconds.
export function parseDate(str) {
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(str || "");
  if (!m) throw new Error(`Invalid date in backup: "${str}"`);
  const n = m.map(Number);
  return Date.UTC(n[1], n[2] - 1, n[3], n[4], n[5], n[6]) / 1000;
}

// ── File-level authenticated encryption ──────────────────────────────────────
// Format: 0x01 || salt(16) || nonce(12) || AES-256-GCM(ciphertext + tag-16)
// SubtleCrypto.encrypt appends the 16-byte GCM tag; .decrypt expects it too.
// KDF: PBKDF2-SHA256, 600 000 iterations — matches pytools/gpgapp/gpgcard.py.
// Detection: first byte 0x01 → encrypted; first byte '{' (0x7B) → plaintext.

const _ENC_VERSION = 0x01;
const _PBKDF2_ITER = 600_000;
const _SALT_LEN = 16;
const _NONCE_LEN = 12;

async function _deriveKey(passphrase, salt) {
  const raw = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: _PBKDF2_ITER, hash: "SHA-256" },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function isEncryptedBackup(bytes) {
  return bytes instanceof Uint8Array && bytes.length > 0 && bytes[0] === _ENC_VERSION;
}

export async function encryptBackup(payload, passphrase) {
  const plain = new TextEncoder().encode(JSON.stringify(payload, null, 2));
  const salt = crypto.getRandomValues(new Uint8Array(_SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(_NONCE_LEN));
  const key = await _deriveKey(passphrase, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  const out = new Uint8Array(1 + _SALT_LEN + _NONCE_LEN + ct.length);
  let off = 0;
  out[off++] = _ENC_VERSION;
  out.set(salt, off); off += _SALT_LEN;
  out.set(nonce, off); off += _NONCE_LEN;
  out.set(ct, off);
  return out;
}

export async function decryptBackup(bytes, passphrase) {
  const minLen = 1 + _SALT_LEN + _NONCE_LEN + 16;
  if (bytes.length < minLen) throw new Error("Encrypted backup file is truncated");
  let off = 1;
  const salt = bytes.slice(off, off + _SALT_LEN); off += _SALT_LEN;
  const nonce = bytes.slice(off, off + _NONCE_LEN); off += _NONCE_LEN;
  const ct = bytes.slice(off);
  const key = await _deriveKey(passphrase, salt);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
  } catch {
    throw new Error("Backup decryption failed (wrong passphrase or corrupted file)");
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

// ── Plain-JSON parsing ────────────────────────────────────────────────────────

// Size of the PW status bytes (DO C4) returned by the device.
const PW_STATUS_SIZE = 7;

// Largest backup file accepted for a restore; real backups are a few KB.
export const BACKUP_MAX_FILE_SIZE = 64 * 1024;

// Largest value of each backup field, as stored by the device.
export const FINGERPRINT_SIZE = 20;

const FIELD_MAX_SIZE = {
  private: 512,
  name: 39,
  login: 512,
  url: 512,
  lang: 8,
  attribute: 12,
  fingerprint: FINGERPRINT_SIZE,
  cert: 1510,
  key: 1512,
};

export function checkBackupFileSize(size) {
  if (size > BACKUP_MAX_FILE_SIZE) {
    throw new Error(`Backup file too large (${size} bytes)`);
  }
}

function checkFieldSize(name, value, max) {
  const size = typeof value === "string" ? Buffer.byteLength(value, "utf-8") : value.length;
  if (size > max) {
    throw new Error(`Backup field "${name}" too long (${size} bytes)`);
  }
}

// User Interaction Flag values, from the least to the most protective.
const UIF_LABEL = ["Disabled", "Enabled", "Permanently enabled"];

// Full OpenPGP AID: RID and application, version, manufacturer, serial number, RFU
const AID_PATTERN = /^D27600012401[0-9A-F]{20}$/i;
// Key attributes the app accepts: RSA with a supported modulus size, or ECDH, ECDSA and
// EdDSA with the OID of a curve the algorithm works on, in at most 12 bytes
const KEY_ATTRIBUTE_MAX_SIZE = 12;
const RSA_ALGORITHM = 0x01;
const RSA_SIZES = [2048, 3072, 4096];
const OID_P256 = "2a8648ce3d030107";
const OID_SECP256K1 = "2b8104000a";
const ECC_CURVE_OIDS = {
  0x12: [OID_P256, OID_SECP256K1, "2b060104019755010501"],
  0x13: [OID_P256, OID_SECP256K1],
  0x16: ["2b06010401da470f01"],
};
// Cardholder salutations stored in a backup
const SALUTATIONS = ["", "Male", "Female"];

function parseText(value, name) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") {
    throw new Error(`Backup field "${name}" is invalid`);
  }
  return value;
}

// Integer from 0 to `max`, given as a JSON number or a decimal string
function parseCount(value, name, max) {
  const n = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isInteger(n) || n < 0 || n > max) {
    throw new Error(`Backup field "${name}" is invalid`);
  }
  return n;
}

// RSA public exponent the app accepts: odd and at least 3
function parseRsaExponent(value) {
  const exponent = parseCount(value, "rsa_pub_exp", 0xffffffff);
  if (exponent < 3 || exponent % 2 === 0) {
    throw new Error(`Backup field "rsa_pub_exp" is invalid`);
  }
  return exponent;
}

function checkAttribute(attribute, slot) {
  const valid =
    attribute.length <= KEY_ATTRIBUTE_MAX_SIZE &&
    (attribute[0] === RSA_ALGORITHM
      ? attribute.length >= 3 && RSA_SIZES.includes(attribute.readUInt16BE(1))
      : (ECC_CURVE_OIDS[attribute[0]] ?? []).includes(attribute.subarray(1).toString("hex")));
  if (!valid) {
    throw new Error(`Backup field "${slot}.attribute" is invalid`);
  }
}

function parseUif(value, slot) {
  if (!Number.isInteger(value) || value < 0 || value >= UIF_LABEL.length) {
    throw new Error(`Backup field "${slot}.uif" is invalid`);
  }
  return value;
}

// Decode a version-1 backup file into the structure consumed by
// GpgManager.restore(). Inverse of buildBackup(). Throws on a malformed or
// unsupported file.
export function parseBackup(json) {
  const p = typeof json === "string" ? JSON.parse(json) : json;
  if (p.version !== 1) {
    throw new Error(`Unsupported backup version: ${p.version}`);
  }
  for (const slot of ["sig", "dec", "aut"]) {
    if (!p[slot]) throw new Error(`Backup is missing the "${slot}" key slot`);
  }

  const fromb64 = (s) => {
    const bytes = Buffer.from(parseText(s, "base64 data"), "base64");
    if (bytes.toString("base64") !== (s || "")) {
      throw new Error("Backup holds invalid base64 data");
    }
    return bytes;
  };
  const keySlot = (raw, name) => ({
    key: fromb64(raw.key),
    uif: parseUif(raw.uif, name),
    attribute: fromb64(raw.attribute),
    date: parseDate(raw.date),
    fingerprint: fromb64(raw.fingerprint),
    ca_fingerprint: fromb64(raw.ca_fingerprint),
    cert: raw.cert_b64 !== undefined ? fromb64(raw.cert_b64) : Buffer.from(raw.cert || "", "utf-8"),
  });

  if (!AID_PATTERN.test(parseText(p.AID, "AID"))) {
    throw new Error(`Backup field "AID" is invalid`);
  }
  if (!SALUTATIONS.includes(parseText(p.salutation, "salutation"))) {
    throw new Error(`Backup field "salutation" is invalid`);
  }

  const data = {
    AID: p.AID,
    PWStatus: fromb64(p.PW_status),
    rsaPubExp: parseRsaExponent(p.rsa_pub_exp),
    digitalCounter: parseCount(p.digital_counter, "digital_counter", 0xffffff),
    private_01: fromb64(p.private_01),
    private_02: fromb64(p.private_02),
    private_03: fromb64(p.private_03),
    private_04: fromb64(p.private_04),
    name: parseText(p.name, "name"),
    login: parseText(p.login, "login"),
    salutation: parseText(p.salutation, "salutation"),
    url: parseText(p.url, "url"),
    lang: parseText(p.lang, "lang"),
    sig: keySlot(p.sig, "sig"),
    dec: keySlot(p.dec, "dec"),
    aut: keySlot(p.aut, "aut"),
  };

  if (data.PWStatus.length !== PW_STATUS_SIZE) {
    throw new Error(`Backup field "PW_status" must be ${PW_STATUS_SIZE} bytes`);
  }
  for (const n of ["01", "02", "03", "04"]) {
    checkFieldSize(`private_${n}`, data[`private_${n}`], FIELD_MAX_SIZE.private);
  }
  for (const field of ["name", "login", "url", "lang"]) {
    checkFieldSize(field, data[field], FIELD_MAX_SIZE[field]);
  }
  for (const slot of ["sig", "dec", "aut"]) {
    for (const field of ["attribute", "fingerprint", "cert", "key"]) {
      checkFieldSize(`${slot}.${field}`, data[slot][field], FIELD_MAX_SIZE[field]);
    }
    checkAttribute(data[slot].attribute, slot);
    checkFieldSize(`${slot}.ca_fingerprint`, data[slot].ca_fingerprint, FIELD_MAX_SIZE.fingerprint);
    for (const field of ["fingerprint", "ca_fingerprint"]) {
      const { length } = data[slot][field];
      if (length !== 0 && length !== FINGERPRINT_SIZE) {
        throw new Error(`Backup field "${slot}.${field}" must be empty or ${FINGERPRINT_SIZE} bytes`);
      }
    }
  }
  return data;
}

// ── Security settings review ─────────────────────────────────────────────────

const ALGO_NAME = { 0x12: "ECDH", 0x13: "ECDSA", 0x16: "EdDSA" };

const CURVE_NAME = {
  "2a8648ce3d030107": "NIST P-256",
  "2b81040022": "NIST P-384",
  "2b81040023": "NIST P-521",
  "2b8104000a": "secp256k1",
  "2b2403030208010107": "brainpoolP256r1",
  "2b240303020801010b": "brainpoolP384r1",
  "2b240303020801010d": "brainpoolP512r1",
  "2b06010401da470f01": "Ed25519",
  "2b060104019755010501": "Cv25519",
};

// Human readable key algorithm attributes (DO C1/C2/C3).
export function describeAttribute(attribute) {
  const attr = Buffer.from(attribute || []);
  if (attr.length === 0) return "None";
  if (attr[0] === 0x01 && attr.length >= 3) return `RSA ${attr.readUInt16BE(1)}`;
  // ECC: algorithm id, curve OID, then an optional 0xFF import format
  const oid = attr.slice(1, attr[attr.length - 1] === 0xff ? -1 : undefined).toString("hex");
  const algo = ALGO_NAME[attr[0]];
  if (algo && CURVE_NAME[oid]) return `${algo} ${CURVE_NAME[oid]}`;
  return `Unknown (${attr.toString("hex")})`;
}

function describePw1Mode(pwStatus) {
  return pwStatus[0] === 0x00 ? "Required for each signature" : "Valid for several signatures";
}

const SLOT_LABEL = { sig: "Signature", dec: "Decryption", aut: "Authentication" };

// Security settings of `current` (read from the card) that restoring `backup`
// changes, each flagged when the new value is less protective, then the keys
// of `erasedKeys` ("sig", "dec", "aut") that the restore erases.
export function securityChanges(current, backup, erasedKeys = []) {
  const changes = [];
  const add = (setting, from, to, weaker) => {
    if (from !== to) changes.push({ setting, from, to, weaker });
  };
  add(
    "Signature PIN",
    describePw1Mode(current.PWStatus),
    describePw1Mode(backup.PWStatus),
    current.PWStatus[0] === 0x00 && backup.PWStatus[0] !== 0x00
  );
  for (const slot of ["sig", "dec", "aut"]) {
    const from = current[slot].uif;
    const to = backup[slot].uif;
    add(`${SLOT_LABEL[slot]} key confirmation`, UIF_LABEL[from] ?? `Unknown (${from})`, UIF_LABEL[to], to < from);
    const fromAttr = describeAttribute(current[slot].attribute);
    add(`${SLOT_LABEL[slot]} key algorithm`, fromAttr, describeAttribute(backup[slot].attribute), false);
  }
  for (const slot of erasedKeys) {
    changes.push({ setting: `${SLOT_LABEL[slot]} key`, from: "On the card", to: "Erased, not restored", erased: true });
  }
  return changes;
}
