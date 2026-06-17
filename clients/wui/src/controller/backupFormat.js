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
    cert: slot.cert,
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

  const fromb64 = (s) => Buffer.from(s || "", "base64");
  const keySlot = (raw) => ({
    key: fromb64(raw.key),
    uif: parseInt(raw.uif, 10) || 0,
    attribute: fromb64(raw.attribute),
    date: parseDate(raw.date),
    fingerprint: fromb64(raw.fingerprint),
    ca_fingerprint: fromb64(raw.ca_fingerprint),
    cert: raw.cert || "",
  });

  return {
    AID: p.AID || "",
    PWStatus: fromb64(p.PW_status),
    rsaPubExp: parseInt(p.rsa_pub_exp, 10) || 0,
    digitalCounter: parseInt(p.digital_counter, 10) || 0,
    private_01: fromb64(p.private_01),
    private_02: fromb64(p.private_02),
    private_03: fromb64(p.private_03),
    private_04: fromb64(p.private_04),
    name: p.name || "",
    login: p.login || "",
    salutation: p.salutation || "",
    url: p.url || "",
    lang: p.lang || "",
    sig: keySlot(p.sig),
    dec: keySlot(p.dec),
    aut: keySlot(p.aut),
  };
}
