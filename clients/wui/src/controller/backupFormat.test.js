import {
  formatDate,
  buildBackup,
  parseDate,
  parseBackup,
  checkBackupFileSize,
  describeAttribute,
  securityChanges,
  BACKUP_MAX_FILE_SIZE,
} from "./backupFormat";

describe("formatDate", () => {
  test("epoch is 1970-01-01 00:00:00 (UTC)", () => {
    expect(formatDate(0)).toBe("1970-01-01 00:00:00");
  });
  test("formats a known UTC timestamp", () => {
    // 2024-01-02 03:04:05 UTC
    const ts = Date.UTC(2024, 0, 2, 3, 4, 5) / 1000;
    expect(formatDate(ts)).toBe("2024-01-02 03:04:05");
  });
});

describe("buildBackup", () => {
  const slot = () => ({
    key: Buffer.from([0xaa, 0xbb]),
    uif: 1,
    attribute: Buffer.from([0x01, 0x08]),
    date: 0,
    fingerprint: Buffer.from([0x11]),
    ca_fingerprint: Buffer.from([0x22]),
    cert: Buffer.from("cert-data"),
  });

  const data = {
    AID: "D2760001240103xxxx",
    PWStatus: Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]),
    rsaPubExp: 65537,
    digitalCounter: 42,
    private_01: Buffer.from("p1"),
    private_02: Buffer.alloc(0),
    private_03: Buffer.alloc(0),
    private_04: Buffer.alloc(0),
    name: "Alice",
    login: "alice",
    salutation: "Female",
    url: "https://example.com",
    lang: "en",
    sig: slot(),
    dec: slot(),
    aut: slot(),
  };

  test("produces a version-1 payload with the expected keys", () => {
    const out = buildBackup(data);
    expect(out.version).toBe(1);
    expect(Object.keys(out)).toEqual([
      "version",
      "AID",
      "PW_status",
      "rsa_pub_exp",
      "digital_counter",
      "private_01",
      "private_02",
      "private_03",
      "private_04",
      "name",
      "login",
      "salutation",
      "url",
      "lang",
      "sig",
      "dec",
      "aut",
    ]);
  });

  test("base64-encodes binary fields and formats dates", () => {
    const out = buildBackup(data);
    expect(out.PW_status).toBe(data.PWStatus.toString("base64"));
    expect(out.private_01).toBe(Buffer.from("p1").toString("base64"));
    expect(out.sig.key).toBe(Buffer.from([0xaa, 0xbb]).toString("base64"));
    expect(out.sig.date).toBe("1970-01-01 00:00:00");
    expect(out.sig.cert).toBe("cert-data");
    expect(out.sig.cert_b64).toBe(Buffer.from("cert-data").toString("base64"));
    expect(out.sig.uif).toBe(1);
  });

  test("keeps scalars as-is", () => {
    const out = buildBackup(data);
    expect(out.rsa_pub_exp).toBe(65537);
    expect(out.digital_counter).toBe(42);
    expect(out.name).toBe("Alice");
    expect(out.salutation).toBe("Female");
  });

  test("round-trips through parseBackup", () => {
    const parsed = parseBackup(buildBackup(data));
    expect(parsed.AID).toBe(data.AID);
    expect(parsed.rsaPubExp).toBe(data.rsaPubExp);
    expect(parsed.digitalCounter).toBe(data.digitalCounter);
    expect(parsed.salutation).toBe(data.salutation);
    expect(parsed.PWStatus.equals(data.PWStatus)).toBe(true);
    expect(parsed.private_01.equals(data.private_01)).toBe(true);
    expect(parsed.sig.key.equals(data.sig.key)).toBe(true);
    expect(parsed.sig.fingerprint.equals(data.sig.fingerprint)).toBe(true);
    expect(parsed.sig.date).toBe(data.sig.date);
    expect(parsed.sig.uif).toBe(data.sig.uif);
    expect(parsed.sig.cert.equals(data.sig.cert)).toBe(true);
  });

  test("round-trips a binary certificate", () => {
    const der = Buffer.from([0x30, 0x82, 0x01, 0xff, 0x80, 0xc0, 0x00]);
    const parsed = parseBackup(buildBackup({ ...data, aut: { ...slot(), cert: der } }));
    expect(parsed.aut.cert.equals(der)).toBe(true);
  });
});

describe("parseDate", () => {
  test("parses a UTC timestamp string to epoch seconds", () => {
    expect(parseDate("1970-01-01 00:00:00")).toBe(0);
    expect(parseDate("2024-01-02 03:04:05")).toBe(
      Date.UTC(2024, 0, 2, 3, 4, 5) / 1000
    );
  });
  test("rejects malformed dates", () => {
    expect(() => parseDate("not-a-date")).toThrow();
  });
});

describe("parseBackup", () => {
  test("rejects an unsupported version", () => {
    expect(() => parseBackup({ version: 2 })).toThrow(/version/);
  });
  test("rejects a file missing a key slot", () => {
    expect(() => parseBackup({ version: 1, sig: {}, dec: {} })).toThrow(/aut/);
  });

  const minimal = (fields = {}, slotFields = {}) => {
    const empty = { date: "1970-01-01 00:00:00", uif: 0 };
    const slot = { ...empty, ...slotFields };
    const pwStatus = Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]).toString("base64");
    return { version: 1, PW_status: pwStatus, sig: slot, dec: empty, aut: empty, ...fields };
  };

  test("reads the certificate of a backup without cert_b64 as UTF-8", () => {
    const parsed = parseBackup(minimal({}, { cert: "cert-é" }));
    expect(parsed.sig.cert.equals(Buffer.from("cert-é", "utf-8"))).toBe(true);
  });

  test.each([[undefined], [3], [-1], ["1"], [1.5]])("rejects the UIF value %s", (uif) => {
    expect(() => parseBackup(minimal({}, { uif }))).toThrow("sig.uif");
  });

  test("accepts fields at their maximum size", () => {
    const parsed = parseBackup(
      minimal({ name: "n".repeat(39), private_01: Buffer.alloc(512).toString("base64") }, { cert: "c".repeat(1510) })
    );
    expect(parsed.name.length).toBe(39);
  });

  test.each([
    ["name", minimal({ name: "n".repeat(40) })],
    ["private_01", minimal({ private_01: Buffer.alloc(513).toString("base64") })],
    ["sig.cert", minimal({}, { cert: "c".repeat(1511) })],
    ["sig.cert", minimal({}, { cert_b64: Buffer.alloc(1511).toString("base64") })],
    ["sig.key", minimal({}, { key: Buffer.alloc(1513).toString("base64") })],
    ["PW_status", minimal({ PW_status: "" })],
    ["PW_status", minimal({ PW_status: Buffer.alloc(8).toString("base64") })],
  ])("rejects a too long %s", (field, backup) => {
    expect(() => parseBackup(backup)).toThrow(field);
  });
});

describe("checkBackupFileSize", () => {
  test("accepts a file up to the maximum size", () => {
    expect(() => checkBackupFileSize(BACKUP_MAX_FILE_SIZE)).not.toThrow();
  });
  test("rejects a larger file", () => {
    expect(() => checkBackupFileSize(BACKUP_MAX_FILE_SIZE + 1)).toThrow(/too large/);
  });
});

describe("describeAttribute", () => {
  test.each([
    ["010800002001", "RSA 2048"],
    ["132a8648ce3d030107", "ECDSA NIST P-256"],
    ["132a8648ce3d030107ff", "ECDSA NIST P-256"],
    ["162b06010401da470f01", "EdDSA Ed25519"],
    ["122b060104019755010501", "ECDH Cv25519"],
    ["", "None"],
    ["1301020304", "Unknown (1301020304)"],
  ])("describes %s as %s", (hex, name) => {
    expect(describeAttribute(Buffer.from(hex, "hex"))).toBe(name);
  });
});

describe("securityChanges", () => {
  const settings = (pw1, uif, attr = "132a8648ce3d030107") => {
    const slot = { uif, attribute: Buffer.from(attr, "hex") };
    return { PWStatus: Buffer.from([pw1, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]), sig: slot, dec: slot, aut: slot };
  };

  test("lists nothing when the settings are unchanged", () => {
    expect(securityChanges(settings(0, 1), settings(0, 1))).toEqual([]);
  });

  test("flags less protective settings", () => {
    const changes = securityChanges(settings(0, 2), settings(1, 0));
    expect(changes.map((c) => [c.setting, c.weaker])).toEqual([
      ["Signature PIN", true],
      ["Signature key confirmation", true],
      ["Decryption key confirmation", true],
      ["Authentication key confirmation", true],
    ]);
    expect(changes[1].from).toBe("Permanently enabled");
    expect(changes[1].to).toBe("Disabled");
  });

  test("lists stronger settings and algorithm changes without flagging them", () => {
    const changes = securityChanges(settings(1, 0), settings(0, 1, "010800002001"));
    expect(changes.every((c) => !c.weaker)).toBe(true);
    expect(changes.find((c) => c.setting === "Signature key algorithm")).toMatchObject({
      from: "ECDSA NIST P-256",
      to: "RSA 2048",
    });
  });
});
