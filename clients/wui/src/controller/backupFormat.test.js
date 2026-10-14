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
    attribute: Buffer.from("010800002001", "hex"),
    date: 0,
    fingerprint: Buffer.alloc(20, 0x11),
    ca_fingerprint: Buffer.alloc(20, 0x22),
    cert: Buffer.from("cert-data"),
  });

  const data = {
    AID: "D2760001240103040000000100000000",
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
    const attribute = Buffer.from("132a8648ce3d030107", "hex").toString("base64");
    const empty = { date: "1970-01-01 00:00:00", uif: 0, attribute };
    const slot = { ...empty, ...slotFields };
    const pwStatus = Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]).toString("base64");
    return {
      version: 1,
      AID: "D2760001240103040000000100000000",
      PW_status: pwStatus,
      rsa_pub_exp: 65537,
      digital_counter: 0,
      sig: slot,
      dec: empty,
      aut: empty,
      ...fields,
    };
  };

  test.each([
    ["010800002001"],
    ["010c00002001"],
    ["011000002001"],
    ["132a8648ce3d030107"],
    ["122b8104000a"],
    ["132b8104000a"],
    ["122a8648ce3d030107"],
    ["162b06010401da470f01"],
    ["122b060104019755010501"],
  ])("accepts the key attributes %s", (attribute) => {
    const parsed = parseBackup(minimal({}, { attribute: Buffer.from(attribute, "hex").toString("base64") }));
    expect(parsed.sig.attribute.toString("hex")).toBe(attribute);
  });

  test.each([[3], [65537], ["65537"], [0xffffffff]])("accepts the RSA exponent %s", (exponent) => {
    expect(parseBackup(minimal({ rsa_pub_exp: exponent })).rsaPubExp).toBe(Number(exponent));
  });

  test("accepts a minimal backup", () => {
    expect(parseBackup(minimal()).rsaPubExp).toBe(65537);
  });

  test.each([
    ["AID", minimal({ AID: "D2760001240103040000000100000" })],
    ["AID", minimal({ AID: "D27600012401030400000001000000ZZ" })],
    ["AID", minimal({ AID: "A0000000030000000000000000000000" })],
    ["AID", minimal({ AID: undefined })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: -1 })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: 2 ** 32 })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: "0x10001" })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: 1.5 })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: 0 })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: 1 })],
    ["rsa_pub_exp", minimal({ rsa_pub_exp: 65536 })],
    ["digital_counter", minimal({ digital_counter: 2 ** 24 })],
    ["digital_counter", minimal({ digital_counter: undefined })],
    ["salutation", minimal({ salutation: "Dr" })],
    ["name", minimal({ name: 42 })],
    ["sig.attribute", minimal({}, { attribute: "" })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("02080000", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("01", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("0108", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("010400002001", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("010800002001000000000000ff", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("132a8648ce3d030107ff", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("13", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("132b81040022", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("142a8648ce3d030107", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("162a8648ce3d030107", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("132b06010401da470f01", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("132b060104019755010501", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("162b060104019755010501", "hex").toString("base64") })],
    ["sig.attribute", minimal({}, { attribute: Buffer.from("122b06010401da470f01", "hex").toString("base64") })],
    ["base64", minimal({ private_01: "AA" })],
    ["base64", minimal({ private_01: "!!!!" })],
  ])("rejects an invalid %s", (field, backup) => {
    expect(() => parseBackup(backup)).toThrow(field);
  });

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

  test.each([
    ["sig.fingerprint", minimal({}, { fingerprint: Buffer.alloc(19).toString("base64") })],
    ["sig.ca_fingerprint", minimal({}, { ca_fingerprint: Buffer.alloc(1).toString("base64") })],
  ])("rejects a %s that is neither empty nor 20 bytes", (field, backup) => {
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

  test("lists the erased keys after the settings", () => {
    const changes = securityChanges(settings(0, 1), settings(0, 1, "010800002001"), ["sig", "aut"]);
    expect(changes.filter((c) => c.erased).map((c) => c.setting)).toEqual(["Signature key", "Authentication key"]);
    expect(changes.at(-1)).toMatchObject({ from: "On the card", to: "Erased, not restored" });
  });
});
