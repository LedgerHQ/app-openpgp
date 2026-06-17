import { formatDate, buildBackup, parseDate, parseBackup } from "./backupFormat";

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
    cert: "cert-data",
  });

  const data = {
    AID: "D2760001240103xxxx",
    PWStatus: Buffer.from([0x00, 0x20, 0x20]),
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
    expect(out.PW_status).toBe(Buffer.from([0x00, 0x20, 0x20]).toString("base64"));
    expect(out.private_01).toBe(Buffer.from("p1").toString("base64"));
    expect(out.sig.key).toBe(Buffer.from([0xaa, 0xbb]).toString("base64"));
    expect(out.sig.date).toBe("1970-01-01 00:00:00");
    expect(out.sig.cert).toBe("cert-data");
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
    expect(parsed.sig.cert).toBe(data.sig.cert);
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
});
