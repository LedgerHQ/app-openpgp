import { vi } from "vitest";

const transports = [];

vi.mock("@ledgerhq/hw-transport-webhid", () => ({
  default: {
    isSupported: async () => true,
    request: async () => transports.shift(),
  },
}));

const { default: GpgManager } = await import("./GpgManager");
const { formatDate } = await import("./backupFormat");

const OK = Buffer.from([0x90, 0x00]);
// Backup fields every restore test needs, besides the PW status and the key slots
const BACKUP_FIELDS = { version: 1, AID: "D2760001240103040000000100000000", rsa_pub_exp: 65537, digital_counter: 0 };
const AID = Buffer.concat([Buffer.from("D2760001240103040000000100000000", "hex"), OK]);

// Fake WebHID transport: answers SELECT and GET DATA AID, then replies to
// every other command with `reply()`, which may be left pending.
class FakeTransport {
  constructor(reply = async () => OK) {
    this.reply = reply;
    this.handlers = {};
  }
  on(event, handler) {
    this.handlers[event] = handler;
  }
  emit(event) {
    this.handlers[event]();
  }
  async close() {}
  async exchange(buffer) {
    const apdu = Buffer.from(buffer);
    if (apdu[1] === 0xa4) return OK;
    if (apdu[1] === 0xca && apdu[3] === 0x4f) return AID;
    return this.reply(apdu);
  }
}

describe("disconnect", () => {
  test("keeps the operation lock until the running operation ends", async () => {
    let release;
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const transport = new FakeTransport(() => pending);
    transports.push(transport);
    const gpg = new GpgManager();
    await gpg.connect();

    const running = gpg.backup("123456", "12345678");
    transport.emit("disconnect");
    expect(gpg.busy).toBe(true);
    await expect(gpg.backup("123456", "12345678")).rejects.toThrow("busy");

    release(Buffer.from([0x63, 0xc2]));
    await expect(running).rejects.toThrow("PIN verification failed");
    expect(gpg.busy).toBe(false);
  });

  test("ignores the disconnection of a previous transport", async () => {
    const first = new FakeTransport();
    const second = new FakeTransport();
    transports.push(first, second);
    const gpg = new GpgManager();
    await gpg.connect();
    first.emit("disconnect");
    await gpg.connect();

    first.emit("disconnect");
    expect(gpg.transport).toBe(second);
    expect(gpg.connected).toBe(true);
  });
});

describe("logout", () => {
  test("leaves the PINs not verified after a backup, even when it fails", async () => {
    const sent = [];
    const transport = new FakeTransport(async (apdu) => {
      sent.push(apdu.toString("hex"));
      return Buffer.from([0x63, 0xc2]);
    });
    transports.push(transport);
    const gpg = new GpgManager();
    await gpg.connect();

    await expect(gpg.backup("123456", "12345678")).rejects.toThrow("PIN verification failed");
    expect(sent.slice(-3)).toEqual(["0020ff8100", "0020ff8200", "0020ff8300"]);
  });
});

describe("getAll", () => {
  const tlv = (tag, value) => {
    const t = tag > 0xff ? Buffer.from([tag >> 8, tag & 0xff]) : Buffer.from([tag]);
    const l = value.length > 0x7f ? Buffer.from([0x81, value.length]) : Buffer.from([value.length]);
    return Buffer.concat([t, l, value]);
  };
  const P256_ATTR = Buffer.from("132a8648ce3d030107", "hex");
  const AID_BYTES = Buffer.from("D2760001240103040000000100000000", "hex");

  // Discretionary data objects (73) of the card, each overridable or removable (null)
  const discretionary = (overrides = {}) => {
    const fields = {
      0xc0: Buffer.from([0x00]),
      0xc1: P256_ATTR,
      0xc2: P256_ATTR,
      0xc3: P256_ATTR,
      0xc4: Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]),
      0xc5: Buffer.alloc(60),
      0xc6: Buffer.alloc(60),
      0xcd: Buffer.alloc(12),
      ...overrides,
    };
    return Buffer.concat(
      Object.entries(fields)
        .filter(([, value]) => value !== null)
        .map(([tag, value]) => tlv(Number(tag), value))
    );
  };

  const card = (overrides = {}, aid = AID_BYTES, keys = {}) => {
    const transport = new FakeTransport(async (apdu) => {
      const tag = (apdu[2] << 8) | apdu[3];
      const reply = (value) => Buffer.concat([value, OK]);
      if (apdu[1] !== 0xca) return OK;
      switch (tag) {
        case 0x006e:
          return reply(tlv(0x73, discretionary(overrides)));
        case 0x01f8:
          return reply(Buffer.from([0x00, 0x01, 0x00, 0x01]));
        case 0x00d6:
        case 0x00d7:
        case 0x00d8:
          return reply(Buffer.from([0x00, 0x20]));
        case 0x00b6:
        case 0x00b8:
        case 0x00a4:
          return reply(keys[tag] ?? Buffer.alloc(0));
        default:
          return OK;
      }
    });
    // The base fake answers GET DATA 4F itself: answer it with `aid` first
    const exchange = transport.exchange.bind(transport);
    transport.exchange = async (buffer) => {
      const apdu = Buffer.from(buffer);
      if (apdu[1] === 0xca && apdu[3] === 0x4f) return Buffer.concat([aid, OK]);
      return exchange(buffer);
    };
    return transport;
  };

  const getAll = async (overrides, aid, keys) => {
    transports.push(card({}));
    const gpg = new GpgManager();
    await gpg.connect();
    gpg.transport = card(overrides, aid, keys);
    return gpg.getAll();
  };

  const u32 = (n) => Buffer.from([n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  // Public key and encrypted private key of a key backup, each with its length
  const keyFields = Buffer.concat([u32(3), Buffer.alloc(3, 0x04), u32(5), Buffer.alloc(5, 0xee)]);
  const keyBlobV3 = (ref = 0xb6, attribute = P256_ATTR) =>
    Buffer.concat([
      Buffer.from([0x03]),
      Buffer.alloc(12, 0xaa),
      Buffer.from([ref >> 8, ref & 0xff, attribute.length]),
      attribute,
      keyFields,
    ]);

  test("reads a well-formed card", async () => {
    const data = await getAll({});
    expect(data.sig.attribute.equals(P256_ATTR)).toBe(true);
    expect(data.PWStatus.length).toBe(7);
  });

  test.each([
    ["PW status", { 0xc4: null }],
    ["fingerprints", { 0xc5: null }],
    ["fingerprints", { 0xc5: Buffer.alloc(40) }],
    ["CA fingerprints", { 0xc6: Buffer.alloc(61) }],
    ["key dates", { 0xcd: null }],
    ["signature key attributes", { 0xc1: null }],
    ["decryption key attributes", { 0xc2: Buffer.from([0x02, 0x08]) }],
    ["authentication key attributes", { 0xc3: Buffer.alloc(13, 0x13) }],
  ])("rejects an invalid %s", async (name, overrides) => {
    await expect(getAll(overrides)).rejects.toThrow(name);
  });

  test.each([
    ["format 3", keyBlobV3()],
    [
      "format 2",
      Buffer.concat([Buffer.from([0x02]), u32(0x33000004), u32(25), Buffer.alloc(12, 0xaa), keyFields]),
    ],
    ["format 1", Buffer.concat([Buffer.from([0x01]), u32(0x33000004), u32(25), keyFields])],
    ["legacy", Buffer.concat([u32(0x33000004), u32(25), keyFields])],
  ])("reads a %s key backup", async (_, blob) => {
    const data = await getAll({}, AID_BYTES, { 0xb6: blob });
    expect(data.sig.key.equals(blob)).toBe(true);
  });

  test.each([
    ["truncated", keyBlobV3().subarray(0, 30)],
    ["trailing bytes", Buffer.concat([keyBlobV3(), Buffer.from([0x00])])],
    ["oversized length", Buffer.concat([keyBlobV3().subarray(0, 29), u32(0xffffffff)])],
    ["other key reference", keyBlobV3(0xa4)],
    ["other key attributes", keyBlobV3(0xb6, Buffer.from("16", "hex"))],
  ])("rejects a key backup with %s", async (_, blob) => {
    await expect(getAll({}, AID_BYTES, { 0xb6: blob })).rejects.toThrow("signature key backup");
  });

  test.each([
    ["short", AID_BYTES.subarray(0, 15)],
    ["foreign", Buffer.from("A0000000030000000000000000000000", "hex")],
  ])("rejects a %s AID", async (_, aid) => {
    await expect(getAll({}, aid)).rejects.toThrow("AID");
  });
});

describe("backup slot", () => {
  const slotInfo = () => ({
    key: Buffer.alloc(0),
    uif: 0,
    attribute: Buffer.from("132a8648ce3d030107", "hex"),
    date: 0,
    fingerprint: Buffer.alloc(0),
    ca_fingerprint: Buffer.alloc(0),
    cert: Buffer.alloc(0),
  });
  const cardInfo = () => ({
    AID: "D2760001240103040000000100000000",
    PWStatus: Buffer.alloc(7),
    rsaPubExp: 65537,
    digitalCounter: 0,
    private_01: Buffer.alloc(0),
    private_02: Buffer.alloc(0),
    private_03: Buffer.alloc(0),
    private_04: Buffer.alloc(0),
    name: "",
    login: "",
    salutation: "",
    url: "",
    lang: "",
    sig: slotInfo(),
    dec: slotInfo(),
    aut: slotInfo(),
  });

  // Card whose active slot is `active`; records the slot selections (PUT DATA 01F2)
  const card = (active, selections) =>
    new FakeTransport(async (apdu) => {
      if (apdu[1] === 0xca && apdu[2] === 0x01 && apdu[3] === 0xf2) return Buffer.from([active, 0x90, 0x00]);
      if (apdu[1] === 0xda && apdu[2] === 0x01 && apdu[3] === 0xf2) selections.push(apdu[5]);
      return OK;
    });

  const connect = async (active, selections) => {
    transports.push(card(active, selections));
    const gpg = new GpgManager();
    await gpg.connect();
    return gpg;
  };

  test("reads the active slot", async () => {
    const gpg = await connect(2, []);
    expect(await gpg.activeSlot()).toBe(2);
  });

  test("rejects an unknown active slot", async () => {
    const gpg = await connect(3, []);
    await expect(gpg.activeSlot()).rejects.toThrow("Unexpected active slot");
  });

  test("selects the active slot again after the backup", async () => {
    const selections = [];
    const gpg = await connect(1, selections);
    vi.spyOn(gpg, "getAll").mockResolvedValue(cardInfo());
    await gpg.backup("123456", "12345678", 0);
    expect(selections).toEqual([0, 1]);
  });

  test("selects the active slot again when the backup fails", async () => {
    const selections = [];
    const gpg = await connect(2, selections);
    vi.spyOn(gpg, "getAll").mockRejectedValue(new Error("read failed"));
    await expect(gpg.backup("123456", "12345678", 0)).rejects.toThrow("read failed");
    expect(selections).toEqual([0, 2]);
  });

  test("wipes the card data once the backup is built", async () => {
    const gpg = await connect(0, []);
    const data = cardInfo();
    data.private_03 = Buffer.from("secret DO");
    data.sig.key = Buffer.from("key blob");
    vi.spyOn(gpg, "getAll").mockResolvedValue(data);
    const payload = await gpg.backup("123456", "12345678", 0);
    expect(payload.private_03).toBe(Buffer.from("secret DO").toString("base64"));
    expect(data.private_03.every((b) => b === 0)).toBe(true);
    expect(data.sig.key.every((b) => b === 0)).toBe(true);
    expect(Object.values(gpg).includes(data)).toBe(false);
  });

  test("wipes the PIN buffers after a VERIFY", async () => {
    const gpg = await connect(0, []);
    const sent = [];
    const exchange = gpg.transport.exchange.bind(gpg.transport);
    gpg.transport.exchange = async (apdu) => {
      sent.push({ ins: apdu[1], apdu });
      return exchange(apdu);
    };
    await gpg.verifyPin(0x81, "123456");
    const verify = sent.find((frame) => frame.ins === 0x20);
    expect(verify.apdu.every((b) => b === 0)).toBe(true);
  });

  test.each([
    ["RSA key attributes without modulus size", (data) => (data.sig.attribute = Buffer.from([0x01]))],
    ["an unknown ECDSA curve", (data) => (data.dec.attribute = Buffer.from([0x13, 0xff]))],
    ["an unknown UIF", (data) => (data.aut.uif = 0xff)],
    ["a zero RSA exponent", (data) => (data.rsaPubExp = 0)],
  ])("rejects a backup with %s", async (_, change) => {
    const gpg = await connect(0, []);
    const data = cardInfo();
    change(data);
    vi.spyOn(gpg, "getAll").mockResolvedValue(data);
    await expect(gpg.backup("123456", "12345678", 0)).rejects.toThrow("Unexpected data from the device");
  });

  test("keeps the slot when backing up the active one", async () => {
    const selections = [];
    const gpg = await connect(1, selections);
    vi.spyOn(gpg, "getAll").mockResolvedValue(cardInfo());
    await gpg.backup("123456", "12345678", 1);
    expect(selections).toEqual([1]);
  });
});

describe("restore", () => {
  const pwStatus = (pw1) => Buffer.from([pw1, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]);
  const P256_ATTR = Buffer.from("132a8648ce3d030107", "hex");
  const backup = (pw1, uif) => {
    const slot = { date: "1970-01-01 00:00:00", uif, attribute: P256_ATTR.toString("base64") };
    const pw = pwStatus(pw1).toString("base64");
    return JSON.stringify({ ...BACKUP_FIELDS, PW_status: pw, sig: slot, dec: slot, aut: slot });
  };

  // Card with PW1 valid for one signature and UIF enabled on every key
  const card = (sent) =>
    new FakeTransport(async (apdu) => {
      sent.push(apdu);
      if (apdu[1] === 0xca && apdu[3] === 0x6e) {
        const attributes = [0xc1, 0xc2, 0xc3].map((tag) => Buffer.concat([Buffer.from([tag, P256_ATTR.length]), P256_ATTR]));
        const discretionary = Buffer.concat([Buffer.from([0xc4, 0x07]), pwStatus(0), ...attributes]);
        return Buffer.concat([Buffer.from([0x73, discretionary.length]), discretionary, OK]);
      }
      if (apdu[1] === 0xca && apdu[3] >= 0xd6 && apdu[3] <= 0xd8) return Buffer.from([0x01, 0x20, 0x90, 0x00]);
      return OK;
    });

  test("writes nothing when the security changes are not confirmed", async () => {
    const sent = [];
    transports.push(card(sent));
    const gpg = new GpgManager();
    await gpg.connect();

    const confirm = vi.fn(async () => false);
    expect(await gpg.restore("123456", "12345678", backup(1, 0), false, 0, confirm)).toBe(null);
    const [changes] = confirm.mock.calls[0];
    expect(changes.filter((c) => c.weaker).length).toBe(4);
    const writes = sent.filter((apdu) => apdu[1] === 0xda && apdu[3] !== 0xf2);
    expect(writes).toEqual([]);
    expect(gpg.busy).toBe(false);
  });

  test("does not ask for a confirmation when no security setting changes", async () => {
    const sent = [];
    transports.push(card(sent));
    const gpg = new GpgManager();
    await gpg.connect();

    const confirm = vi.fn(async () => false);
    expect(await gpg.restore("123456", "12345678", backup(0, 1), false, 0, confirm)).not.toBe(null);
    expect(confirm).not.toHaveBeenCalled();
  });
});

describe("restore fingerprints", () => {
  const P256_ATTR = Buffer.from("132a8648ce3d030107", "hex");
  const P256_POINT = Buffer.from(
    "04213d060d85290672936c17346f84cd6fa784e9c40fa974acf2016942e9804baa33ac0f771af9cffd6281d7affcd9fa" +
      "da327d11258d4ac5e719ffb641e7bedc42",
    "hex"
  );
  const P256_DATE = 1790753455;
  const P256_FINGERPRINT = "7a8b60a8bdf28b89f44d7ff7299b67877042b3c7";

  // Backup holding the signature key, and the same key as decryption key when `withDec`
  const backup = (withDec = false) => {
    const empty = { date: "1970-01-01 00:00:00", uif: 0, attribute: P256_ATTR.toString("base64") };
    const sig = {
      date: formatDate(P256_DATE),
      uif: 0,
      attribute: P256_ATTR.toString("base64"),
      fingerprint: Buffer.from(P256_FINGERPRINT, "hex").toString("base64"),
    };
    const pwStatus = Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]).toString("base64");
    return JSON.stringify({ ...BACKUP_FIELDS, PW_status: pwStatus, sig, dec: withDec ? sig : empty, aut: empty });
  };

  // Card whose key public point is `point`, or absent when null, with the
  // signature key `attribute`; `generated` maps a generation P2 to the point it
  // gives, or to a status word, or is a function of the key tag and P2. Writing
  // key attributes erases the key, as the firmware does.
  const card = (point, sent = [], generated = {}, attribute = P256_ATTR, decAttribute = P256_ATTR) =>
    new FakeTransport(async (apdu) => {
      sent.push(apdu);
      if (apdu[1] === 0xda && apdu[2] === 0x00 && apdu[3] >= 0xc1 && apdu[3] <= 0xc3) {
        point = null;
        return OK;
      }
      if (apdu[1] === 0x47 && apdu[2] === 0x80) {
        const result = typeof generated === "function" ? generated(apdu[5], apdu[3]) : generated[apdu[3]];
        if (result === undefined) return OK;
        if (typeof result === "number") return Buffer.from([result >> 8, result & 0xff]);
        point = result;
        return OK;
      }
      if (apdu[1] === 0xca && apdu[3] === 0x6e) {
        const pw = Buffer.from([0xc4, 0x07, 0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]);
        const attributes = [
          [0xc1, attribute],
          [0xc2, decAttribute],
          [0xc3, P256_ATTR],
        ].map(([tag, value]) => Buffer.concat([Buffer.from([tag, value.length]), value]));
        const discretionary = Buffer.concat([pw, ...attributes]);
        return Buffer.concat([Buffer.from([0x73, discretionary.length]), discretionary, OK]);
      }
      if (apdu[1] === 0xca && apdu[3] >= 0xd6 && apdu[3] <= 0xd8) return Buffer.from([0x00, 0x20, 0x90, 0x00]);
      if (apdu[1] === 0x47 && apdu[2] === 0x81) {
        if (point === null) return Buffer.from([0x69, 0x85]);
        const inner = Buffer.concat([Buffer.from([0x86, point.length]), point]);
        return Buffer.concat([Buffer.from([0x7f, 0x49, inner.length]), inner, OK]);
      }
      return OK;
    });

  const restore = async (
    point,
    sent = [],
    regenerate = false,
    generated = {},
    withDec = false,
    attribute = P256_ATTR,
    confirm = async () => true,
    decAttribute = P256_ATTR
  ) => {
    transports.push(card(point, sent, generated, attribute, decAttribute));
    const gpg = new GpgManager();
    gpg.generationDelay = 0;
    await gpg.connect();
    return gpg.restore("123456", "12345678", backup(withDec), regenerate, 0, confirm);
  };

  // PUT DATA APDUs writing the signature key attributes (C1)
  const sigAttributeWrites = (sent) => sent.filter((apdu) => apdu[1] === 0xda && apdu[2] === 0x00 && apdu[3] === 0xc1);
  const RSA2048_ATTR = Buffer.from("010800002001", "hex");

  // Data of the PUT DATA APDUs writing the signature key fingerprint (C7)
  const sigFingerprintWrites = (sent) =>
    sent.filter((apdu) => apdu[1] === 0xda && apdu[2] === 0x00 && apdu[3] === 0xc7).map((apdu) => apdu.subarray(5));

  test("accepts a key matching the backup fingerprint", async () => {
    expect(await restore(P256_POINT)).toEqual([]);
  });

  test("writes the fingerprint of a matching key after reading it", async () => {
    const sent = [];
    await restore(P256_POINT, sent);
    const read = sent.findIndex((apdu) => apdu[1] === 0x47 && apdu[2] === 0x81);
    const write = sent.findIndex((apdu) => apdu[1] === 0xda && apdu[3] === 0xc7);
    expect(read).toBeGreaterThanOrEqual(0);
    expect(write).toBeGreaterThan(read);
    expect(sigFingerprintWrites(sent).map((d) => d.toString("hex"))).toEqual([P256_FINGERPRINT]);
  });

  test("keeps the fingerprint of a mismatching key kept on the card", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const sent = [];
    const failures = await restore(other, sent);
    expect(failures[0].keyMismatch).toBe(true);
    expect(sigFingerprintWrites(sent)).toEqual([]);
  });

  test("keeps the card keys when the backup does not change their attributes", async () => {
    const sent = [];
    expect(await restore(P256_POINT, sent)).toEqual([]);
    expect(sigAttributeWrites(sent)).toEqual([]);
  });

  test("asks before erasing a key whose algorithm the backup changes", async () => {
    const sent = [];
    const confirm = vi.fn(async () => false);
    expect(await restore(P256_POINT, sent, false, {}, false, RSA2048_ATTR, confirm)).toBe(null);
    const [changes] = confirm.mock.calls[0];
    expect(changes.filter((c) => c.erased).map((c) => c.setting)).toEqual(["Signature key"]);
    expect(sent.filter((apdu) => apdu[1] === 0xda && apdu[3] !== 0xf2)).toEqual([]);
  });

  test("reports the key erased by an algorithm change once confirmed", async () => {
    const sent = [];
    const failures = await restore(P256_POINT, sent, false, {}, false, RSA2048_ATTR);
    expect(sigAttributeWrites(sent).map((apdu) => apdu.subarray(5).toString("hex"))).toEqual([
      P256_ATTR.toString("hex"),
    ]);
    expect(failures.map((f) => f.name)).toEqual(["Signature key (fingerprint)"]);
    expect(failures[0].message).toMatch("no key on the card");
    expect(sigFingerprintWrites(sent).map((d) => d.toString("hex"))).toEqual(["00".repeat(20)]);
  });

  test("does not ask before erasing a key the backup regenerates", async () => {
    const confirm = vi.fn(async () => true);
    expect(await restore(P256_POINT, [], true, { 0x02: P256_POINT }, false, RSA2048_ATTR, confirm)).toEqual([]);
    const [changes] = confirm.mock.calls[0];
    expect(changes.filter((c) => c.erased)).toEqual([]);
  });

  test("keeps the fingerprint of a card key the backup does not regenerate", async () => {
    const sent = [];
    expect(await restore(P256_POINT, sent, true, { 0x02: P256_POINT })).toEqual([]);
    const fingerprintTags = sent.filter((apdu) => apdu[1] === 0xda && apdu[2] === 0x00).map((apdu) => apdu[3]);
    expect(fingerprintTags).not.toContain(0xc8);
    expect(fingerprintTags).not.toContain(0xc9);
  });

  test("asks before erasing a card key the backup does not regenerate", async () => {
    const confirm = vi.fn(async () => false);
    const args = [P256_POINT, [], true, { 0x02: P256_POINT }, false, P256_ATTR, confirm, RSA2048_ATTR];
    expect(await restore(...args)).toBe(null);
    const [changes] = confirm.mock.calls[0];
    expect(changes.filter((c) => c.erased).map((c) => c.setting)).toEqual(["Decryption key"]);
  });

  test("does not rewrite unchanged attributes before regenerating", async () => {
    const sent = [];
    await restore(P256_POINT, sent, true, { 0x02: P256_POINT });
    const firstGeneration = sent.findIndex((apdu) => apdu[1] === 0x47 && apdu[2] === 0x80);
    expect(sigAttributeWrites(sent.slice(0, firstGeneration))).toEqual([]);
  });

  test("regenerates only the keys the backup holds", async () => {
    const sent = [];
    await restore(P256_POINT, sent, true);
    const generated = sent.filter((apdu) => apdu[1] === 0x47 && apdu[2] === 0x80).map((apdu) => apdu[5]);
    expect(generated).toEqual([0xb6]);
  });

  // P2 of the GEN ASYM KEY APDUs sent to generate a key
  const generationModes = (sent) =>
    sent.filter((apdu) => apdu[1] === 0x47 && apdu[2] === 0x80).map((apdu) => apdu[3]);

  test("regenerates a key with the current derivation first", async () => {
    const sent = [];
    expect(await restore(null, sent, true, { 0x02: P256_POINT })).toEqual([]);
    expect(generationModes(sent)).toEqual([0x02]);
    expect(sigFingerprintWrites(sent).map((d) => d.toString("hex"))).toEqual([P256_FINGERPRINT]);
  });

  test("regenerates a legacy key when the current derivation does not match", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const sent = [];
    expect(await restore(null, sent, true, { 0x02: other, 0x01: P256_POINT })).toEqual([]);
    expect(generationModes(sent)).toEqual([0x02, 0x01]);
    expect(sigFingerprintWrites(sent).map((d) => d.toString("hex"))).toEqual([P256_FINGERPRINT]);
  });

  test("regenerates a legacy key on an app without the current derivation", async () => {
    const sent = [];
    expect(await restore(null, sent, true, { 0x02: 0x6b00, 0x01: P256_POINT })).toEqual([]);
    expect(generationModes(sent)).toEqual([0x02, 0x01]);
  });

  test("reports a regenerated key matching no derivation", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const sent = [];
    const failures = await restore(null, sent, true, { 0x02: other, 0x01: other });
    expect(failures.map((f) => f.name)).toEqual(["Signature key (fingerprint)"]);
    expect(failures[0].keyMismatch).toBe(true);
    expect(sigFingerprintWrites(sent).map((d) => d.toString("hex"))).toEqual(["00".repeat(20)]);
  });

  test("erases a regenerated key matching no derivation", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const sent = [];
    await restore(null, sent, true, { 0x02: other, 0x01: other });
    const lastGeneration = sent.findLastIndex((apdu) => apdu[1] === 0x47 && apdu[2] === 0x80);
    const attributeWrites = sent
      .map((apdu, index) => ({ apdu, index }))
      .filter(({ apdu }) => apdu[1] === 0xda && apdu[2] === 0x00 && apdu[3] === 0xc1);
    expect(attributeWrites.at(-1).index).toBeGreaterThan(lastGeneration);
    expect(attributeWrites.at(-1).apdu.subarray(5).equals(P256_ATTR)).toBe(true);
  });

  test("keeps a regenerated key matching the backup", async () => {
    const sent = [];
    await restore(null, sent, true, { 0x02: P256_POINT });
    const lastGeneration = sent.findLastIndex((apdu) => apdu[1] === 0x47 && apdu[2] === 0x80);
    const lateAttributeWrites = sent.filter(
      (apdu, index) => index > lastGeneration && apdu[1] === 0xda && apdu[3] === 0xc1
    );
    expect(lateAttributeWrites).toEqual([]);
  });

  test("tries the derivation of the first key first for the next keys", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const sent = [];
    expect(await restore(null, sent, true, { 0x02: other, 0x01: P256_POINT }, true)).toEqual([]);
    expect(generationModes(sent)).toEqual([0x02, 0x01, 0x01]);
  });

  test("regenerates a backup mixing both derivations", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    // Legacy signature key, current decryption key
    const generated = (tag, p2) => ((tag === 0xb6) === (p2 === 0x01) ? P256_POINT : other);
    const sent = [];
    expect(await restore(null, sent, true, generated, true)).toEqual([]);
    expect(generationModes(sent)).toEqual([0x02, 0x01, 0x01, 0x02]);
  });

  test("regenerates the next keys when the first key matches no derivation", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    // Imported signature key, seeded decryption key
    const generated = (tag, p2) => (tag === 0xb8 && p2 === 0x01 ? P256_POINT : other);
    const sent = [];
    const failures = await restore(null, sent, true, generated, true);
    expect(generationModes(sent)).toEqual([0x02, 0x01, 0x02, 0x01]);
    expect(failures.map((f) => f.name)).toEqual(["Signature key (fingerprint)"]);
  });

  test("reports a key that cannot be regenerated", async () => {
    const failures = await restore(null, [], true, { 0x02: 0x6982, 0x01: 0x6982 });
    expect(failures.map((f) => f.name)).toEqual(["Signature key (regenerate)"]);
    expect(failures[0].sw).toBe(0x6982);
  });

  test("reports a key not matching the backup fingerprint", async () => {
    const other = Buffer.from(P256_POINT);
    other[10] ^= 0x01;
    const failures = await restore(other);
    expect(failures.map((f) => f.name)).toEqual(["Signature key (fingerprint)"]);
    expect(failures[0].message).toMatch("does not match the backup");
  });

  test("reports a missing key", async () => {
    const failures = await restore(null);
    expect(failures.map((f) => f.name)).toEqual(["Signature key (fingerprint)"]);
    expect(failures[0].message).toMatch("no key on the card");
  });
});

describe("WebHID permission", () => {
  const withDevice = () => {
    const transport = new FakeTransport();
    transport.device = { forget: vi.fn(async () => {}) };
    transports.push(transport);
    return transport;
  };

  test("is revoked on disconnect", async () => {
    const transport = withDevice();
    const gpg = new GpgManager();
    await gpg.connect();

    await gpg.disconnect();
    expect(transport.device.forget).toHaveBeenCalled();
  });

  test("is revoked when the device vanishes", async () => {
    const transport = withDevice();
    const gpg = new GpgManager();
    await gpg.connect();

    transport.emit("disconnect");
    expect(transport.device.forget).toHaveBeenCalled();
  });

  test("is left alone by browsers without forget()", async () => {
    const transport = new FakeTransport();
    transport.device = {};
    transports.push(transport);
    const gpg = new GpgManager();
    await gpg.connect();

    await expect(gpg.disconnect()).resolves.toBeUndefined();
  });
});
