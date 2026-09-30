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

describe("restore", () => {
  const pwStatus = (pw1) => Buffer.from([pw1, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]);
  const backup = (pw1, uif) => {
    const slot = { date: "1970-01-01 00:00:00", uif };
    return JSON.stringify({ version: 1, PW_status: pwStatus(pw1).toString("base64"), sig: slot, dec: slot, aut: slot });
  };

  // Card with PW1 valid for one signature and UIF enabled on every key
  const card = (sent) =>
    new FakeTransport(async (apdu) => {
      sent.push(apdu);
      if (apdu[1] === 0xca && apdu[3] === 0x6e) {
        const discretionary = Buffer.concat([Buffer.from([0xc4, 0x07]), pwStatus(0)]);
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

  const backup = () => {
    const empty = { date: "1970-01-01 00:00:00", uif: 0 };
    const sig = {
      date: formatDate(P256_DATE),
      uif: 0,
      attribute: P256_ATTR.toString("base64"),
      fingerprint: Buffer.from(P256_FINGERPRINT, "hex").toString("base64"),
    };
    const pwStatus = Buffer.from([0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]).toString("base64");
    return JSON.stringify({ version: 1, PW_status: pwStatus, sig, dec: empty, aut: empty });
  };

  // Card whose signature key public point is `point`, or absent when null
  const card = (point) =>
    new FakeTransport(async (apdu) => {
      if (apdu[1] === 0xca && apdu[3] === 0x6e) {
        const pw = Buffer.from([0xc4, 0x07, 0x01, 0x7f, 0x7f, 0x7f, 0x03, 0x00, 0x03]);
        return Buffer.concat([Buffer.from([0x73, pw.length]), pw, OK]);
      }
      if (apdu[1] === 0xca && apdu[3] >= 0xd6 && apdu[3] <= 0xd8) return Buffer.from([0x00, 0x20, 0x90, 0x00]);
      if (apdu[1] === 0x47 && apdu[2] === 0x81) {
        if (point === null) return Buffer.from([0x69, 0x85]);
        const inner = Buffer.concat([Buffer.from([0x86, point.length]), point]);
        return Buffer.concat([Buffer.from([0x7f, 0x49, inner.length]), inner, OK]);
      }
      return OK;
    });

  const restore = async (point) => {
    transports.push(card(point));
    const gpg = new GpgManager();
    await gpg.connect();
    return gpg.restore("123456", "12345678", backup(), false, 0, async () => true);
  };

  test("accepts a key matching the backup fingerprint", async () => {
    expect(await restore(P256_POINT)).toEqual([]);
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
