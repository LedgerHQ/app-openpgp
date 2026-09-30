import { vi } from "vitest";

const transports = [];

vi.mock("@ledgerhq/hw-transport-webhid", () => ({
  default: {
    isSupported: async () => true,
    request: async () => transports.shift(),
  },
}));

const { default: GpgManager } = await import("./GpgManager");

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
