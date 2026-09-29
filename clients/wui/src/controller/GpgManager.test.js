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
