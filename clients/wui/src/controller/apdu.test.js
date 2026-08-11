import { exchange, getData, putData, APDU_MAX_SIZE } from "./apdu";

// Minimal fake transport: records every frame sent and replays canned
// responses (each a Buffer of data + 2-byte SW) in order.
class MockTransport {
  constructor(responses) {
    this.responses = responses;
    this.sent = [];
    this.index = 0;
  }
  async exchange(buffer) {
    this.sent.push(Buffer.from(buffer));
    return this.responses[this.index++];
  }
}

describe("exchange", () => {
  test("parses data and status word", async () => {
    const t = new MockTransport([Buffer.from([0x01, 0x02, 0x90, 0x00])]);
    const { data, sw } = await exchange(t, "00CA004F00");
    expect(data.equals(Buffer.from([0x01, 0x02]))).toBe(true);
    expect(sw).toBe(0x9000);
  });

  test("hex string command is parsed as hex, not utf-8", async () => {
    const t = new MockTransport([Buffer.from([0x90, 0x00])]);
    await exchange(t, "00A4040006D27600012401");
    expect(t.sent[0].length).toBe(11);
    expect(t.sent[0].toString("hex")).toBe("00a4040006d27600012401");
  });

  test("drains GET RESPONSE (61xx) continuations", async () => {
    const t = new MockTransport([
      Buffer.from([0xaa, 0x61, 0x03]), // more data: 3 bytes
      Buffer.from([0xbb, 0xcc, 0xdd, 0x90, 0x00]),
    ]);
    const { data, sw } = await exchange(t, "00CA004F00");
    expect(data.equals(Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]))).toBe(true);
    expect(sw).toBe(0x9000);
    expect(t.sent[1].equals(Buffer.from([0x00, 0xc0, 0x00, 0x00, 0x03]))).toBe(
      true
    );
  });

  test("command-chains outgoing data larger than APDU_MAX_SIZE", async () => {
    const payload = Buffer.alloc(300, 0x77); // > 254
    const t = new MockTransport([
      Buffer.from([0x90, 0x00]), // intermediate chained frame
      Buffer.from([0x90, 0x00]), // final frame
    ]);
    const sw = await putData(t, 0xb6, payload);
    expect(sw).toBe(0x9000);

    // First frame: chained CLA (0x00 | 0x10), full 0xFE chunk.
    const first = t.sent[0];
    expect(first[0]).toBe(0x10);
    expect(first.slice(1, 5).equals(Buffer.from([0xda, 0x00, 0xb6, APDU_MAX_SIZE]))).toBe(
      true
    );
    expect(first.length).toBe(5 + APDU_MAX_SIZE);

    // Last frame: original CLA, remaining 46 bytes.
    const last = t.sent[1];
    expect(last[0]).toBe(0x00);
    expect(last.slice(0, 4).equals(Buffer.from([0x00, 0xda, 0x00, 0xb6]))).toBe(
      true
    );
    expect(last[4]).toBe(300 - APDU_MAX_SIZE);
    expect(last.length).toBe(5 + (300 - APDU_MAX_SIZE));
  });
});

describe("getData", () => {
  test("builds a GET DATA APDU with the tag as P1P2 and Le=0", async () => {
    const t = new MockTransport([Buffer.from([0xde, 0xad, 0x90, 0x00])]);
    const data = await getData(t, 0x01f1);
    expect(t.sent[0].equals(Buffer.from([0x00, 0xca, 0x01, 0xf1, 0x00]))).toBe(
      true
    );
    expect(data.equals(Buffer.from([0xde, 0xad]))).toBe(true);
  });
});
