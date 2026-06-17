import { getInt, decodeTLV } from "./tlv";

describe("getInt", () => {
  const buf = Buffer.from([0x12, 0x34, 0x56, 0x78]);

  test("reads 2 bytes big-endian", () => {
    expect(getInt(buf, 2, 0)).toBe(0x1234);
  });
  test("reads 3 bytes big-endian", () => {
    expect(getInt(buf, 3, 0)).toBe(0x123456);
  });
  test("reads 4 bytes big-endian (no sign overflow)", () => {
    expect(getInt(Buffer.from([0xff, 0xff, 0xff, 0xff]), 4, 0)).toBe(0xffffffff);
  });
  test("honors offset", () => {
    expect(getInt(buf, 2, 2)).toBe(0x5678);
  });
});

describe("decodeTLV", () => {
  test("short tag and short length", () => {
    // tag 0x5B, len 3, "ABC"
    const tags = decodeTLV(Buffer.from([0x5b, 0x03, 0x41, 0x42, 0x43]));
    expect(tags[0x5b].toString()).toBe("ABC");
  });

  test("two-byte tag", () => {
    // tag 0x5F50, len 3, "abc"
    const tags = decodeTLV(
      Buffer.from([0x5f, 0x50, 0x03, 0x61, 0x62, 0x63])
    );
    expect(tags[0x5f50].toString()).toBe("abc");
  });

  test("1-byte long length form (0x81)", () => {
    const value = Buffer.alloc(0x80, 0xaa); // 128 bytes
    const tags = decodeTLV(
      Buffer.concat([Buffer.from([0x5b, 0x81, 0x80]), value])
    );
    expect(tags[0x5b].length).toBe(0x80);
    expect(tags[0x5b].equals(value)).toBe(true);
  });

  test("2-byte long length form (0x82)", () => {
    const value = Buffer.alloc(0x0100, 0xbb); // 256 bytes
    const tags = decodeTLV(
      Buffer.concat([Buffer.from([0x5b, 0x82, 0x01, 0x00]), value])
    );
    expect(tags[0x5b].length).toBe(0x0100);
  });

  test("multiple concatenated objects", () => {
    const tags = decodeTLV(
      Buffer.from([0x5b, 0x01, 0x41, 0x5e, 0x02, 0x42, 0x43])
    );
    expect(tags[0x5b].toString()).toBe("A");
    expect(tags[0x5e].toString()).toBe("BC");
  });
});
