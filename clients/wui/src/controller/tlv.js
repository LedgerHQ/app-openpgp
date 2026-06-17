// BER-TLV helpers, ported from pytools/gpgapp/gpgcard.py (`_get_int`,
// `_decode_tlv`). The OpenPGP card returns most data objects as nested TLV
// structures (cardholder data, application related data, ...).

// Read a big-endian unsigned integer of `size` bytes at `offset`.
export function getInt(buffer, size = 2, offset = 0) {
  let value = 0;
  for (let i = 0; i < size; i++) {
    value = value * 256 + buffer[offset + i];
  }
  return value;
}

// Decode a (possibly multi-object) TLV buffer into a plain object keyed by
// the numeric tag. Tags may be 1 or 2 bytes; lengths use the short form or the
// 0x81 / 0x82 long forms. Duplicate tags keep the last occurrence, matching
// the python implementation.
export function decodeTLV(buffer) {
  const tags = {};
  let tlv = Buffer.from(buffer);

  while (tlv.length) {
    let offset;
    let tag;
    if ((tlv[0] & 0x1f) === 0x1f) {
      tag = getInt(tlv, 2, 0);
      offset = 2;
    } else {
      tag = tlv[0];
      offset = 1;
    }

    let length = tlv[offset];
    if (length & 0x80) {
      const numBytes = length & 0x7f;
      if (numBytes === 1) {
        length = tlv[offset + 1];
        offset += 2;
      } else if (numBytes === 2) {
        length = getInt(tlv, 2, offset + 1);
        offset += 3;
      }
    } else {
      offset += 1;
    }

    tags[tag] = tlv.slice(offset, offset + length);
    tlv = tlv.slice(offset + length);
  }
  return tags;
}
