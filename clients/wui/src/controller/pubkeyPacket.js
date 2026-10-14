// OpenPGP v4 fingerprint of a card public key (RFC 4880 §12.2, RFC 6637),
// computed as GnuPG does for the keys it creates on the card.

import { CURVE_OID } from "./dataObjects.js";

const ALGO_RSA = 0x01;
const ALGO_ECDH = 0x12;
const ALGO_ECDSA = 0x13;
const ALGO_EDDSA = 0x16;

// Curve OID -> size in bits, which selects the default ECDH KDF parameters
const CURVE_BITS = {
  [CURVE_OID.nistp256]: 256, // NIST P-256
  "2b81040022": 384, // NIST P-384
  "2b81040023": 521, // NIST P-521
  [CURVE_OID.secp256k1]: 256, // secp256k1
  "2b2403030208010107": 256, // brainpoolP256r1
  "2b240303020801010b": 384, // brainpoolP384r1
  "2b240303020801010d": 512, // brainpoolP512r1
  [CURVE_OID.ed25519]: 256, // Ed25519
  [CURVE_OID.cv25519]: 256, // Cv25519
};

// Curves whose points are 32 raw bytes, encoded with the 0x40 native prefix
const NATIVE_CURVES = new Set([CURVE_OID.ed25519, CURVE_OID.cv25519]);

// ECDH KDF parameters: reserved 0x01, hash algorithm, key wrap algorithm
function kdfParams(bits) {
  if (bits <= 256) return [0x03, 0x01, 0x08, 0x07]; // SHA-256, AES-128
  if (bits <= 384) return [0x03, 0x01, 0x09, 0x09]; // SHA-384, AES-256
  return [0x03, 0x01, 0x0a, 0x09]; // SHA-512, AES-256
}

function mpi(value) {
  let v = Buffer.from(value);
  let start = 0;
  while (start < v.length && v[start] === 0) start++;
  v = v.slice(start);
  const bits = v.length === 0 ? 0 : (v.length - 1) * 8 + (32 - Math.clz32(v[0]));
  return Buffer.concat([Buffer.from([bits >> 8, bits & 0xff]), v]);
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

// Public key packet body, or null when the algorithm is not supported.
// `pubkey` holds the 7F49 content: 81 modulus and 82 exponent, or 86 point.
function publicKeyBody(attribute, pubkey, date) {
  const attr = Buffer.from(attribute || []);
  if (attr.length === 0) return null;
  const head = Buffer.concat([Buffer.from([0x04]), u32be(date), Buffer.from([attr[0]])]);

  if (attr[0] === ALGO_RSA) {
    if (!pubkey[0x81] || !pubkey[0x82]) return null;
    return Buffer.concat([head, mpi(pubkey[0x81]), mpi(pubkey[0x82])]);
  }
  if (![ALGO_ECDH, ALGO_ECDSA, ALGO_EDDSA].includes(attr[0]) || !pubkey[0x86]) return null;

  const oid = attr.slice(1, attr[attr.length - 1] === 0xff ? -1 : undefined);
  const bits = CURVE_BITS[oid.toString("hex")];
  if (!bits) return null;
  const point = NATIVE_CURVES.has(oid.toString("hex"))
    ? Buffer.concat([Buffer.from([0x40]), pubkey[0x86]])
    : pubkey[0x86];
  const parts = [head, Buffer.from([oid.length]), oid, mpi(point)];
  if (attr[0] === ALGO_ECDH) parts.push(Buffer.from(kdfParams(bits)));
  return Buffer.concat(parts);
}

// Fingerprint (20 bytes), or null when the key algorithm is not supported.
export async function keyFingerprint(attribute, pubkey, date) {
  const body = publicKeyBody(attribute, pubkey, date);
  if (!body) return null;
  const packet = Buffer.concat([Buffer.from([0x99, body.length >> 8, body.length & 0xff]), body]);
  return Buffer.from(await crypto.subtle.digest("SHA-1", packet));
}
