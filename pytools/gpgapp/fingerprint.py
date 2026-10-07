"""OpenPGP v4 fingerprint of a card public key (RFC 4880 §12.2, RFC 6637),
computed as GnuPG does for the keys it creates on the card.
"""

import hashlib

ALGO_RSA = 0x01
ALGO_ECDH = 0x12
ALGO_ECDSA = 0x13
ALGO_EDDSA = 0x16

# Curve OID -> size in bits, which selects the default ECDH KDF parameters
CURVE_BITS = {
    "2a8648ce3d030107": 256,  # NIST P-256
    "2b81040022": 384,  # NIST P-384
    "2b81040023": 521,  # NIST P-521
    "2b8104000a": 256,  # secp256k1
    "2b2403030208010107": 256,  # brainpoolP256r1
    "2b240303020801010b": 384,  # brainpoolP384r1
    "2b240303020801010d": 512,  # brainpoolP512r1
    "2b06010401da470f01": 256,  # Ed25519
    "2b060104019755010501": 256,  # Cv25519
}

# Curves whose points are 32 raw bytes, encoded with the 0x40 native prefix
NATIVE_CURVES = {"2b06010401da470f01", "2b060104019755010501"}


def _kdf_params(bits: int) -> bytes:
    """ECDH KDF parameters: reserved 0x01, hash algorithm, key wrap algorithm"""

    if bits <= 256:
        return bytes([0x03, 0x01, 0x08, 0x07])  # SHA-256, AES-128
    if bits <= 384:
        return bytes([0x03, 0x01, 0x09, 0x09])  # SHA-384, AES-256
    return bytes([0x03, 0x01, 0x0A, 0x09])  # SHA-512, AES-256


def _mpi(value: bytes) -> bytes:
    value = value.lstrip(b"\x00")
    bits = int.from_bytes(value, "big").bit_length()
    return bits.to_bytes(2, "big") + value


def _public_key_body(attribute: bytes, pubkey: dict, date: int) -> bytes | None:
    """Public key packet body, or None when the algorithm is not supported

    `pubkey` holds the 7F49 content: 81 modulus and 82 exponent, or 86 point.
    """

    if len(attribute) == 0:
        return None
    head = bytes([0x04]) + date.to_bytes(4, "big") + bytes([attribute[0]])

    if attribute[0] == ALGO_RSA:
        if 0x81 not in pubkey or 0x82 not in pubkey:
            return None
        return head + _mpi(pubkey[0x81]) + _mpi(pubkey[0x82])
    if attribute[0] not in (ALGO_ECDH, ALGO_ECDSA, ALGO_EDDSA) or 0x86 not in pubkey:
        return None

    oid = attribute[1:-1] if attribute[-1] == 0xFF else attribute[1:]
    bits = CURVE_BITS.get(oid.hex())
    if bits is None:
        return None
    point = b"\x40" + pubkey[0x86] if oid.hex() in NATIVE_CURVES else pubkey[0x86]
    body = head + bytes([len(oid)]) + oid + _mpi(point)
    if attribute[0] == ALGO_ECDH:
        body += _kdf_params(bits)
    return body


def key_fingerprint(attribute: bytes, pubkey: dict, date: int) -> bytes | None:
    """Fingerprint (20 bytes), or None when the key algorithm is not supported"""

    body = _public_key_body(attribute, pubkey, date)
    if body is None:
        return None
    packet = bytes([0x99]) + len(body).to_bytes(2, "big") + body
    return hashlib.sha1(packet).digest()
