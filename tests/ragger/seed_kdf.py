# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
Python model of the seeded key derivation, legacy and v2,
computed from the default Speculos recovery phrase.
"""

import hashlib
from math import isqrt

from bip_utils import Bip32Slip10Secp256k1, Bip39SeedGenerator, Secp256k1PrivateKey
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Util.number import isPrime
from ragger.bip.seed import SPECULOS_MNEMONIC

APP_PATH = 0x80475047
ALGO_RSA = 0x01

# Curve orders, as used to reduce the derived scalar
CURVE_ORDER = {
    "nistp256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "secp256k1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    "ed25519": 2**252 + 27742317777372353535851937790883648493,
    "cv25519": 2**252 + 27742317777372353535851937790883648493,
}
P25519 = 2**255 - 19


def slot_seed(slot: int) -> bytes:
    """Seed of a slot: BIP32 secp256k1 derivation on APP_PATH / (slot + 1)"""

    root = Bip32Slip10Secp256k1.FromSeed(Bip39SeedGenerator(SPECULOS_MNEMONIC).Generate())
    return root.ChildKey(APP_PATH).ChildKey(slot + 1).PrivateKey().Raw().ToBytes()


def role_name(role: str) -> bytes:
    """Key name hashed by the derivation: 'sig ', 'dec ' or 'aut '"""

    return role.encode() + b" "


def derive_legacy(seed: bytes, role: str, idx: int, nbytes: int) -> bytes:
    """Legacy derivation: only nbytes / 8 bytes are produced"""

    h = hashlib.sha256(seed + role_name(role) + idx.to_bytes(2, "big")).digest()
    return hashlib.shake_256(h).digest(nbytes // 8)


def derive_v2(seed: bytes, role: str, idx: int, attributes: bytes, nbytes: int) -> bytes:
    """v2 derivation, bound to the algorithm and the RSA size or curve OID"""

    ctx = attributes[:3] if attributes[0] == ALGO_RSA else attributes
    h = hashlib.sha256(b"kdf2" + seed + role_name(role) + idx.to_bytes(2, "big") + bytes([len(ctx)]) + ctx).digest()
    return hashlib.shake_256(h).digest(nbytes)


def next_prime(x: int) -> int:
    """Smallest prime from x, as the SDK next_prime"""

    x |= 1
    while not isPrime(x):
        x += 2
    return x


def rsa_modulus(slot: int, role: str, attributes: bytes, v2: bool) -> int:
    """Modulus of a seeded RSA key"""

    seed = slot_seed(slot)
    size = int.from_bytes(attributes[1:3], "big") // 16
    primes = []
    for idx in (1, 2):
        if v2:
            start = bytearray(derive_v2(seed, role, idx, attributes, size))
            start[0] |= 0xC0
        else:
            start = bytearray(derive_legacy(seed, role, idx, size).ljust(size, b"\x00"))
            start[0] |= 0x80
        primes.append(next_prime(int.from_bytes(start, "big")))
    return primes[0] * primes[1]


def ecc_private(slot: int, role: str, template: str, attributes: bytes, v2: bool) -> bytes:
    """Private scalar of a seeded key on a 256-bit curve"""

    seed = slot_seed(slot)
    if not v2:
        # derived in place over the slot seed
        return derive_legacy(seed, role, 1, 32) + seed[4:32]
    wide = derive_v2(seed, role, 1, attributes, 64)
    d = bytearray((int.from_bytes(wide, "big") % CURVE_ORDER[template]).to_bytes(32, "big"))
    if template == "cv25519":
        d[31] &= 0xF8
        d[0] = (d[0] & 0x7F) | 0x40
    return bytes(d)


def _x25519_base(k: int) -> int:
    """Montgomery ladder on the Curve25519 base point, over 255 bits as the SDK"""

    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P25519, (x2 - z2) % P25519
        aa, bb = a * a % P25519, b * b % P25519
        e = (aa - bb) % P25519
        c, d = (x3 + z3) % P25519, (x3 - z3) % P25519
        da, cb = d * a % P25519, c * b % P25519
        x3 = (da + cb) ** 2 % P25519
        z3 = x1 * (da - cb) ** 2 % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + 121665 * e) % P25519
    if swap:
        x2, z2 = x3, z3
    return x2 * pow(z2, P25519 - 2, P25519) % P25519


def ecc_public(template: str, d: bytes) -> bytes:
    """Public key, encoded as returned by the app in tag 86"""

    if template == "nistp256":
        q = ECC.construct(curve="P-256", d=int.from_bytes(d, "big")).pointQ
        return b"\x04" + q.x.to_bytes(32, "big") + q.y.to_bytes(32, "big")
    if template == "secp256k1":
        return Secp256k1PrivateKey.FromBytes(d).PublicKey().RawUncompressed().ToBytes()
    if template == "ed25519":
        return eddsa.import_private_key(d).public_key().export_key(format="raw")
    if template == "cv25519":
        return _x25519_base(int.from_bytes(d, "big")).to_bytes(32, "little")
    raise ValueError(f"Unsupported template: {template}")


def _divisor_pairs(m: int):
    d = 1
    while d * d <= m:
        if m % d == 0:
            yield d, m // d
            yield m // d, d
        d += 1


def factor_legacy_rsa(n: int) -> tuple[int, int] | None:
    """Factor a legacy seeded modulus, whose primes are a * 2^k + small gap"""

    half = n.bit_length() // 2
    k = half - half // 8
    low = n % (1 << k)
    if low.bit_length() > 32:
        return None
    for dp, dq in _divisor_pairs(low):
        m = (n - low) >> k
        for carry in range(4):
            ab = (m >> k) - carry
            s = m - (ab << k)
            disc = s * s - 4 * dq * ab * dp
            if disc < 0 or isqrt(disc) ** 2 != disc:
                continue
            for num in (s + isqrt(disc), s - isqrt(disc)):
                if num > 0 and num % (2 * dq) == 0:
                    p = ((num // (2 * dq)) << k) + dp
                    if 1 < p < n and n % p == 0:
                        return p, n // p
    return None
