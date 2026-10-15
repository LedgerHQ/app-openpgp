# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for private key backup and restore
"""

import struct

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, KeyGenMode, PassWord
from application_client.command_sender import CommandSender
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, pkcs1_15
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.utils import RAPDU
from seed_kdf import derive_legacy, ecc_private, slot_seed
from utils import KEY_TEMPLATES, SHA256_DIGEST_INFO, check_pincode, generate_key, get_ECDSA_pub_key, get_RSA_pub_key

APDU_CHUNK_LEN = 0xFE
P256_COORD_LEN = 32
BACKUP_FORMAT_V3 = 0x03
GCM_NONCE_LEN = 12
# Offset of the key reference in the v3 blob, after the version and the nonce
BACKUP_V3_ROLE_OFFSET = 1 + GCM_NONCE_LEN
P256_ATTRIBUTES_LEN = len(bytes.fromhex(KEY_TEMPLATES["nistp256"]))
# Offset of the EC point in the v3 blob: role, public key length, curve and point length
BACKUP_V3_EC_POINT_OFFSET = BACKUP_V3_ROLE_OFFSET + 2 + 1 + P256_ATTRIBUTES_LEN + 4 + 4 + 4

# v1 backup of the seeded NIST P-256 SIG key, exported on Speculos default seed before v2
BACKUP_V1_P256_SIG = bytes.fromhex(
    "01333000040000000c000000ac220000004100000004bd19fa51014ce1d8f9030167f75082ac2a570311f03c0941afbc"
    "0765825d8a44cd62f02c961919cdd1977c6fcaa19e06069d7ea8fa56d0dc61c0ec004fec972f00000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000006855cff1"
    "07bdd44271044e4a4a1913279ae0055e959a93b56b38d846298d7da013aabd4c0198afbb8eb417681bcd6a8f89c84d85"
    "0adb2c64b4cd216ac34ee4bf91fbbe6af2a42d98142d4307da17e83932ff2ed6abc5b242a5cd2ac86b267d856f32e24b"
    "a58ccf2c40"
)

# v2 backup of the seeded (v2 derivation) NIST P-256 SIG key, exported on Speculos default seed before v3
BACKUP_V2_P256_SIG = bytes.fromhex(
    "02330000040000000c8db27946148d7583761bd5eb000000ac2200000041000000045aeec40b367d0964478b40d82427"
    "3d719a576a9b1031aa33593651bf4ab1a445086704d520c9f339d9630ccf597571c28a99f08add48b04aa1b114ec7be7"
    "862500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000006872fec08c1a319adb70d652dd30dbd1bc450718a3e68b498da7d2de11a331723d93543de72c807f"
    "686fd56e96b764c01568d602f906f2951fb666adbafb4c3b9ff92e7e843c01a0b96af7cc62b3f0c16f79c2a5be51084f"
    "fe28917b75198e0da1f38b3ed653ecad8b"
)

# Legacy (AES-CBC) backup blob: TARGET_ID and API level, then the public and private EC key structures
LEGACY_HEADER = struct.pack(">II", 0x33000004, 25)
# Public key structure of the seeded (legacy derivation) NIST P-256 SIG key, taken from the v1 backup
V1_PUBLIC_KEY_OFFSET = 1 + 4 + 4
P256_LEGACY_SIG_PUBLIC = BACKUP_V1_P256_SIG[V1_PUBLIC_KEY_OFFSET + 4 : V1_PUBLIC_KEY_OFFSET + 4 + 0xAC]
# SDK private key structure: curve, scalar length (little endian), then the scalar on 80 bytes
CX_CURVE_SECP256R1 = 0x22
EC_PRIVATE_SCALAR_SIZE = 80


def _rsa2048_private(key: RSA.RsaKey) -> bytes:
    """SDK RSA-2048 private key structure: size (little endian), private exponent and modulus"""

    size = key.size_in_bytes()
    return struct.pack("<I", size) + key.d.to_bytes(size, "big") + key.n.to_bytes(size, "big")


def _legacy_backup(private: bytes, public: bytes = P256_LEGACY_SIG_PUBLIC, pad: bool = True) -> bytes:
    """Legacy backup blob of the slot 1, encrypted with AES-CBC and a zero IV"""

    seed = slot_seed(0)
    key = derive_legacy(seed, "key", 1, 16) + seed[2:16]
    plain = private + b"\x80" if pad else private
    plain += bytes(-len(plain) % AES.block_size)
    encrypted = AES.new(key, AES.MODE_CBC, iv=bytes(AES.block_size)).encrypt(plain)
    return LEGACY_HEADER + struct.pack(">I", len(public)) + public + struct.pack(">I", len(encrypted)) + encrypted


def _p256_legacy_private() -> bytes:
    """Private key structure of the seeded (legacy derivation) NIST P-256 SIG key"""

    attributes = bytes.fromhex(KEY_TEMPLATES["nistp256"])
    d = ecc_private(0, "sig", "nistp256", attributes, False)
    return struct.pack("<II", CX_CURVE_SECP256R1, len(d)) + d.ljust(EC_PRIVATE_SCALAR_SIZE, b"\x00")


def _get_key_backup(backend: BackendInterface, client: CommandSender, key: DataObject) -> bytes:
    header = struct.pack(">BBBBB", ClaType.CLA_APP, InsType.INS_GET_DATA, 0, key, 0)
    try:
        rapdu = backend.exchange_raw(header)
    except ExceptionRAPDU as err:
        rapdu = RAPDU(err.status, err.data)
    rapdu = client.get_long_response(rapdu)
    assert rapdu.status == Errors.SW_OK
    return rapdu.data


def _put_key_backup(backend: BackendInterface, key: DataObject, data: bytes) -> None:
    chunks = [data[i : i + APDU_CHUNK_LEN] for i in range(0, len(data), APDU_CHUNK_LEN)]
    for idx, chunk in enumerate(chunks):
        cla = ClaType.CLA_APP if idx == len(chunks) - 1 else ClaType.CLA_APP_CHAIN
        header = struct.pack(">BBBBB", cla, InsType.INS_PUT_DATA, 0, key, len(chunk))
        rapdu = backend.exchange_raw(header + chunk)
        assert rapdu.status == Errors.SW_OK


def _sign_raw(client: CommandSender, digest: bytes) -> bytes:
    # MPI encoding 0x00 || r || 0x00 || s is only unambiguous when r and s are full length
    for _ in range(8):
        rapdu = client.sign(digest)
        assert rapdu.status == Errors.SW_OK
        sig = rapdu.data
        if len(sig) == 2 * (P256_COORD_LEN + 1):
            return sig[1 : P256_COORD_LEN + 1] + sig[P256_COORD_LEN + 2 :]
    pytest.fail("No full length ECDSA signature received")


# In this test we back up a private key and restore it
def test_backup_restore(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["nistp256"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_SIG_KEY)
    pubkey = get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)

    backup = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)

    tampered = bytearray(backup)
    tampered[-1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(tampered))

    _put_key_backup(backend, DataObject.DO_SIG_KEY, backup)
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    DSS.new(pubkey, "fips-186-3").verify(hash_obj, _sign_raw(client, hash_obj.digest()))


def _gen_p256_sig_key(client: CommandSender, mode: KeyGenMode = KeyGenMode.DEFAULT):
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["nistp256"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_SIG_KEY, mode)
    return get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)


# In this test we check that every backup uses its own nonce
def test_backup_nonce_unique(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)

    backup1 = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)
    backup2 = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)
    assert backup1[0] == BACKUP_FORMAT_V3
    nonce = slice(1, 1 + GCM_NONCE_LEN)
    assert backup1[nonce] != backup2[nonce]
    assert backup1[-P256_COORD_LEN:] != backup2[-P256_COORD_LEN:]

    for backup in (backup1, backup2):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, backup)


# In this test we restore a backup produced in the v1 format
def test_restore_v1_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client, KeyGenMode.SEED_LEGACY)

    tampered = bytearray(BACKUP_V1_P256_SIG)
    tampered[-1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(tampered))

    _put_key_backup(backend, DataObject.DO_SIG_KEY, BACKUP_V1_P256_SIG)
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    DSS.new(pubkey, "fips-186-3").verify(hash_obj, _sign_raw(client, hash_obj.digest()))


# In this test we restore a backup produced in the v2 format
def test_restore_v2_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client, KeyGenMode.SEED_V2)

    tampered = bytearray(BACKUP_V2_P256_SIG)
    tampered[-1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(tampered))

    _put_key_backup(backend, DataObject.DO_SIG_KEY, BACKUP_V2_P256_SIG)
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    DSS.new(pubkey, "fips-186-3").verify(hash_obj, _sign_raw(client, hash_obj.digest()))


# In this test we restore a backup produced in the legacy format
def test_restore_legacy_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client, KeyGenMode.SEED_LEGACY)

    _put_key_backup(backend, DataObject.DO_SIG_KEY, _legacy_backup(_p256_legacy_private()))
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    DSS.new(pubkey, "fips-186-3").verify(hash_obj, _sign_raw(client, hash_obj.digest()))


# In this test we restore altered legacy backups, carrying another public key
def test_restore_altered_legacy_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client)
    private = _p256_legacy_private()

    blobs = {
        "bad padding": _legacy_backup(private, pad=False),
        "bad length": _legacy_backup(private[:-1]),
        "altered ciphertext": _legacy_backup(private)[:-1] + b"\x00",
    }
    for name, blob in blobs.items():
        # Every failure gives the same status, and the public key is left untouched
        assert _put_key_backup_status(backend, DataObject.DO_SIG_KEY, blob) == Errors.SW_WRONG_DATA, name
        assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey, name


# In this test we restore a RSA key from a legacy backup, then from altered ones
def test_restore_legacy_backup_rsa(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])
    assert rapdu.status == Errors.SW_OK
    key = RSA.generate(2048)
    public = key.e.to_bytes(4, "big")

    _put_key_backup(backend, DataObject.DO_SIG_KEY, _legacy_backup(_rsa2048_private(key), public))
    assert get_RSA_pub_key(client, DataObject.DO_SIG_KEY).n == key.n

    other = RSA.generate(2048)
    for blob in (
        _legacy_backup(_rsa2048_private(other), public, pad=False),
        _legacy_backup(_rsa2048_private(other)[:-1], public),
    ):
        assert _put_key_backup_status(backend, DataObject.DO_SIG_KEY, blob) == Errors.SW_WRONG_DATA
        assert get_RSA_pub_key(client, DataObject.DO_SIG_KEY).n == key.n

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    rapdu = client.sign(SHA256_DIGEST_INFO + hash_obj.digest())
    assert rapdu.status == Errors.SW_OK
    pkcs1_15.new(key.public_key()).verify(hash_obj, rapdu.data)


# In this test we restore the backup of a key into another key role with the same attributes
def test_restore_backup_other_role(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)
    backup = bytearray(_get_key_backup(backend, client, DataObject.DO_SIG_KEY))

    rapdu = client.set_template(DataObject.DO_AUT_ATTR, KEY_TEMPLATES["nistp256"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_AUT_KEY)
    aut_pubkey = get_ECDSA_pub_key(client, DataObject.DO_AUT_KEY)

    assert _put_key_backup_status(backend, DataObject.DO_AUT_KEY, bytes(backup)) == Errors.SW_WRONG_DATA

    # The key reference is authenticated: rewriting it breaks the blob
    struct.pack_into(">H", backup, BACKUP_V3_ROLE_OFFSET, DataObject.DO_AUT_KEY)
    assert _put_key_backup_status(backend, DataObject.DO_AUT_KEY, bytes(backup)) != Errors.SW_OK

    assert get_ECDSA_pub_key(client, DataObject.DO_AUT_KEY) == aut_pubkey


# In this test we restore the backup of a key on another slot
def test_restore_backup_other_slot(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)
    backup = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)

    check_pincode(client, PassWord.PW2)
    assert client.set_slot(1).status == Errors.SW_OK
    pubkey = _gen_p256_sig_key(client)
    assert _put_key_backup_status(backend, DataObject.DO_SIG_KEY, backup) != Errors.SW_OK
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey
    check_pincode(client, PassWord.PW2)
    assert client.set_slot(0).status == Errors.SW_OK


# In this test we restore a backup whose authenticated public key has been modified
def test_restore_tampered_public_key(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client)

    backup = bytearray(_get_key_backup(backend, client, DataObject.DO_SIG_KEY))
    backup[BACKUP_V3_EC_POINT_OFFSET + 1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(backup))

    # The stored public key is left untouched
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey


# In this test we restore a key whose curve differs from the current key attributes
def test_restore_key_on_other_curve(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)
    backup = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)

    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["secp256k1"])
    assert rapdu.status == Errors.SW_OK
    assert _put_key_backup_status(backend, DataObject.DO_SIG_KEY, backup) == Errors.SW_WRONG_DATA

    # The P-256 key is not stored under secp256k1 attributes
    rapdu = client.read_key(DataObject.DO_SIG_KEY)
    assert rapdu.status == Errors.SW_REFERENCED_DATA_NOT_FOUND
    check_pincode(client, PassWord.PW1)
    rapdu = client.sign(get_random_bytes(P256_COORD_LEN))
    assert rapdu.status != Errors.SW_OK


def _put_key_backup_status(backend: BackendInterface, key: DataObject, data: bytes) -> int:
    header = struct.pack(">BBBB", ClaType.CLA_APP, InsType.INS_PUT_DATA, 0, key)
    try:
        if len(data) <= APDU_CHUNK_LEN:
            return backend.exchange_raw(header + struct.pack(">B", len(data)) + data if data else header).status
        _put_key_backup(backend, key, data)
        return Errors.SW_OK
    except (ExceptionRAPDU, AssertionError) as err:
        return getattr(err, "status", Errors.SW_UNKNOWN)


# In this test we restore empty and truncated backups
def test_restore_truncated_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)
    backup = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)
    legacy_header = struct.pack(">I", 0x33300004)

    blobs = [b"", backup[:1], backup[:GCM_NONCE_LEN], backup[:BACKUP_V3_ROLE_OFFSET]]
    blobs += [backup[: BACKUP_V3_ROLE_OFFSET + 2], backup[: BACKUP_V3_ROLE_OFFSET + 3 + P256_ATTRIBUTES_LEN - 1]]
    blobs += [backup[: BACKUP_V3_ROLE_OFFSET + 3 + P256_ATTRIBUTES_LEN + 2], backup[:-1]]
    blobs += [legacy_header, legacy_header + bytes(6)]
    for blob in blobs:
        assert _put_key_backup_status(backend, DataObject.DO_SIG_KEY, blob) != Errors.SW_OK
        # The application is still running
        assert client.get_data(DataObject.DO_AID).status == Errors.SW_OK


# In this test we restore a RSA key after its attributes have been written again, as a full restore does
def test_backup_restore_rsa(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_SIG_KEY)
    pubkey = get_RSA_pub_key(client, DataObject.DO_SIG_KEY)
    backup = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)

    # Writing the key attributes erases the key
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])
    assert rapdu.status == Errors.SW_OK
    _put_key_backup(backend, DataObject.DO_SIG_KEY, backup)
    assert get_RSA_pub_key(client, DataObject.DO_SIG_KEY).n == pubkey.n

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    rapdu = client.sign(SHA256_DIGEST_INFO + hash_obj.digest())
    assert rapdu.status == Errors.SW_OK
    pkcs1_15.new(pubkey).verify(hash_obj, rapdu.data)
