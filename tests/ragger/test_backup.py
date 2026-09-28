# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for private key backup and restore
"""

import struct

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, PassWord
from application_client.command_sender import CommandSender
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.utils import RAPDU
from utils import KEY_TEMPLATES, check_pincode, generate_key, get_ECDSA_pub_key

APDU_CHUNK_LEN = 0xFE
P256_COORD_LEN = 32
BACKUP_FORMAT_V2 = 0x02
BACKUP_HEADER_LEN = 1 + 4 + 4
GCM_NONCE_LEN = 12
# Offset of the EC point in the v2 blob: header, nonce, public key length, curve and point length
BACKUP_V2_EC_POINT_OFFSET = BACKUP_HEADER_LEN + GCM_NONCE_LEN + 4 + 4 + 4

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


def _gen_p256_sig_key(client: CommandSender):
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["nistp256"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_SIG_KEY)
    return get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)


# In this test we check that every backup uses its own nonce
def test_backup_nonce_unique(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _gen_p256_sig_key(client)

    backup1 = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)
    backup2 = _get_key_backup(backend, client, DataObject.DO_SIG_KEY)
    assert backup1[0] == BACKUP_FORMAT_V2
    nonce = slice(BACKUP_HEADER_LEN, BACKUP_HEADER_LEN + GCM_NONCE_LEN)
    assert backup1[nonce] != backup2[nonce]
    assert backup1[-P256_COORD_LEN:] != backup2[-P256_COORD_LEN:]

    for backup in (backup1, backup2):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, backup)


# In this test we restore a backup produced in the v1 format
def test_restore_v1_backup(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client)

    tampered = bytearray(BACKUP_V1_P256_SIG)
    tampered[-1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(tampered))

    _put_key_backup(backend, DataObject.DO_SIG_KEY, BACKUP_V1_P256_SIG)
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey

    check_pincode(client, PassWord.PW1)
    hash_obj = SHA256.new(get_random_bytes(16))
    DSS.new(pubkey, "fips-186-3").verify(hash_obj, _sign_raw(client, hash_obj.digest()))


# In this test we restore a backup whose authenticated public key has been modified
def test_restore_tampered_public_key(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pubkey = _gen_p256_sig_key(client)

    backup = bytearray(_get_key_backup(backend, client, DataObject.DO_SIG_KEY))
    backup[BACKUP_V2_EC_POINT_OFFSET + 1] ^= 0x01
    with pytest.raises(ExceptionRAPDU):
        _put_key_backup(backend, DataObject.DO_SIG_KEY, bytes(backup))

    # The stored public key is left untouched
    assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey
