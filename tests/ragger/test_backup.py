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
