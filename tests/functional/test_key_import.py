# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for private key import (Extended Header list)
"""

import struct

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, PassWord
from application_client.command_sender import CommandSender
from Crypto.PublicKey import RSA
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils import KEY_TEMPLATES, check_pincode, get_RSA_pub_key

TAG_EXTENDED_HEADER = 0x4D
TAG_TEMPLATE = 0x7F48
TAG_KEY_DATA = 0x5F48
TAG_RSA_E = 0x91
TAG_RSA_P = 0x92
TAG_RSA_Q = 0x93

RSA_2048_FACTOR_LEN = 2048 // 8 // 2
RSA_E = (65537).to_bytes(3, "big")
APDU_CHUNK_LEN = 0xFE


def _tag(tag: int) -> bytes:
    return struct.pack(">H", tag) if tag > 0xFF else struct.pack(">B", tag)


def _len(length: int) -> bytes:
    if length < 0x80:
        return struct.pack(">B", length)
    if length <= 0xFF:
        return struct.pack(">BB", 0x81, length)
    return struct.pack(">BH", 0x82, length)


def _tl(tag: int, length: int) -> bytes:
    return _tag(tag) + _len(length)


def _extended_header(template: bytes, key_data_len: int, key_data: bytes) -> bytes:
    content = _tl(DataObject.DO_SIG_KEY, 0)
    content += _tl(TAG_TEMPLATE, len(template)) + template
    content += _tl(TAG_KEY_DATA, key_data_len) + key_data
    return _tl(TAG_EXTENDED_HEADER, len(content)) + content


def _rsa_template(len_p: int, len_q: int) -> bytes:
    return _tl(TAG_RSA_E, len(RSA_E)) + _tl(TAG_RSA_P, len_p) + _tl(TAG_RSA_Q, len_q)


def _put_data_chained(backend: BackendInterface, tag: DataObject, data: bytes) -> None:
    chunks = [data[i : i + APDU_CHUNK_LEN] for i in range(0, len(data), APDU_CHUNK_LEN)]
    for idx, chunk in enumerate(chunks):
        cla = ClaType.CLA_APP if idx == len(chunks) - 1 else ClaType.CLA_APP_CHAIN
        header = struct.pack(">BBBBB", cla, InsType.INS_PUT_DATA, tag >> 8, tag & 0xFF, len(chunk))
        rapdu = backend.exchange_raw(header + chunk)
        assert rapdu.status == Errors.SW_OK


# In this test we import a valid RSA key
def test_import_rsa_key(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])

    key = RSA.generate(2048, e=int.from_bytes(RSA_E, "big"))
    p = key.p.to_bytes(RSA_2048_FACTOR_LEN, "big")
    q = key.q.to_bytes(RSA_2048_FACTOR_LEN, "big")
    template = _rsa_template(len(p), len(q))
    key_data = RSA_E + p + q
    _put_data_chained(backend, DataObject.DO_EXTENDED_HEADER_LIST, _extended_header(template, len(key_data), key_data))

    pubkey = get_RSA_pub_key(client, DataObject.DO_SIG_KEY)
    assert pubkey.n == key.n
    assert pubkey.e == key.e


# In this test we import RSA key data shorter than announced by its TLV lengths
def test_import_truncated_key_data(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])

    template = _rsa_template(RSA_2048_FACTOR_LEN, RSA_2048_FACTOR_LEN)
    factors_len = 2 * RSA_2048_FACTOR_LEN
    partial = RSA_E + bytes(range(16))

    # Key data value longer than the received payload
    data = _extended_header(template, len(RSA_E) + factors_len, partial)
    with pytest.raises(ExceptionRAPDU) as err:
        client.put_data(DataObject.DO_EXTENDED_HEADER_LIST, data)
    assert err.value.status == Errors.SW_WRONG_DATA

    # Component lengths exceeding the key data value
    data = _extended_header(template, len(partial), partial)
    with pytest.raises(ExceptionRAPDU) as err:
        client.put_data(DataObject.DO_EXTENDED_HEADER_LIST, data)
    assert err.value.status == Errors.SW_WRONG_DATA


# In this test we import an Extended Header list cut inside its headers
def test_import_truncated_headers(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])

    template = _rsa_template(RSA_2048_FACTOR_LEN, RSA_2048_FACTOR_LEN)
    data = _extended_header(template, len(RSA_E), RSA_E)
    # Cut in the 4D, CRT and 7F48 headers, then in the 5F48 header
    template_start = len(_tl(TAG_EXTENDED_HEADER, 0)) + len(_tl(DataObject.DO_SIG_KEY, 0))
    key_data_start = template_start + len(_tl(TAG_TEMPLATE, len(template))) + len(template)
    cuts = [*range(1, template_start + 3), key_data_start + 1, key_data_start + 2]
    for cut in cuts:
        with pytest.raises(ExceptionRAPDU) as err:
            client.put_data(DataObject.DO_EXTENDED_HEADER_LIST, data[:cut])
        assert err.value.status == Errors.SW_WRONG_LENGTH

    # The application is still running
    check_pincode(client, PassWord.PW3)
