# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for APDU framing
"""

import struct

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, PassWord
from application_client.command_sender import CommandSender
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils import KEY_TEMPLATES, check_pincode, generate_key


def _header(cla: int, ins: int, p1: int, p2: int, lc: int) -> bytes:
    return struct.pack(">BBBBB", cla, ins, p1, p2, lc)


# In this test we send APDUs announcing more data than transmitted
def test_truncated_apdu(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    login = b"John.Doe"
    announced = len(login) + 4
    p1, p2 = DataObject.DO_LOGIN >> 8, DataObject.DO_LOGIN & 0xFF
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(_header(ClaType.CLA_APP, InsType.INS_PUT_DATA, p1, p2, announced) + login)
    assert err.value.status == Errors.SW_WRONG_LENGTH

    pin = b"123"
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(_header(ClaType.CLA_APP, InsType.INS_VERIFY, 0, PassWord.PW1, 6) + pin)
    assert err.value.status == Errors.SW_WRONG_LENGTH

    # Well-formed APDUs are still processed
    rapdu = client.put_data(DataObject.DO_LOGIN, login)
    assert rapdu.status == Errors.SW_OK
    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == login


# In this test we send an APDU made of its header only, without Lc
def test_header_only_apdu(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    rapdu = client.put_data(DataObject.DO_LOGIN, b"John.Doe")
    assert rapdu.status == Errors.SW_OK

    p1, p2 = DataObject.DO_LOGIN >> 8, DataObject.DO_LOGIN & 0xFF
    rapdu = backend.exchange_raw(struct.pack(">BBBB", ClaType.CLA_APP, InsType.INS_PUT_DATA, p1, p2))
    assert rapdu.status == Errors.SW_OK
    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == b""


# In this test we send a chained APDU whose continuation is truncated
def test_truncated_chained_apdu(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    p1, p2 = DataObject.DO_LOGIN >> 8, DataObject.DO_LOGIN & 0xFF
    first = b"John."
    rapdu = backend.exchange_raw(_header(ClaType.CLA_APP_CHAIN, InsType.INS_PUT_DATA, p1, p2, len(first)) + first)
    assert rapdu.status == Errors.SW_OK

    last = b"Doe"
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(_header(ClaType.CLA_APP, InsType.INS_PUT_DATA, p1, p2, len(last) + 2) + last)
    assert err.value.status == Errors.SW_WRONG_LENGTH

    # The aborted chain is not resumed
    rapdu = client.put_data(DataObject.DO_LOGIN, first + last)
    assert rapdu.status == Errors.SW_OK
    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == first + last


# In this test we send a chained APDU whose continuation does not match the first part
def test_mismatched_chained_apdu(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    login = b"John.Doe"
    rapdu = client.put_data(DataObject.DO_LOGIN, login)
    assert rapdu.status == Errors.SW_OK

    p1, p2 = DataObject.DO_LOGIN >> 8, DataObject.DO_LOGIN & 0xFF
    first = b"Jane."
    rapdu = backend.exchange_raw(_header(ClaType.CLA_APP_CHAIN, InsType.INS_PUT_DATA, p1, p2, len(first)) + first)
    assert rapdu.status == Errors.SW_OK

    url_p1, url_p2 = DataObject.DO_URL >> 8, DataObject.DO_URL & 0xFF
    last = b"Doe"
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(_header(ClaType.CLA_APP, InsType.INS_PUT_DATA, url_p1, url_p2, len(last)) + last)
    assert err.value.status == Errors.SW_LAST_COMMAND_EXPECTED

    # The partial command is not executed
    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == login


# In this test we send frames too short to hold an APDU header
def test_short_frame(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    login = b"John.Doe"
    rapdu = client.put_data(DataObject.DO_LOGIN, login)
    assert rapdu.status == Errors.SW_OK

    header = _header(ClaType.CLA_APP, InsType.INS_GET_DATA, 0, DataObject.DO_LOGIN, 0)
    for length in range(1, 4):
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(header[:length])
        assert err.value.status == Errors.SW_WRONG_LENGTH

    # The previous command is not replayed
    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == login


# In this test we send a new command instead of GET RESPONSE during a long response
def test_long_response_aborted(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])
    generate_key(client, DataObject.DO_SIG_KEY)

    login = b"John.Doe"
    rapdu = client.put_data(DataObject.DO_LOGIN, login)
    assert rapdu.status == Errors.SW_OK

    read_pubkey = 0x81
    crt = struct.pack(">BB", DataObject.DO_SIG_KEY, 0)
    header = _header(ClaType.CLA_APP, InsType.INS_GEN_ASYM_KEYPAIR, read_pubkey, 0, len(crt))
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(header + crt)
    assert (err.value.status & 0xFF00) == Errors.SW_CORRECT_LONG_RESPONSE

    rapdu = client.get_data(DataObject.DO_LOGIN)
    assert rapdu.data == login
