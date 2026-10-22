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
from ragger.utils import RAPDU
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


# In this test we send the largest short APDU: 255 bytes of data followed by Le
def test_largest_apdu(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    login = bytes(range(0xFF))
    le = 0x00
    p1, p2 = DataObject.DO_LOGIN >> 8, DataObject.DO_LOGIN & 0xFF
    header = _header(ClaType.CLA_APP, InsType.INS_PUT_DATA, p1, p2, len(login))
    rapdu = backend.exchange_raw(header + login + struct.pack(">B", le))
    assert rapdu.status == Errors.SW_OK

    # The response does not fit in one APDU
    with pytest.raises(ExceptionRAPDU) as err:
        client.get_data(DataObject.DO_LOGIN)
    rapdu = client.get_long_response(RAPDU(err.value.status, err.value.data))
    assert rapdu.status == Errors.SW_OK
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


# In this test we read a public key with malformed Control Reference Templates
def test_gen_key_malformed_crt(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    read_pubkey = 0x81

    for crt, status in (
        (struct.pack(">H", DataObject.DO_PUB_KEY), Errors.SW_WRONG_DATA),
        (struct.pack(">B", DataObject.DO_SIG_KEY), Errors.SW_WRONG_LENGTH),
        (struct.pack(">BBB", DataObject.DO_SIG_KEY, 0, 0), Errors.SW_WRONG_LENGTH),
    ):
        header = _header(ClaType.CLA_APP, InsType.INS_GEN_ASYM_KEYPAIR, read_pubkey, 0, len(crt))
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(header + crt)
        assert err.value.status == status

    # A long form length byte is not parsed
    crt = struct.pack(">BB", DataObject.DO_SIG_KEY, 0x81)
    header = _header(ClaType.CLA_APP, InsType.INS_GEN_ASYM_KEYPAIR, read_pubkey, 0, len(crt))
    try:
        backend.exchange_raw(header + crt)
    except ExceptionRAPDU:
        pass

    # The app is still running
    rapdu = client.get_data(DataObject.DO_AID)
    assert rapdu.status == Errors.SW_OK


# In this test we write the PW status bytes without any data
def test_empty_pw_status(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    p1, p2 = DataObject.DO_PW_STATUS >> 8, DataObject.DO_PW_STATUS & 0xFF
    with pytest.raises(ExceptionRAPDU) as err:
        backend.exchange_raw(struct.pack(">BBBB", ClaType.CLA_APP, InsType.INS_PUT_DATA, p1, p2))
    assert err.value.status == Errors.SW_WRONG_LENGTH

    pw1_multiple_use = 0x01
    rapdu = client.put_data(DataObject.DO_PW_STATUS, struct.pack(">B", pw1_multiple_use))
    assert rapdu.status == Errors.SW_OK
    assert client.get_data(DataObject.DO_PW_STATUS).data[0] == pw1_multiple_use


def _put_data_chained(backend: BackendInterface, tag: DataObject, data: bytes) -> RAPDU:
    chunk_len = 0xFE
    chunks = [data[i : i + chunk_len] for i in range(0, len(data), chunk_len)]
    for idx, chunk in enumerate(chunks):
        cla = ClaType.CLA_APP if idx == len(chunks) - 1 else ClaType.CLA_APP_CHAIN
        rapdu = backend.exchange_raw(_header(cla, InsType.INS_PUT_DATA, tag >> 8, tag & 0xFF, len(chunk)) + chunk)
    return rapdu


# In this test we write cardholder certificates up to the size that can be read back
def test_cardholder_certificate_size(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    tag = DataObject.DO_CARDHOLDER_CERT
    max_cert_len = 1512 - 2

    with pytest.raises(ExceptionRAPDU) as err:
        _put_data_chained(backend, tag, bytes(max_cert_len + 1))
    assert err.value.status == Errors.SW_WRONG_LENGTH

    cert = bytes(i & 0xFF for i in range(max_cert_len))
    rapdu = _put_data_chained(backend, tag, cert)
    assert rapdu.status == Errors.SW_OK

    try:
        rapdu = backend.exchange_raw(_header(ClaType.CLA_APP, InsType.INS_GET_DATA, tag >> 8, tag & 0xFF, 0))
    except ExceptionRAPDU as err:
        rapdu = RAPDU(err.status, err.data)
    rapdu = client.get_long_response(rapdu)
    assert rapdu.status == Errors.SW_OK
    assert rapdu.data == cert


def _select_certificate(backend: BackendInterface, occurrence: int) -> None:
    # SELECT DATA of the cardholder certificate, occurrence in P1
    ins_select_data, skip_template = 0xA5, 0x04
    tag = DataObject.DO_CARDHOLDER_CERT
    data = struct.pack(">BBBBH", 0x60, 0x04, 0x5C, 0x02, tag)
    header = _header(ClaType.CLA_APP, ins_select_data, occurrence, skip_template, len(data))
    assert backend.exchange_raw(header + data).status == Errors.SW_OK


def _get_certificate(backend: BackendInterface, get_next: bool = False) -> bytes:
    ins = 0xCC if get_next else InsType.INS_GET_DATA
    tag = DataObject.DO_CARDHOLDER_CERT
    return backend.exchange_raw(_header(ClaType.CLA_APP, ins, tag >> 8, tag & 0xFF, 0)).data


# In this test we write and read the cardholder certificate of each key
def test_cardholder_certificate_occurrences(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    # Occurrences in the order of the OpenPGP card specification
    certs = {"AUT": b"\x30\x82\xff\xfeAUT", "DEC": b"\x30\x82\xff\xfdDEC", "SIG": b"\x30\x82\xff\xfcSIG"}

    for occurrence, cert in enumerate(certs.values()):
        _select_certificate(backend, occurrence)
        rapdu = client.put_data(DataObject.DO_CARDHOLDER_CERT, cert)
        assert rapdu.status == Errors.SW_OK

    for occurrence, cert in enumerate(certs.values()):
        _select_certificate(backend, occurrence)
        assert _get_certificate(backend) == cert

    _select_certificate(backend, 0)
    assert _get_certificate(backend) == certs["AUT"]
    assert _get_certificate(backend, get_next=True) == certs["DEC"]
    assert _get_certificate(backend, get_next=True) == certs["SIG"]
    with pytest.raises(ExceptionRAPDU):
        _get_certificate(backend, get_next=True)


# In this test we send malformed SELECT DATA commands
def test_select_data_malformed(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    ins_select_data, skip_template = 0xA5, 0x04
    tag = DataObject.DO_CARDHOLDER_CERT
    for data in (
        b"",
        b"\x60",
        struct.pack(">BBB", 0x60, 0x04, 0x5C),
        struct.pack(">BBBBH", 0x60, 0x05, 0x5C, 0x02, tag),
        struct.pack(">BBBBH", 0x61, 0x04, 0x5C, 0x02, tag),
        struct.pack(">BBBBHB", 0x60, 0x05, 0x5C, 0x03, tag, 0),
    ):
        header = struct.pack(">BBBB", ClaType.CLA_APP, ins_select_data, 0, skip_template)
        apdu = header + struct.pack(">B", len(data)) + data if data else header
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(apdu)
        assert err.value.status == Errors.SW_WRONG_DATA
        # The application is still running
        assert client.get_data(DataObject.DO_AID).status == Errors.SW_OK
