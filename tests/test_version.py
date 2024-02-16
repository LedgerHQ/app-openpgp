# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Version check
"""
from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord
from application_client.response_unpacker import unpack_info_response

from ragger.utils.misc import get_current_app_name_and_version

from utils import verify_name, verify_version, decode_tlv, check_pincode


# In this test we check the App name and version
def test_check_version(backend):
    """Check version and name"""

    # Send the APDU
    app_name, version = get_current_app_name_and_version(backend)
    print(f" Name: {app_name}")
    print(f" Version: {version}")
    verify_name(app_name)
    verify_version(version)


# In this test we check the Card activation
def test_activate(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Activate the Card
    rapdu = client.send_activate()
    assert rapdu.status == Errors.SW_OK


# In this test we get the Card Application ID value
def test_info(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Get info from the Card
    rapdu = client.get_data(DataObject.DO_AID)
    assert rapdu.status == Errors.SW_OK
    aid = rapdu.data.hex()
    print(f" AID:     {aid}")
    assert aid[:12] == "d27600012401"

    # Parse the response
    version, serial = unpack_info_response(rapdu.data)
    print(f" Version: {int(version[0:2]):d}.{int(version[2:4]):d}")
    print(f" Serial:  {serial}")

    # Check expected value
    assert version == "0303"


# In this test we test the User Data information
def test_user(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    # Write and Read the 'Login'
    _check_user_value(client, DataObject.DO_LOGIN, "John.Doe")

    # Write and Read the 'URL'
    _check_user_value(client, DataObject.DO_URL, "This is John Doe URL")

    # Write and Read the 'name'
    _check_card_value(client, DataObject.DO_CARD_NAME, "John Doe")

    # Write and Read the 'Lang'
    _check_card_value(client, DataObject.DO_CARD_LANG, "fr")

    # Write and Read the 'Salutation'
    _check_card_value(client, DataObject.DO_CARD_SALUTATION, "1")

    # Write and Read the 'Serial number'
    serial = "12345678"
    rapdu = client.put_data(DataObject.DO_AID, bytes.fromhex(serial))
    assert rapdu.status == Errors.SW_OK

    rapdu = client.get_data(DataObject.DO_AID)
    assert rapdu.status == Errors.SW_OK
    assert rapdu.data.hex()[20:28] == serial


def _check_card_value(client, tag: DataObject, value: str):

    rapdu = client.put_data(tag, value.encode("utf-8"))
    assert rapdu.status == Errors.SW_OK

    rapdu = client.get_data(DataObject.DO_CARDHOLDER_DATA)
    assert rapdu.status == Errors.SW_OK
    tags = decode_tlv(rapdu.data)
    rvalue = tags.get(tag, b"").decode("utf-8")
    assert rvalue == value


def _check_user_value(client, tag: DataObject, value: str):

    rapdu = client.put_data(tag, value.encode("utf-8"))
    assert rapdu.status == Errors.SW_OK

    rapdu = client.get_data(tag)
    assert rapdu.status == Errors.SW_OK
    assert rapdu.data.decode("utf-8") == value
