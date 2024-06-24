# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Password feature
"""
from pathlib import Path
import pytest
from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, PassWord


from utils import util_navigate


# In this test we check the card Password verification
@pytest.mark.parametrize(
    "pwd, value",
    [
        (PassWord.PW1, "123456"),
        (PassWord.PW2, "123456"),
        (PassWord.PW3, "12345678"),
    ],
)
def test_verify(backend: BackendInterface, pwd: PassWord, value: str) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW status - Not yet verified
    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(pwd)
    assert err.value.status & 0xFFF0 == 0x63c0

    # Verify PW with its value
    rapdu = client.send_verify_pw(pwd, value)
    assert rapdu.status == Errors.SW_OK

    # Verify PW status
    rapdu = client.send_verify_pw(pwd)
    assert rapdu.status == Errors.SW_OK

    # Verify PW Reset Status
    rapdu = client.send_verify_pw(pwd, reset=True)
    assert rapdu.status == Errors.SW_OK

    # Verify PW status - Not yet verified
    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(pwd)
    assert err.value.status & 0xFFF0 == 0x63c0


def test_verify_wrong(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW status - Wrong Password
    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(PassWord.PW1, "999999")
    assert err.value.status == Errors.SW_SECURITY_STATUS_NOT_SATISFIED


# In this test we check the card Password verification with Pinpad
def test_verify_confirm_accepted(firmware: Firmware,
                                 backend: BackendInterface,
                                 navigator: Navigator,
                                 test_name: Path) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU (Asynchronous)
    with client.send_verify_pw_with_confirmation(PassWord.PW1):
        util_navigate(firmware, navigator, test_name, "Confirm_Yes")

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_OK


# In this test we check the Rejected card Password verification with Pinpad
def test_verify_confirm_refused(firmware: Firmware,
                                backend: BackendInterface,
                                navigator: Navigator,
                                test_name: Path) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU (Asynchronous)
    with pytest.raises(ExceptionRAPDU) as err:
        with client.send_verify_pw_with_confirmation(PassWord.PW1):
            util_navigate(firmware, navigator, test_name, "Confirm_No")

    # Assert we have received a refusal
    assert err.value.status == Errors.SW_CONDITIONS_NOT_SATISFIED
    assert len(err.value.data) == 0


# In this test we check the Password Update
@pytest.mark.parametrize(
    "pwd, actual, new",
    [
        (PassWord.PW1, "123456",   "654321"),
        (PassWord.PW3, "12345678", "87654321"),
    ],
)
def test_change(backend: BackendInterface, pwd: PassWord, actual: str, new: str) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW with its value
    rapdu = client.send_verify_pw(pwd, actual)
    assert rapdu.status == Errors.SW_OK

    # Change PW value
    rapdu = client.send_change_pw(pwd, actual, new)
    assert rapdu.status == Errors.SW_OK

    # Verify PW status
    rapdu = client.send_verify_pw(pwd, new)
    assert rapdu.status == Errors.SW_OK


# In this test we check the Password Reset
def test_reset(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW1
    rapdu = client.send_verify_pw(PassWord.PW1, "123456")
    assert rapdu.status == Errors.SW_OK

    # Verify PW3 (Admin)
    rapdu = client.send_verify_pw(PassWord.PW3, "12345678")
    assert rapdu.status == Errors.SW_OK

    # Reset PW1 with a new value
    rapdu = client.send_reset_pw("654321")
    assert rapdu.status == Errors.SW_OK

    # Verify PW status
    rapdu = client.send_verify_pw(PassWord.PW1, "654321")
    assert rapdu.status == Errors.SW_OK


# In this test we check the Get Challenge
def test_challenge(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Get Random number
    rapdu = client.get_challenge(32)
    assert rapdu.status == Errors.SW_OK
    print(f"Random: {rapdu.data.hex()}")
