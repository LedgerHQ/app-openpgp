# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Password feature
"""

import struct
from pathlib import Path

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, PassWord
from application_client.command_sender import CommandSender
from ledgered.devices import Device, DeviceType
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID
from utils import check_pincode, util_navigate


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
    assert err.value.status & 0xFFF0 == 0x63C0

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
    assert err.value.status & 0xFFF0 == 0x63C0


def test_verify_wrong(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW status - Wrong Password
    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(PassWord.PW1, "999999")
    assert err.value.status == Errors.SW_SECURITY_STATUS_NOT_SATISFIED


# In this test we check the card Password verification with Pinpad
def test_verify_confirm_accepted(device: Device, backend: BackendInterface, navigator: Navigator, test_name: Path) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU (Asynchronous)
    with client.send_verify_pw_with_confirmation(PassWord.PW1):
        util_navigate(device, navigator, test_name, "Confirm_Yes")

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_OK


# In this test we check the Rejected card Password verification with Pinpad
def test_verify_confirm_refused(device: Device, backend: BackendInterface, navigator: Navigator, test_name: Path) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU (Asynchronous)
    with pytest.raises(ExceptionRAPDU) as err:
        with client.send_verify_pw_with_confirmation(PassWord.PW1):
            util_navigate(device, navigator, test_name, "Confirm_No")

    # Assert we have received a refusal
    assert err.value.status == Errors.SW_CONDITIONS_NOT_SATISFIED
    assert len(err.value.data) == 0


# In this test we check the Password Update
@pytest.mark.parametrize(
    "pwd, actual, new",
    [
        (PassWord.PW1, "123456", "654321"),
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


# In this test we check that a card reset clears the verified PINs
def test_reset_clears_verified_pins(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    pins = (PassWord.PW1, PassWord.PW2, PassWord.PW3)
    for pwd in pins:
        check_pincode(client, pwd)

    rapdu = client.send_terminate()
    assert rapdu.status == Errors.SW_OK
    rapdu = client.send_activate()
    assert rapdu.status == Errors.SW_OK

    for pwd in pins:
        with pytest.raises(ExceptionRAPDU) as err:
            client.send_verify_pw(pwd)
        assert (err.value.status & 0xFFF0) == Errors.SW_VERIFY_FAILED


# In this test we check that resetting PW1 revokes the sessions opened with the previous value
def test_reset_revokes_pw1_sessions(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    for pwd in (PassWord.PW1, PassWord.PW2, PassWord.PW3):
        check_pincode(client, pwd)

    rapdu = client.send_reset_pw("654321")
    assert rapdu.status == Errors.SW_OK

    for pwd in (PassWord.PW1, PassWord.PW2):
        with pytest.raises(ExceptionRAPDU) as err:
            client.send_verify_pw(pwd)
        assert (err.value.status & 0xFFF0) == Errors.SW_VERIFY_FAILED
    rapdu = client.send_verify_pw(PassWord.PW3)
    assert rapdu.status == Errors.SW_OK


# In this test we check that changing PW1 revokes the PW2 session opened with the previous value
def test_change_revokes_pw2_session(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW2)

    rapdu = client.send_change_pw(PassWord.PW1, "123456", "654321")
    assert rapdu.status == Errors.SW_OK

    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(PassWord.PW2)
    assert (err.value.status & 0xFFF0) == Errors.SW_VERIFY_FAILED


# In this test we unblock PW1 with the Resetting Code
def test_reset_with_resetting_code(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    resetting_code, new_pin = b"87654321", b"654321"
    reset_with_code = 0x00

    check_pincode(client, PassWord.PW3)
    rapdu = client.put_data(DataObject.DO_RESET_CODE, resetting_code)
    assert rapdu.status == Errors.SW_OK
    rapdu = client.send_verify_pw(PassWord.PW3, reset=True)
    assert rapdu.status == Errors.SW_OK

    # Block PW1
    for _ in range(3):
        with pytest.raises(ExceptionRAPDU):
            client.send_verify_pw(PassWord.PW1, "000000")
    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(PassWord.PW1, "123456")
    assert err.value.status == Errors.SW_AUTH_METHOD_BLOCKED

    # A wrong Resetting Code is refused
    with pytest.raises(ExceptionRAPDU):
        backend.exchange(
            cla=ClaType.CLA_APP,
            ins=InsType.INS_RESET_RC,
            p1=reset_with_code,
            p2=PassWord.PW1,
            data=b"00000000" + new_pin,
        )

    rapdu = backend.exchange(
        cla=ClaType.CLA_APP,
        ins=InsType.INS_RESET_RC,
        p1=reset_with_code,
        p2=PassWord.PW1,
        data=resetting_code + new_pin,
    )
    assert rapdu.status == Errors.SW_OK
    rapdu = client.send_verify_pw(PassWord.PW1, new_pin.decode())
    assert rapdu.status == Errors.SW_OK


# Row of the "Trust" choice in the PIN mode settings of touch devices
TRUST_CHOICE = {DeviceType.FLEX: (430, 326), DeviceType.STAX: (350, 327), DeviceType.APEX_P: (270, 230)}
PIN_MODE_SETTING = {DeviceType.FLEX: (430, 325), DeviceType.STAX: (350, 320), DeviceType.APEX_P: (270, 235)}


# In this test we check that a pinpad VERIFY is answered in TRUST mode
def test_verify_trust_mode(device: Device, backend: BackendInterface, navigator: Navigator) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    # Settings / PIN mode / Trust / confirm
    if device.is_nano:
        navigator.navigate(
            [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
            screen_change_before_first_instruction=False,
        )
        navigator.navigate_until_text(
            NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Pin mode", screen_change_before_first_instruction=False
        )
        navigator.navigate_until_text(
            NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Trust", screen_change_before_first_instruction=False
        )
        navigator.navigate_until_text(
            NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Yes", screen_change_before_first_instruction=False
        )
    else:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, PIN_MODE_SETTING[device.type]),
                NavIns(NavInsID.TOUCH, TRUST_CHOICE[device.type]),
                NavInsID.USE_CASE_CHOICE_CONFIRM,
            ],
            screen_change_before_first_instruction=False,
        )
    backend.wait_for_text_on_screen("TRUST MODE")

    rapdu = backend.exchange(cla=ClaType.CLA_APP_VERIFY, ins=InsType.INS_VERIFY, p2=PassWord.PW1)
    assert rapdu.status == Errors.SW_OK
    rapdu = client.send_verify_pw(PassWord.PW1)
    assert rapdu.status == Errors.SW_OK


# Centers of the keypad columns and rows (digits 1 to 9, then back, 0 and validate) on touch devices
KEYPAD = {
    DeviceType.FLEX: ((80, 240, 398), (288, 376, 464, 552)),
    DeviceType.STAX: ((68, 198, 330), (300, 404, 508, 612)),
    DeviceType.APEX_P: ((52, 150, 250), (188, 248, 308, 368)),
}


def _enter_pin(device: Device, navigator: Navigator, pin: str) -> None:
    if device.is_nano:
        # The selection starts on 5 after each digit, and moves to Validate once the PIN is long enough
        for digit in map(int, pin):
            move = NavInsID.RIGHT_CLICK if digit > 5 else NavInsID.LEFT_CLICK
            digit_instructions = [move] * abs(digit - 5) + [NavInsID.BOTH_CLICK]
            navigator.navigate(digit_instructions, screen_change_before_first_instruction=False)
        navigator.navigate([NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)
    else:
        cols, rows = KEYPAD[device.type]
        instructions: list[NavIns | NavInsID] = []
        for digit in map(int, pin):
            position = (cols[1], rows[3]) if digit == 0 else (cols[(digit - 1) % 3], rows[(digit - 1) // 3])
            instructions.append(NavIns(NavInsID.TOUCH, position))
        instructions.append(NavIns(NavInsID.TOUCH, (cols[2], rows[3])))
        navigator.navigate(instructions, screen_change_before_first_instruction=False)


# In this test we check that cancelling an on-device PIN change leaves the PIN not verified
def test_change_pin_cancelled(device: Device, backend: BackendInterface, navigator: Navigator) -> None:
    client = CommandSender(backend)
    header = struct.pack(">BBBB", ClaType.CLA_APP, InsType.INS_CHANGE_REF_DATA, 0, PassWord.PW1)

    with pytest.raises(ExceptionRAPDU) as err:
        with backend.exchange_async_raw(header):
            backend.wait_for_text_on_screen("Current User PIN")
            _enter_pin(device, navigator, "123456")
            backend.wait_for_text_on_screen("New User PIN")
            if device.is_nano:
                # Backspace, on the left of 0, goes back when no digit is entered
                navigator.navigate(
                    [NavInsID.LEFT_CLICK] * 6 + [NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False
                )
            else:
                navigator.navigate([NavInsID.NAVIGATION_HEADER_TAP], screen_change_before_first_instruction=False)
    assert err.value.status == Errors.SW_CONDITIONS_NOT_SATISFIED

    with pytest.raises(ExceptionRAPDU) as err:
        client.send_verify_pw(PassWord.PW1)
    assert (err.value.status & 0xFFF0) == Errors.SW_VERIFY_FAILED
