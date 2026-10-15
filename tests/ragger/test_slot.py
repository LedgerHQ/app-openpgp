# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Slots feature
"""

import pytest
from application_client.app_def import DataObject, Errors, PassWord
from application_client.command_sender import CommandSender
from ledgered.devices import Device
from ragger.backend import BackendInterface
from utils import check_pincode, generate_key

# Slot selection methods allowed by byte 3 of DO 01F1
SLOT_SELECT_APDU = 0x01


def test_slot(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Check slots availability
    nb_slots, def_slot = client.get_slot_config()
    print("Slots configuration:")
    print(f"  Nb: {nb_slots}")
    print(f"  default: {def_slot}")
    if nb_slots == 1:
        pytest.skip("single slot configuration")

    # Generate the SIG Key Pair
    generate_key(client, DataObject.DO_SIG_KEY)

    # Read slot
    slot = client.get_slot()
    assert slot == 0

    # Read the SIG pub Key
    rapdu = client.read_key(DataObject.DO_SIG_KEY)
    assert rapdu.status == Errors.SW_OK

    # Verify PW2
    check_pincode(client, PassWord.PW2)

    # Change slot
    rapdu = client.set_slot(2)
    assert rapdu.status == Errors.SW_OK

    # Read slot
    slot = client.get_slot()
    assert slot == 2

    # Read an empty pub key
    rapdu = client.read_key(DataObject.DO_SIG_KEY)
    assert rapdu.status == Errors.SW_REFERENCED_DATA_NOT_FOUND


# In this test we check that the home screen follows a slot change requested by APDU
def test_slot_home_screen(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    nb_slots, _ = client.get_slot_config()
    if nb_slots == 1:
        pytest.skip("single slot configuration")

    backend.wait_for_text_on_screen("ID: .* / 1")
    check_pincode(client, PassWord.PW2)
    rapdu = client.set_slot(1)
    assert rapdu.status == Errors.SW_OK
    backend.wait_for_text_on_screen("ID: .* / 2")


def _select_slot_shown(device: Device, backend: BackendInterface) -> bool:
    """Tell whether the home screen offers the slot selection"""
    backend.wait_for_text_on_screen("ID: ")
    if not device.is_nano:
        return backend.compare_screen_with_text("Select Slot")
    # The slot selection is the second page of the Nano home screen
    backend.right_click()
    backend.wait_for_screen_change()
    shown = backend.compare_screen_with_text("Select Slot")
    backend.left_click()
    backend.wait_for_screen_change()
    return shown


# In this test we check that the home screen hides the slot selection when DO 01F1 forbids it
def test_slot_screen_selection_disabled(device: Device, backend: BackendInterface) -> None:
    client = CommandSender(backend)
    nb_slots, _ = client.get_slot_config()
    if nb_slots == 1:
        pytest.skip("single slot configuration")
    config = client.get_data(DataObject.CMD_SLOT_CFG).data
    assert _select_slot_shown(device, backend)

    check_pincode(client, PassWord.PW3)
    rapdu = client.put_data(DataObject.CMD_SLOT_CFG, bytes([config[0], config[1], SLOT_SELECT_APDU]))
    assert rapdu.status == Errors.SW_OK
    assert not _select_slot_shown(device, backend)

    # The selection by APDU stays allowed
    check_pincode(client, PassWord.PW2)
    assert client.set_slot(1).status == Errors.SW_OK
    assert client.set_slot(0).status == Errors.SW_OK

    rapdu = client.put_data(DataObject.CMD_SLOT_CFG, config)
    assert rapdu.status == Errors.SW_OK
    assert _select_slot_shown(device, backend)
