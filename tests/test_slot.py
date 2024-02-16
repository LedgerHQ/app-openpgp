# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Slots feature
"""
import pytest

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord

from utils import check_pincode, generate_key

def test_slot(backend):
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
