# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Signing feature with SEED mode
"""
import sys
import pytest

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord, PubkeyAlgo

from utils import get_RSA_pub_key, get_ECDSA_pub_key, get_EDDSA_pub_key
from utils import check_pincode, generate_key, get_key_attributes, KEY_TEMPLATES


def _gen_key(client: CommandSender, template: str):

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    # Set SIG key template
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES[template])
    assert rapdu.status == Errors.SW_OK

    # Generate the SIG Key Pair in SEED mode
    generate_key(client, DataObject.DO_SIG_KEY, True)

    key_algo, _ = get_key_attributes(client, DataObject.DO_SIG_ATTR)

     # Read the SIG pub Key
    if key_algo == PubkeyAlgo.RSA:
        return get_RSA_pub_key(client, DataObject.DO_SIG_KEY)
    if key_algo == PubkeyAlgo.ECDSA:
        return get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)
    if key_algo == PubkeyAlgo.EDDSA:
        return get_EDDSA_pub_key(client, DataObject.DO_SIG_KEY)

    raise ValueError


@pytest.mark.parametrize(
    "template",
    [
        "rsa2048",
        pytest.param("rsa3072", marks=pytest.mark.skipif("--full" not in sys.argv, reason="skipping long test")),
        pytest.param("rsa4096", marks=pytest.mark.skipif("--full" not in sys.argv, reason="skipping long test")),
        "nistp256",  # ECDSA
        "ed25519",   # EdDSA
        # "cv25519",   # ECDH, SDK returns CX_EC_INVALID_CURVE
    ],
)
def test_seed_key(backend, template):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Generate the key
    pubkey1 = _gen_key(client, template)

    # Reset the App (delete the key)
    client.send_terminate()
    client.send_activate()

    # Ensure the SIG Key is no more available
    rapdu = client.read_key(DataObject.DO_SIG_KEY)
    assert rapdu.status == Errors.SW_REFERENCED_DATA_NOT_FOUND

    # Generate the key again
    pubkey2 = _gen_key(client, template)

    # Check generated keys
    assert pubkey1 == pubkey2
