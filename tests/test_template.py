# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Key Templates feature
"""
import sys
import pytest
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord, PubkeyAlgo

from utils import get_RSA_pub_key, get_ECDSA_pub_key, get_EDDSA_pub_key
from utils import check_pincode, generate_key, get_key_attributes
from utils import KEY_TEMPLATES, SHA256_DIGEST_INFO


@pytest.mark.parametrize(
    "template",
    [
        "rsa2048",
        pytest.param("rsa3072", marks=pytest.mark.skipif("--full" not in sys.argv, reason="skipping long test")),
        # "rsa4096",   # Invalid signature?
        # "nistp256",  # ECDSA, Pb with Pubkey generation?
        "ed25519",   # EdDSA
        # "cv25519",   # ECDH, SDK returns CX_EC_INVALID_CURVE
    ],
)
def test_sign(backend, template):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    # Set SIG key template
    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES[template])
    assert rapdu.status == Errors.SW_OK

    # Generate the SIG Key Pair
    generate_key(client, DataObject.DO_SIG_KEY)

    key_algo, _ = get_key_attributes(client, DataObject.DO_SIG_ATTR)

    # Hash data buffer
    plain = get_random_bytes(16)
    hash_obj = SHA256.new(plain)

    # Sign data buffer
    if key_algo == PubkeyAlgo.RSA:
        digest_info = SHA256_DIGEST_INFO
        data = digest_info + hash_obj.digest()
    elif key_algo == PubkeyAlgo.ECDSA:
        data = hash_obj.digest()
    else:
        data = plain

    # Verify PW1 (User)
    check_pincode(client, PassWord.PW1)

    rapdu = client.sign(data)
    assert rapdu.status == Errors.SW_OK

    # Read the SIG pub Key and Verify the signature
    if key_algo == PubkeyAlgo.RSA:
        pubkey = get_RSA_pub_key(client, DataObject.DO_SIG_KEY)
        verifier = pkcs1_15.new(pubkey)
        verifier.verify(hash_obj, rapdu.data)
    elif key_algo == PubkeyAlgo.ECDSA:
        pubkey = get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)
        verifier = DSS.new(pubkey, 'fips-186-3')
        verifier.verify(hash_obj, rapdu.data[2:])
    elif key_algo == PubkeyAlgo.EDDSA:
        pubkey = get_EDDSA_pub_key(client, DataObject.DO_SIG_KEY)
        verifier = eddsa.new(pubkey, 'rfc8032')
        verifier.verify(plain, rapdu.data)
    else:
        raise ValueError
