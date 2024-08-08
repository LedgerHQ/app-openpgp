# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Signing feature
"""
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

from ragger.backend import BackendInterface

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord, PubkeyAlgo

from utils import check_pincode, get_key_attributes, get_RSA_pub_key, generate_key, SHA256_DIGEST_INFO


# In this test we check the key pair generation
def test_sign(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Generate the SIG Key Pair
    generate_key(client, DataObject.DO_SIG_KEY)

    # SIG Key attributes
    key_algo, key_size = get_key_attributes(client, DataObject.DO_SIG_ATTR)
    # Check default config values
    assert key_algo == PubkeyAlgo.RSA
    assert key_size == 2048

    # Verify PW1 (User)
    check_pincode(client, PassWord.PW1)

    # Hash data buffer
    hash_obj = SHA256.new(get_random_bytes(16))

    rapdu = client.sign(SHA256_DIGEST_INFO + hash_obj.digest())
    assert rapdu.status == Errors.SW_OK

    # Verify the signature
    _verify_signature(client, hash_obj, DataObject.DO_SIG_KEY, rapdu.data)


# In this test we check the key pair generation
def test_auth(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Generate the AUT Key Pair
    generate_key(client, DataObject.DO_AUT_KEY)

    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Hash data buffer
    hash_obj = SHA256.new(get_random_bytes(16))

    rapdu = client.authenticate(SHA256_DIGEST_INFO + hash_obj.digest())
    assert rapdu.status == Errors.SW_OK

    # Verify the signature
    _verify_signature(client, hash_obj, DataObject.DO_AUT_KEY, rapdu.data)


def _verify_signature(client: CommandSender,
                      hash_obj: SHA256.SHA256Hash,
                      key_tag: DataObject,
                      signature: bytes) -> None:
    # Read the SIG pub Key
    pubkey: RsaKey = get_RSA_pub_key(client, key_tag)
    # Verify the signature
    verifier = pkcs1_15.new(pubkey)
    verifier.verify(hash_obj, signature)
