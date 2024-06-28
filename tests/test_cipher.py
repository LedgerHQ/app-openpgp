# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Cipher feature
"""
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord

from utils import check_pincode, generate_key, get_RSA_pub_key


# In this test we check the symmetric key encryption
def test_AES(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    key = get_random_bytes(32)
    # Store the AES Key
    rapdu = client.put_data(DataObject.DO_KEY_AES, key)
    assert rapdu.status == Errors.SW_OK

    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Encrypt the data
    plain = get_random_bytes(16)
    rapdu = client.encrypt(plain)
    assert rapdu.status == Errors.SW_OK

    # Decrypt the data
    rapdu = client.decrypt(rapdu.data)
    assert rapdu.status == Errors.SW_OK

    assert rapdu.data == plain


# In this test we check the symmetric key encryption
def test_Asym(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Generate the DEC Key Pair
    generate_key(client, DataObject.DO_DEC_KEY)

    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Read the DEC pub Key
    pubkey = get_RSA_pub_key(client, DataObject.DO_DEC_KEY)

    # Encrypt random bytes with Pub Key
    plain = get_random_bytes(32)
    cipher = PKCS1_v1_5.new(pubkey)
    ciphertext = cipher.encrypt(plain)

    # Decrypt the data with the Private key
    rapdu = client.decrypt_asym(ciphertext)
    assert rapdu.status == Errors.SW_OK

    assert rapdu.data == plain


# In this test we check the symmetric key encryption with MSE
def test_MSE(backend):
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Generate the AUT Key Pair
    generate_key(client, DataObject.DO_AUT_KEY)

    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Read the AUT pub Key
    pubkey = get_RSA_pub_key(client, DataObject.DO_AUT_KEY)

    # Encrypt random bytes with Pub Key
    plain = get_random_bytes(32)
    cipher = PKCS1_v1_5.new(pubkey)
    ciphertext = cipher.encrypt(plain)

    # Change default DEC key by AUT
    rapdu = client.manage_security_env(DataObject.DO_DEC_KEY, 3)
    assert rapdu.status == Errors.SW_OK

    # Decrypt the data with the Private key
    rapdu = client.decrypt_asym(ciphertext)
    assert rapdu.status == Errors.SW_OK

    assert rapdu.data == plain
