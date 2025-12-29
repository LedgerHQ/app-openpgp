# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Cipher feature
"""
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

from ragger.backend import BackendInterface

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, DataObject, PassWord, PubkeyAlgo

from utils import check_pincode, generate_key, get_RSA_pub_key
from utils import get_ECDH_pub_key, KEY_TEMPLATES


# In this test we check the symmetric key encryption
def test_AES(backend: BackendInterface) -> None:
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
def test_Asym(backend: BackendInterface) -> None:
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
def test_MSE(backend: BackendInterface) -> None:
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


def test_cv25519(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    # Set dec key template
    rapdu = client.set_template(DataObject.DO_DEC_ATTR, KEY_TEMPLATES["cv25519"])
    assert rapdu.status == Errors.SW_OK

    # Generate the DEC Key Pair
    generate_key(client, DataObject.DO_DEC_KEY)

    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Read the DEC pub Key
    pubkey = get_ECDH_pub_key(client, DataObject.DO_DEC_KEY)

    # Generate Keypair
    privkey = ECC.generate(curve="Curve25519")
    expected_secret = key_agreement(static_priv=privkey, static_pub=pubkey, kdf=lambda x:x)

    # Compute ecdh
    pubkey2 = privkey.public_key()
    exp_pubkey = pubkey2.export_key(format="raw", compress="True")
    payload_len = len(exp_pubkey)
    hdr1 = payload_len.to_bytes(1, byteorder='big')
    hdr2 = bytes.fromhex("86") + hdr1 # tag_PubKey_ext
    payload_len += 2
    hdr3 = bytes.fromhex("7f49") + payload_len.to_bytes(1, byteorder='big') + hdr2  # tag_PubKey_D0
    payload_len += 3
    hdr = payload_len.to_bytes(1, byteorder='big') + hdr3
    secret = client.decrypt_asym(hdr + exp_pubkey, PubkeyAlgo.ECDH).data

    assert secret == expected_secret
