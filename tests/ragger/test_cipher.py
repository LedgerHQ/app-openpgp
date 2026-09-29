# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Cipher feature
"""

import struct
from pathlib import Path

import pytest
from application_client.app_def import ClaType, DataObject, Errors, InsType, PassWord, PubkeyAlgo
from application_client.command_sender import CommandSender
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from utils import (
    KEY_TEMPLATES,
    check_pincode,
    generate_key,
    get_ECDH_pub_key,
    get_RSA_pub_key,
    util_navigate,
)


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


# In this test we check the one-shot secure messaging keys import
def test_SM_keys(backend: BackendInterface) -> None:
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    aes128_len = 16
    for wrong_len in (aes128_len, 2 * aes128_len - 1, 2 * aes128_len + 1):
        with pytest.raises(ExceptionRAPDU) as err:
            client.put_data(DataObject.DO_KEY_SM, get_random_bytes(wrong_len))
        assert err.value.status == Errors.SW_WRONG_LENGTH

    rapdu = client.put_data(DataObject.DO_KEY_SM, get_random_bytes(2 * aes128_len))
    assert rapdu.status == Errors.SW_OK


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
    expected_secret = key_agreement(static_priv=privkey, static_pub=pubkey, kdf=lambda x: x)

    # Compute ecdh
    pubkey2 = privkey.public_key()
    exp_pubkey = pubkey2.export_key(format="raw", compress=True)
    payload_len = len(exp_pubkey)
    hdr1 = payload_len.to_bytes(1, byteorder="big")
    hdr2 = bytes.fromhex("86") + hdr1  # tag_PubKey_ext
    payload_len += 2
    hdr3 = bytes.fromhex("7f49") + payload_len.to_bytes(1, byteorder="big") + hdr2  # tag_PubKey_D0
    payload_len += 3
    hdr = payload_len.to_bytes(1, byteorder="big") + hdr3
    secret = client.decrypt_asym(hdr + exp_pubkey, PubkeyAlgo.ECDH).data

    assert secret == expected_secret


# In this test we check that a confirmed decryption failing on padding only returns a status word
def test_uif_decrypt_invalid_padding(device: Device, backend: BackendInterface, navigator: Navigator, test_name: Path) -> None:
    client = CommandSender(backend)

    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_DEC_ATTR, KEY_TEMPLATES["rsa2048"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_DEC_KEY)
    rapdu = client.set_uif(DataObject.DO_UIF_DEC, True)
    assert rapdu.status == Errors.SW_OK

    check_pincode(client, PassWord.PW2)
    pubkey = get_RSA_pub_key(client, DataObject.DO_DEC_KEY)

    # Plaintext block without PKCS#1 v1.5 encryption padding
    modulus_len = pubkey.size_in_bytes()
    block = b"\x00\x05" + get_random_bytes(modulus_len - 2)
    ciphertext = pow(int.from_bytes(block, "big"), pubkey.e, pubkey.n).to_bytes(modulus_len, "big")

    pso_dec_p1, pso_dec_p2 = 0x80, 0x86
    rsa_padding_indicator = b"\x00"
    frame = rsa_padding_indicator + ciphertext
    first, last = frame[: len(frame) // 2], frame[len(frame) // 2 :]
    header = struct.pack(">BBBBB", ClaType.CLA_APP_CHAIN, InsType.INS_PSO, pso_dec_p1, pso_dec_p2, len(first))
    rapdu = backend.exchange_raw(header + first)
    assert rapdu.status == Errors.SW_OK

    header = struct.pack(">BBBBB", ClaType.CLA_APP, InsType.INS_PSO, pso_dec_p1, pso_dec_p2, len(last))
    with pytest.raises(ExceptionRAPDU) as err:
        with backend.exchange_async_raw(header + last):
            util_navigate(device, navigator, test_name, "Confirm_Yes")

    assert err.value.status != Errors.SW_OK
    assert len(err.value.data) == 0


# In this test we send malformed PSO:DEC requests to an ECDH key
def test_decrypt_malformed(backend: BackendInterface) -> None:
    client = CommandSender(backend)

    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_DEC_ATTR, KEY_TEMPLATES["cv25519"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_DEC_KEY)
    check_pincode(client, PassWord.PW2)

    pso_dec_p1, pso_dec_p2 = 0x80, 0x86
    ecdh_padding_indicator = 0xA6
    tag_pubkey_do, tag_ext_pubkey = 0x7F49, 0x86
    header_only = struct.pack(">BBBB", ClaType.CLA_APP, InsType.INS_PSO, pso_dec_p1, pso_dec_p2)
    frames = (
        b"",
        struct.pack(">B", ecdh_padding_indicator),
        struct.pack(">BBH", ecdh_padding_indicator, 5, tag_pubkey_do),
        struct.pack(">BBHBBB", ecdh_padding_indicator, 37, tag_pubkey_do, 34, tag_ext_pubkey, 32) + bytes(8),
    )
    for frame in frames:
        with pytest.raises(ExceptionRAPDU) as err:
            if frame:
                backend.exchange_raw(header_only + struct.pack(">B", len(frame)) + frame)
            else:
                backend.exchange_raw(header_only)
        assert err.value.status == Errors.SW_WRONG_LENGTH

    # The app still decrypts valid requests
    pubkey = get_ECDH_pub_key(client, DataObject.DO_DEC_KEY)
    privkey = ECC.generate(curve="Curve25519")
    expected_secret = key_agreement(static_priv=privkey, static_pub=pubkey, kdf=lambda x: x)
    ext_pubkey = privkey.public_key().export_key(format="raw", compress=True)
    ext_pubkey_tlv = struct.pack(">BB", tag_ext_pubkey, len(ext_pubkey)) + ext_pubkey
    pubkey_do = struct.pack(">HB", tag_pubkey_do, len(ext_pubkey_tlv)) + ext_pubkey_tlv
    rapdu = client.decrypt_asym(struct.pack(">B", len(pubkey_do)) + pubkey_do, PubkeyAlgo.ECDH)
    assert rapdu.data == expected_secret
