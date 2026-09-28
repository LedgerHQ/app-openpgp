# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Key Templates feature
"""

import sys

import pytest
from application_client.app_def import DataObject, Errors, PassWord, PubkeyAlgo
from application_client.command_sender import CommandSender
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, eddsa, pkcs1_15
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from utils import (
    KEY_TEMPLATES,
    SHA256_DIGEST_INFO,
    check_pincode,
    generate_key,
    get_ECDSA_pub_key,
    get_EDDSA_pub_key,
    get_key_attributes,
    get_RSA_pub_key,
)


@pytest.mark.parametrize(
    "template",
    [
        "rsa2048",
        pytest.param(
            "rsa3072",
            marks=pytest.mark.skipif("--full" not in sys.argv, reason="skipping long test"),
        ),
        pytest.param(
            "rsa4096",
            marks=pytest.mark.skipif("--full" not in sys.argv, reason="skipping long test"),
        ),
        "nistp256",  # ECDSA
        "ed25519",  # EdDSA
    ],
)
def test_sign(backend: BackendInterface, template: str) -> None:
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
        pubRsakey = get_RSA_pub_key(client, DataObject.DO_SIG_KEY)
        rsaVerifier = pkcs1_15.new(pubRsakey)
        rsaVerifier.verify(hash_obj, rapdu.data)
    elif key_algo == PubkeyAlgo.ECDSA:
        pubEcckey = get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)
        # OpenPGP card returns signature in MPI format (may have 0x00 padding for r and s)
        sig_data = rapdu.data
        # For P-256, r and s should be 32 bytes each
        if len(sig_data) == 66:
            # Format: 0x00 || r(32) || 0x00 || s(32)
            r = sig_data[1:33]
            s = sig_data[34:66]
            sig_data = r + s
        elif len(sig_data) == 65:
            # One component has padding
            if sig_data[0] == 0x00:
                r = sig_data[1:33]
                s = sig_data[33:65]
            else:
                r = sig_data[0:32]
                s = sig_data[33:65]
            sig_data = r + s
        elif len(sig_data) == 64:
            # No padding
            pass
        else:
            # Try to extract last 64 bytes
            sig_data = sig_data[-64:]
        verifier = DSS.new(pubEcckey, "fips-186-3")
        verifier.verify(hash_obj, sig_data)
    elif key_algo == PubkeyAlgo.EDDSA:
        pubEcckey = get_EDDSA_pub_key(client, DataObject.DO_SIG_KEY)
        eddsaVerifier = eddsa.new(pubEcckey, "rfc8032")
        eddsaVerifier.verify(plain, rapdu.data)
    else:
        raise ValueError


# In this test we check that ECDSA operations reject digests shorter than the curve length
def test_ecdsa_digest_length(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    for key_attr, key in ((DataObject.DO_SIG_ATTR, DataObject.DO_SIG_KEY), (DataObject.DO_AUT_ATTR, DataObject.DO_AUT_KEY)):
        rapdu = client.set_template(key_attr, KEY_TEMPLATES["nistp256"])
        assert rapdu.status == Errors.SW_OK
        generate_key(client, key)

    check_pincode(client, PassWord.PW1)
    check_pincode(client, PassWord.PW2)
    curve_len = 32
    for length in (0, 1, curve_len - 1):
        rapdu = client.sign(get_random_bytes(length))
        assert rapdu.status == Errors.SW_WRONG_LENGTH
        rapdu = client.authenticate(get_random_bytes(length))
        assert rapdu.status == Errors.SW_WRONG_LENGTH

    for length in (curve_len, 2 * curve_len):
        rapdu = client.sign(get_random_bytes(length))
        assert rapdu.status == Errors.SW_OK
        rapdu = client.authenticate(get_random_bytes(length))
        assert rapdu.status == Errors.SW_OK


# In this test we check the RSA public exponent configuration used for key generation
def test_rsa_exponent(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    # The exponent is written little-endian and read back big-endian
    for exponent in (0, 1, 2, 65536):
        with pytest.raises(ExceptionRAPDU) as err:
            client.put_data(DataObject.CMD_RSA_EXP, exponent.to_bytes(4, "little"))
        assert err.value.status == Errors.SW_WRONG_DATA

    for exponent in (3, 65537):
        rapdu = client.put_data(DataObject.CMD_RSA_EXP, exponent.to_bytes(4, "little"))
        assert rapdu.status == Errors.SW_OK
        rapdu = client.get_data(DataObject.CMD_RSA_EXP)
        assert rapdu.data == exponent.to_bytes(4, "big")

    rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["rsa2048"])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, DataObject.DO_SIG_KEY)
    assert get_RSA_pub_key(client, DataObject.DO_SIG_KEY).e == 65537
