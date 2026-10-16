# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Signing feature
"""

from application_client.app_def import DataObject, Errors, PassWord, PubkeyAlgo
from application_client.command_sender import CommandSender
from Crypto.Hash import SHA224, SHA256, SHA512
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, eddsa, pkcs1_15
from ragger.backend import BackendInterface
from utils import (
    KEY_TEMPLATES,
    SHA256_DIGEST_INFO,
    check_pincode,
    generate_key,
    get_ECDSA_pub_key,
    get_EDDSA_pub_key,
    get_key_attributes,
    get_RSA_pub_key,
    verify_ecdsa_p256,
)


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


def _verify_signature(
    client: CommandSender,
    hash_obj: SHA256.SHA256Hash,
    key_tag: DataObject,
    signature: bytes,
) -> None:
    # Read the SIG pub Key
    pubkey: RsaKey = get_RSA_pub_key(client, key_tag)
    # Verify the signature
    verifier = pkcs1_15.new(pubkey)
    verifier.verify(hash_obj, signature)


def _use_template(client: CommandSender, attr: DataObject, key_tag: DataObject, template: str) -> None:
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(attr, KEY_TEMPLATES[template])
    assert rapdu.status == Errors.SW_OK
    generate_key(client, key_tag)


# In this test we check the ECDSA signatures: r || s, each on the curve size
def test_sign_ecdsa(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _use_template(client, DataObject.DO_SIG_ATTR, DataObject.DO_SIG_KEY, "nistp256")
    verifier = DSS.new(get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY), "fips-186-3")
    check_pincode(client, PassWord.PW1)

    # About 1 in 128 signatures has r or s shorter than the curve size
    for _ in range(300):
        hash_obj = SHA256.new(get_random_bytes(16))
        rapdu = client.sign(hash_obj.digest())
        assert rapdu.status == Errors.SW_OK
        assert len(rapdu.data) == 64
        verifier.verify(hash_obj, rapdu.data)


# In this test we check that a digest shorter than the curve is left-padded
def test_sign_ecdsa_short_digest(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _use_template(client, DataObject.DO_SIG_ATTR, DataObject.DO_SIG_KEY, "nistp256")
    pubkey = get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)
    check_pincode(client, PassWord.PW1)

    digest = SHA224.new(get_random_bytes(16)).digest()
    rapdu = client.sign(digest)
    assert rapdu.status == Errors.SW_OK
    assert verify_ecdsa_p256(pubkey, digest, rapdu.data)


# In this test we check the ECDSA authentication
def test_auth_ecdsa(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _use_template(client, DataObject.DO_AUT_ATTR, DataObject.DO_AUT_KEY, "nistp256")
    verifier = DSS.new(get_ECDSA_pub_key(client, DataObject.DO_AUT_KEY), "fips-186-3")
    check_pincode(client, PassWord.PW2)

    hash_obj = SHA256.new(get_random_bytes(16))
    rapdu = client.authenticate(hash_obj.digest())
    assert rapdu.status == Errors.SW_OK
    assert len(rapdu.data) == 64
    verifier.verify(hash_obj, rapdu.data)


# In this test we check the EdDSA signatures
def test_sign_eddsa(backend: BackendInterface) -> None:
    client = CommandSender(backend)
    _use_template(client, DataObject.DO_SIG_ATTR, DataObject.DO_SIG_KEY, "ed25519")
    verifier = eddsa.new(get_EDDSA_pub_key(client, DataObject.DO_SIG_KEY), "rfc8032")
    check_pincode(client, PassWord.PW1)

    # GnuPG sends the digest of the data as the message to sign
    message = SHA512.new(get_random_bytes(16)).digest()
    rapdu = client.sign(message)
    assert rapdu.status == Errors.SW_OK
    assert len(rapdu.data) == 64
    verifier.verify(message, rapdu.data)
