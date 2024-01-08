# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests utility functions
"""
from pathlib import Path
from typing import List, Tuple
import re
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.number import bytes_to_long
from Crypto.Signature import eddsa

from ragger.navigator import NavInsID, NavIns, Navigator
from ragger.firmware import Firmware

from application_client.command_sender import CommandSender
from application_client.app_def import Errors, PassWord, DataObject, PubkeyAlgo

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

KEY_TEMPLATES = {
    "rsa2048" : "010800002001",
    "rsa3072" : "010C00002001",
    "rsa4096" : "011000002001",
    "nistp256": "132A8648CE3D030107",
    "ed25519" : "162B06010401DA470F01",
    "cv25519" : "122B060104019755010501"
}

# digestInfo header: https://www.rfc-editor.org/rfc/rfc8017#section-9.2
SHA256_DIGEST_INFO = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"


def util_navigate(
        firmware: Firmware,
        navigator: Navigator,
        test_name: Path,
        text: str = "",
) -> None:
    """Navigate in the menus with conditions """

    assert text
    valid_instr: list[NavIns | NavInsID] = []

    if firmware.device == "nanos":
        text, txt_cfg = text.split("_")
        nav_inst = NavInsID.RIGHT_CLICK
        if txt_cfg == "Yes":
            valid_instr.append(NavInsID.RIGHT_CLICK)
        elif txt_cfg == "No":
            valid_instr.append(NavInsID.LEFT_CLICK)
        else:
            raise ValueError(f'Wrong text "{text}"')

    elif firmware.device.startswith("nano"):
        text = text.split("_")[1]
        nav_inst = NavInsID.RIGHT_CLICK
        valid_instr.append(NavInsID.BOTH_CLICK)

    else:
        text, txt_cfg = text.split("_")
        if txt_cfg == "Yes":
            nav_inst = NavInsID.USE_CASE_CHOICE_CONFIRM
            valid_instr.append(NavInsID.USE_CASE_CHOICE_CONFIRM)
        elif txt_cfg == "No":
            nav_inst = NavInsID.USE_CASE_REVIEW_REJECT
            valid_instr.append(NavInsID.USE_CASE_CHOICE_REJECT)
        else:
            raise ValueError(f'Wrong text "{text}"')

    # Do not wait last screen change because home screen contain a "random" ID
    navigator.navigate_until_text_and_compare(nav_inst,
                                              valid_instr,
                                              text,
                                              ROOT_SCREENSHOT_PATH,
                                              test_name,
                                              screen_change_after_last_instruction=False)


def generate_key(client: CommandSender, key_tag: DataObject, seed: bool = False) -> None:
    """Generate a Asymmetric key

    Args:
        client (CommandSender): Application object
        key_tag (DataObject):   Tag identifying the key
        seed (bool):            Generate a key in SEED mode
    """

    # Verify PW3 (Admin)
    check_pincode(client, PassWord.PW3)

    # Generate the SIG Key Pair
    rapdu = client.generate_key(key_tag, seed)
    assert rapdu.status == Errors.SW_OK


def get_key_attributes(client: CommandSender, key_attr: int) -> Tuple[PubkeyAlgo, int]:
    """Send and check the pincode

    Args:
        client (CommandSender): Application object
        key_attr (int):         Key related attribute to be parsed

    Returns:
        Public-Key Algorithm ID and Key size
    """

    rapdu = client.get_data(DataObject.DO_APP_DATA)
    assert rapdu.status == Errors.SW_OK

    tags = decode_tlv(rapdu.data)
    data1 = tags.get(DataObject.DO_DISCRET_DATA, b"")
    if not data1:
        return PubkeyAlgo.INVALID, 0
    data2 = decode_tlv(data1)
    attr = data2.get(key_attr, b"")
    if not attr:
        return PubkeyAlgo.INVALID, 0
    key_algo = attr[0]
    print(f" Key ID:       {key_algo}")
    if key_algo == PubkeyAlgo.RSA:
        key_size = (attr[1] << 8) | attr[2]
        print(f" Key size:     {key_size}")
    else:
        key_size = 0
    return key_algo, key_size


def get_EDDSA_pub_key(client: CommandSender, key_tag: DataObject) -> ECC.EccKey:
    """Read the Public Key and generate a EccKey object

    Args:
        client (CommandSender): Application object
        key_tag (DataObject):   Tag identifying the key to read

    Returns:
        EccKey
    """

    # Extract Pub key parameters
    data = _get_pub_key(client, key_tag)

    oid = data[0x86]
    print(f" OID[{len(oid)}]: {oid.hex()}")
    assert len(oid) == 32
    return eddsa.import_public_key(oid)


def get_ECDSA_pub_key(client: CommandSender, key_tag: DataObject) -> ECC.EccKey:
    """Read the Public Key and generate a EccKey object

    Args:
        client (CommandSender): Application object
        key_tag (DataObject):   Tag identifying the key to read

    Returns:
        EccKey
    """

    # Extract Pub key parameters
    data = _get_pub_key(client, key_tag)

    oid = data[0x86][1:]
    pt_len = int(len(oid) / 2)
    x = oid[:pt_len]
    y = oid[pt_len:]
    print(f" X[{len(x)}]: {x.hex()}")
    print(f" Y[{len(y)}]: {y.hex()}")
    assert len(x) == len(y)
    return ECC.construct(curve="P-256", point_x=bytes_to_long(x), point_y=bytes_to_long(y))


def get_RSA_pub_key(client: CommandSender, key_tag: DataObject) -> RSA.RsaKey:
    """Read the Public Key and generate a RsaKey object

    Args:
        client (CommandSender): Application object
        key_tag (DataObject):   Tag identifying the key to read

    Returns:
        RsaKey
    """

    # Extract Pub key parameters
    data = _get_pub_key(client, key_tag)

    exponent = data[0x82]
    modulus = data[0x81]
    print(f" Key Exponent: 0x{exponent.hex()}")
    print(f" Key Modulus[{len(modulus)}]: {modulus.hex()}")

    return RSA.construct((int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')))


def check_pincode(client: CommandSender, pwd: PassWord) -> None:
    """Send and check the pincode

    Args:
        client (CommandSender): Application object
        pwd (PassWord):         Password to be verified
    """

    if pwd in (PassWord.PW1, PassWord.PW2):
        pincode = "123456"
    elif pwd == PassWord.PW3:
        pincode = "12345678"
    # Verify PW2 (User)
    rapdu = client.send_verify_pw(pwd, pincode)
    assert rapdu.status == Errors.SW_OK


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s?=\s?(?P<val>\w+)", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
    assert name == name_str


def decode_tlv(tlv: bytes) -> dict:
    """Decode TLV fields

    Args:
        tlv (bytes): Input data bytes to parse

    Returns:
        dict {t: v, t:v, ...}
    """

    tags = {}
    while len(tlv):
        o = 0
        l = 0
        if (tlv[0] & 0x1F) == 0x1F:
            t = (tlv[0] << 8) | tlv[1]
            o = 2
        else:
            t = tlv[0]
            o = 1
        l = tlv[o]
        if l & 0x80 :
            if (l & 0x7f) == 1:
                l = tlv[o + 1]
                o += 2
            if (l & 0x7f) == 2:
                l = (tlv[o + 1] << 8) | tlv[o + 2]
                o += 3
        else:
            o += 1
        v = tlv[o:o + l]
        tags[t] = v
        tlv = tlv[o + l:]
    return tags


def _read_makefile() -> List[str]:
    """Read lines from the parent Makefile """

    parent = Path(ROOT_SCREENSHOT_PATH).parent.resolve()
    makefile = f"{parent}/Makefile"
    print(f"Analyzing {makefile}...")
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()

    return lines


def _get_pub_key(client: CommandSender, key_tag: DataObject) -> dict:
    """Read the Public Key parameters

    Args:
        client (CommandSender): Application object
        key_tag (DataObject):   Tag identifying the key to read

    Returns:
        Dictionary with key parameters
    """

    rapdu = client.read_key(key_tag)
    assert rapdu.status == Errors.SW_OK

    # Extract Pub key parameters
    tags = decode_tlv(rapdu.data)
    return decode_tlv(tags[DataObject.DO_PUB_KEY])
