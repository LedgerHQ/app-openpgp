# -*- coding: utf-8 -*-
#*****************************************************************************
#   Ledger App OpenPGP.
#   (c) 2024 Ledger SAS.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*****************************************************************************

from enum import Enum, IntEnum


KEY_TEMPLATES = {
    "rsa2048" : "010800002001",
    "rsa3072" : "010C00002001",
    # "rsa4096" : "011000002001", not supported yet
    "nistp256": "132A8648CE3D030107",
    "ed25519" : "162B06010401DA470F01",
    "cv25519" : "122B060104019755010501"
}


KEY_OPERATIONS = {
    "Export":   0x00, # Read and export a Public Key
    "Generate": 0x80, # Generate a new Asymmetric key pair
    "Read":     0x81, # Read Public Key
}


USER_SALUTATION = {
    "Male":   "1",
    "Female": "2",
}


class KeyTypes(str, Enum):
    """Key types definition
        OpenPGP Application manage four keys for cryptographic operation (PSO) plus two
        for secure channel.
        The first four keys are defined as follow:
        - One asymmetric signature private key (RSA or EC), named 'sig'
        - One asymmetric decryption private key (RSA or EC), named 'dec'
        - One asymmetric authentication private key (RSA or EC), named 'aut'
        - One symmetric decryption private key (AES), named 'sym0'

        The 3 first asymmetric keys can be either randomly generated on-card or
        explicitly put from outside.
        The fourth is put from outside.
    """

    # Asymmetric Signature Private Key (RSA or EC)
    KEY_SIG = "SIG"
    # Asymmetric Decryption Private Key (RSA or EC)
    KEY_DEC = "DEC"
    # Asymmetric Authentication Private Key (RSA or EC)
    KEY_AUT = "AUT"
    # Symmetric Decryption Key (AES)


class PubkeyAlgo(IntEnum):
    """ Public-Key Algorithm IDs definition """
    # https://www.rfc-editor.org/rfc/rfc4880#section-9.1

    # RSA (Encrypt or Sign)
    RSA = 1
    # Elliptic Curve Diffie-Hellman
    ECDH = 18
    # Elliptic Curve Digital Signature Algorithm
    ECDSA = 19
    # Edwards-curve Digital Signature Algorithm
    EDDSA = 22


class PassWord(IntEnum):
    """ Password type definition """

    # USER_PIN for only one PSO:CDS command
    PW1 = 0x81
    # USER_PIN for several attempts
    PW2 = 0x82
    # Admin PIN
    PW3 = 0x83


class ErrorCodes:
    """ Error codes definition """

    err_list = {
        0x6285: "Selected file in termination state",
        0x6581: "Memory failure",
        0x6600: "Security-related issues (reserved for UIF in this application)",
        0x6700: "Wrong length (Lc and/or Le)",
        0x6881: "Logical channel not supported",
        0x6882: "Secure messaging not supported",
        0x6883: "Last command of the chain expected",
        0x6884: "Command chaining not supported",
        0x6982: "Security status not satisfied",
        0x6983: "Authentication method blocked",
        0x6984: "Data Invalid",
        0x6985: "Condition of use not satisfied",
        0x6986: "Command not allowed",
        0x6987: "Expected SM data objects missing",
        0x6988: "SM data objects incorrect",
        0x6A80: "Incorrect parameters in the data field",
        0x6A82: "File or application not found",
        0x6A86: "Incorrect P1-P2",
        0x6A88: "Referenced data not found",
        0x6B00: "Wrong parameters P1-P2",
        0x6D00: "Instruction (INS) not supported",
        0x6E00: "Class (CLA) not supported",
        0x6F00: "Unknown Error",
        0x9000: "Success",
    }
    ERR_SUCCESS = 0x9000
    ERR_SW1_VALID = 0x61
    ERR_INTERNAL = 0


class DataObject(IntEnum):
    """ Data Objects definition """

    # [Read/Write] Slot config
    CMD_SLOT_CFG = 0x01F1
    # [Read/Write] Slot selection
    CMD_SLOT_CUR = 0x01F2
    # [Read/Write] RSA Exponent
    CMD_RSA_EXP = 0x01F8

    # [Read] Full Application identifier (AID), ISO 7816-4
    DO_AID = 0x4F
    # [Read/Write] Login data
    DO_LOGIN = 0x5E
    # [Read/Write] Uniform resource locator (URL, as defined in RFC 1738)
    DO_URL = 0x5F50
    # [Read] Historical bytes, Card service data and Card capabilities
    DO_HIST = 0x5F52

    # [Read/Write] Optional DO for private use
    DO_PRIVATE_01 = 0x0101
    DO_PRIVATE_02 = 0x0102
    DO_PRIVATE_03 = 0x0103
    DO_PRIVATE_04 = 0x0104

    # [Read] Cardholder Related Data
    DO_CARDHOLDER_DATA = 0x65
    # [Read/Write] Name according to ISO/IEC 7501-1)
    DO_CARD_NAME = 0x5B
    # [Read/Write] Language preferences (according to ISO 639)
    DO_CARD_LANG = 0x5F2D
    # [Read/Write] Salutation (according to ISO 5218)
    DO_CARD_SALUTATION = 0x5F35

    # [Read/Write] Digital signature
    DO_SIG_KEY = 0xB6
    # [Read/Write] Confidentiality
    DO_DEC_KEY = 0xB8
    # [Read/Write] Authentication
    DO_AUT_KEY = 0xA4

    # [Read] Application Related Data
    DO_APP_DATA = 0x6E
    # [Read] Extended length information (ISO 7816-4)
    DO_EXT_LEN = 0x7F66
    # [Read] Discretionary data objects
    DO_DISCRET_DATA = 0x73

    # [Read] Extended capabilities Flag list
    DO_EXT_CAP = 0xC0
    # [Read/Write] Algorithm attributes SIGnature
    DO_SIG_ATTR = 0xC1
    # [Read/Write] Algorithm attributes DECryption
    DO_DEC_ATTR = 0xC2
    # [Read/Write] Algorithm attributes AUThentication
    DO_AUT_ATTR = 0xC3
    # [Read/Write] PW status Bytes
    DO_PW_STATUS = 0xC4
    # [Read] Fingerprints (binary, 20 bytes (dec.) each for SIG, DEC, AUT)
    DO_FINGERPRINTS = 0xC5
    # [Read] List of CA-Fingerprints (binary, 20 bytes (dec.) each for SIG, DEC, AUT)
    DO_CA_FINGERPRINTS = 0xC6
    # [Write] Fingerprint for SIGnature key, format according to RFC 4880
    DO_FINGERPRINT_WR_SIG = 0xC7
    # [Write] Fingerprint for DECryption key, format according to RFC 4880
    DO_FINGERPRINT_WR_DEC = 0xC8
    # [Write] Fingerprint for AUThentication key, format according to RFC 4880
    DO_FINGERPRINT_WR_AUT = 0xC9
    # [Write] CA-Fingerprint for SIGnature key
    DO_CA_FINGERPRINT_WR_SIG = 0xCA
    # [Write] CA-Fingerprint for DECryption key
    DO_CA_FINGERPRINT_WR_DEC = 0xCB
    # [Write] CA-Fingerprint for AUThentication key
    DO_CA_FINGERPRINT_WR_AUT = 0xCC
    # [Read] List of generation dates. 4 bytes, Big Endian each for SIG, DEC, AUT
    DO_KEY_DATES = 0xCD

    # [Write] Generation date/time of SIGnature key (Big Endian, according to RFC 4880)
    DO_DATES_WR_SIG = 0xCE
    # [Write] Generation date/time of DECryption key (Big Endian, according to RFC 4880)
    DO_DATES_WR_DEC = 0xCF
    # [Write] Generation date/time of AUThentication key (Big Endian, according to RFC 4880)
    DO_DATES_WR_AUT = 0xD0

    # [Read] Security support template
    DO_SEC_TEMPL = 0x7A
    # [Read] Digital signature counter
    DO_SIG_COUNT = 0x93

    # [Write] Resetting Code
    DO_RESET_CODE = 0xD3
    # [Read/Write] User Interaction Flag (UIF) for PSO:CDS
    DO_UIF_SIG = 0xD6
    # [Read/Write] User Interaction Flag (UIF) for PSO:DEC
    DO_UIF_DEC = 0xD7
    # [Read/Write] User Interaction Flag (UIF) for PSO:AUT
    DO_UIF_AUT = 0xD8
    # [Read/Write] Cardholder certificate (each for AUT, DEC and SIG)
    DO_CERT = 0x7F21

    # [Read/Write] Asymmetric Key Pair
    DO_PUB_KEY = 0x7F49

    # [Read] General Feature management
    DO_GEN_FEATURES = 0x7F74
