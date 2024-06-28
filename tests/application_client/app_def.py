# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the applicatuion definitions.
"""
from enum import IntEnum


class ClaType(IntEnum):
    """Application ID definitions"""
    # Application CLA
    CLA_APP        = 0x00
    CLA_APP_CHAIN  = 0x10
    # Special CLA for Verify with pinpad
    CLA_APP_VERIFY = 0xEF


class InsType(IntEnum):
    """Application Command ID definitions"""
    INS_ACTIVATE_FILE    = 0x44
    INS_SELECT           = 0xA4
    INS_TERMINATE_DF     = 0xE6
    INS_VERIFY           = 0x20
    INS_CHANGE_REF_DATA  = 0x24
    INS_RESET_RC         = 0x2C
    INS_GET_DATA         = 0xCA
    INS_PUT_DATA         = 0xDA
    INS_GEN_ASYM_KEYPAIR = 0x47
    INS_GET_RESPONSE     = 0xC0
    INS_PSO              = 0x2A
    INS_INT_AUTHENTICATE = 0x88
    INS_GET_CHALLENGE    = 0x84
    INS_MSE              = 0x22


class PubkeyAlgo(IntEnum):
    """Public-Key Algorithm IDs definition"""
    # https://www.rfc-editor.org/rfc/rfc4880#section-9.1

    INVALID = 0

    # RSA (Encrypt or Sign)
    RSA = 1
    # Elliptic Curve Diffie-Hellman
    ECDH = 18
    # Elliptic Curve Digital Signature Algorithm
    ECDSA = 19
    # Edwards-curve Digital Signature Algorithm
    EDDSA = 22


class PassWord(IntEnum):
    """Password type definition"""
    # USER_PIN for only one PSO:CDS command
    PW1 = 0x81
    # USER_PIN for several attempts
    PW2 = 0x82
    # Admin PIN
    PW3 = 0x83


class Errors(IntEnum):
    """Application Errors definitions"""
    SW_STATE_TERMINATED               = 0x6285
    SW_MEMORY                         = 0x6581
    SW_SECURITY                       = 0x6600
    SW_WRONG_LENGTH                   = 0x6700
    SW_LOGICAL_CHANNEL_NOT_SUPPORTED  = 0x6881
    SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882
    SW_LAST_COMMAND_EXPECTED          = 0x6883
    SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884
    SW_SECURITY_STATUS_NOT_SATISFIED  = 0x6982
    SW_AUTH_METHOD_BLOCKED            = 0x6983
    SW_DATA_INVALID                   = 0x6984
    SW_CONDITIONS_NOT_SATISFIED       = 0x6985
    SW_COMMAND_NOT_ALLOWED            = 0x6986
    SW_EXPECTED_SM_MISSING            = 0x6987
    SW_SM_DATA_INCORRECT              = 0x6988
    SW_WRONG_DATA                     = 0x6a80
    SW_FILE_NOT_FOUND                 = 0x6a82
    SW_INCORRECT_P1P2                 = 0x6a86
    SW_REFERENCED_DATA_NOT_FOUND      = 0x6a88
    SW_WRONG_P1P2                     = 0x6b00
    SW_INS_NOT_SUPPORTED              = 0x6d00
    SW_CLA_NOT_SUPPORTED              = 0x6e00
    SW_UNKNOWN                        = 0x6f00
    SW_OK                             = 0x9000
    SW_CORRECT_LONG_RESPONSE          = 0x6100


class DataObject(IntEnum):
    """Data Objects definition"""

    # [Read] Full Application identifier (AID), ISO 7816-4
    DO_AID = 0x4F

    # [Read/Write] Name according to ISO/IEC 7501-1)
    DO_CARD_NAME = 0x5B
    # [Read/Write] Login data
    DO_LOGIN = 0x5E
    # [Read] Cardholder Related Data
    DO_CARDHOLDER_DATA = 0x65
    # [Read] Application Related Data
    DO_APP_DATA = 0x6E
    # [Read] Discretionary data objects
    DO_DISCRET_DATA = 0x73

    # [Read/Write] Digital signature
    DO_SIG_KEY = 0xB6
    # [Read/Write] Confidentiality
    DO_DEC_KEY = 0xB8
    # [Read/Write] Authentication
    DO_AUT_KEY = 0xA4

    # [Read/Write] Algorithm attributes SIGnature
    DO_SIG_ATTR = 0xC1
    # [Read/Write] Algorithm attributes DECryption
    DO_DEC_ATTR = 0xC2
    # [Read/Write] Algorithm attributes AUThentication
    DO_AUT_ATTR = 0xC3
    # [Write] AES symmetric key
    DO_KEY_AES = 0xD5

    # [Read/Write] User Interaction Flag (UIF) for PSO:CDS
    DO_UIF_SIG = 0xD6
    # [Read/Write] User Interaction Flag (UIF) for PSO:DEC
    DO_UIF_DEC = 0xD7
    # [Read/Write] User Interaction Flag (UIF) for PSO:AUT
    DO_UIF_AUT = 0xD8

    # [Read/Write] Asymmetric Key Pair
    DO_PUB_KEY = 0x7F49

    # [Read/Write] Slot config
    CMD_SLOT_CFG = 0x01F1
    # [Read/Write] Slot selection
    CMD_SLOT_CUR = 0x01F2

    # [Read/Write] Language preferences (according to ISO 639)
    DO_CARD_LANG = 0x5F2D
    # [Read/Write] Salutation (according to ISO 5218)
    DO_CARD_SALUTATION = 0x5F35
    # [Read/Write] Uniform resource locator (URL, as defined in RFC 1738)
    DO_URL = 0x5F50
