/*****************************************************************************
 *   Ledger App OpenPGP.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifndef GPG_TYPES_H
#define GPG_TYPES_H

#include "lcx_sha3.h"
#include "usbd_ccid_if.h"
#include "bolos_target.h"
#ifdef HAVE_NBGL
#include "nbgl_layout.h"
#endif

/* cannot send more that F0 bytes in CCID, why? do not know for now
 *  So set up length to F0 minus 2 bytes for SW
 */
#define GPG_APDU_LENGTH 0xFE

/* big private DO */
#define GPG_EXT_PRIVATE_DO_LENGTH 512
/* will be fixed..1024 is not enough */
#define GPG_EXT_CARD_HOLDER_CERT_LENTH 2560
/* random choice */
#define GPG_EXT_CHALLENGE_LENTH 254
/* accept long PW, but less than one sha256 block */
#define GPG_MAX_PW_LENGTH  12
#define GPG_MIN_PW1_LENGTH 6
#define GPG_MIN_PW3_LENGTH 8

#define AID_LENGTH         16
#define HISTO_LENGTH       15
#define HISTO_OFFSET_STATE 12  // 3rd byte from last (buffer size is 15)
#ifdef TARGET_NANOS
#define GPG_KEYS_SLOTS 1
#else
#define GPG_KEYS_SLOTS 3
#endif

#define GPG_KEY_ATTRIBUTES_LENGTH 12

#define GPG_RSA_DEFAULT_PUB 0x00010001U

#ifndef CX_AES_128_KEY_LEN
#define CX_AES_128_KEY_LEN CX_AES_BLOCK_SIZE
#endif

/* ---  Keys IDs  --- */
// https://www.rfc-editor.org/rfc/rfc4880#section-9.1
#define KEY_ID_RSA   1   // RSA (Encrypt or Sign)
#define KEY_ID_ECDH  18  // Elliptic Curve Diffie-Hellman
#define KEY_ID_ECDSA 19  // Elliptic Curve Digital Signature Algorithm
#define KEY_ID_EDDSA 22  // Edwards-curve Digital Signature Algorithm

struct gpg_pin_s {
    unsigned int ref;
    // initial pin length, 0 means not set
    unsigned int length;
    unsigned int counter;
    // only store sha256 of PIN/RC
    unsigned char value[32];
};
typedef struct gpg_pin_s gpg_pin_t;

#define LV(name, maxlen)             \
    struct {                         \
        unsigned int length;         \
        unsigned char value[maxlen]; \
    } name

typedef struct gpg_key_s {
    /*  C1 C2 C3 */
    LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
    /*  key value */
    union {
        cx_rsa_private_key_t rsa;
        cx_rsa_2048_private_key_t rsa2048;
        cx_rsa_3072_private_key_t rsa3072;
#ifdef WITH_SUPPORT_RSA4096
        cx_rsa_4096_private_key_t rsa4096;
#endif
        cx_ecfp_private_key_t ecfp;
        cx_ecfp_256_private_key_t ecfp256;
        cx_ecfp_384_private_key_t ecfp384;
        cx_ecfp_512_private_key_t ecfp512;
        cx_ecfp_640_private_key_t ecfp640;
    } priv_key;
    union {
        unsigned char rsa[4];
        cx_ecfp_public_key_t ecfp;
        cx_ecfp_256_public_key_t ecfp256;
        cx_ecfp_384_public_key_t ecfp384;
        cx_ecfp_512_public_key_t ecfp512;
        cx_ecfp_640_public_key_t ecfp640;
    } pub_key;
    /* C7 C8 C9 , C5 = C7|C8|C9*/
    unsigned char fingerprints[20];
    /* 7F21 */
    LV(CA, GPG_EXT_CARD_HOLDER_CERT_LENTH);
    /* C7 C8 C9, C6 = C7|C8|C9*/
    unsigned char CA_fingerprints[20];
    /* CE CF D0, CD = CE|CF|D0 */
    unsigned char date[4];
    /* D6/D7/D8- */
    unsigned char UIF[2];
} gpg_key_t;

typedef struct gpg_key_slot_s {
    unsigned char serial[4];
    /* */
    gpg_key_t sig;
    gpg_key_t aut;
    gpg_key_t dec;
    /* -- Security support template -- */
    /* 93 */
    unsigned int sig_count;
    /* D5 */
    cx_aes_key_t AES_dec;

} gpg_key_slot_t;

struct gpg_nv_state_s {
    /* magic */
    unsigned char magic[8];

    /* pin mode */
    unsigned char config_pin[1];

    /* 01F1 (01F2 is volatile)*/
    unsigned char config_slot[3];
    /* RSA exponent */
    unsigned char default_RSA_exponent[4];

    /*  0101 0102 0103 0104 */
    LV(private_DO1, GPG_EXT_PRIVATE_DO_LENGTH);
    LV(private_DO2, GPG_EXT_PRIVATE_DO_LENGTH);
    LV(private_DO3, GPG_EXT_PRIVATE_DO_LENGTH);
    LV(private_DO4, GPG_EXT_PRIVATE_DO_LENGTH);

    /*  5E */
    LV(login, GPG_EXT_PRIVATE_DO_LENGTH);
    /*  5F50 */
    LV(url, GPG_EXT_PRIVATE_DO_LENGTH);

    /* -- Cardholder Related Data -- */
    /*  5B */
    LV(name, 39);
    /*  5F2D */
    LV(lang, 8);
    /*  5F35 */
    unsigned char salutation[1];

    /* -- Application  Related Data -- */
    /*  4F */
    unsigned char AID[AID_LENGTH];
    /*  5F52 */
    unsigned char histo[HISTO_LENGTH];

    /*  C4 */
    unsigned char PW_status[4];

    /* PINs */
    gpg_pin_t PW1;
    gpg_pin_t PW3;
    gpg_pin_t RC;

    /* gpg keys */
    gpg_key_slot_t keys[GPG_KEYS_SLOTS];

    /* --- SM  --- */
    /* D1 */
    cx_aes_key_t SM_enc;
    /* D2 */
    cx_aes_key_t SM_mac;
};

typedef struct gpg_nv_state_s gpg_nv_state_t;

#define GPG_IO_BUFFER_LENGTH (1512)

struct gpg_v_state_s {
    /* app state */
    unsigned char selected;
    unsigned char slot; /* DO 01F2 */
    gpg_key_slot_t *kslot;
    gpg_key_t *mse_aut;
    gpg_key_t *mse_dec;
    unsigned char seed_mode;

    unsigned char UIF_flags;

    /* io state*/

    unsigned char io_cla;
    unsigned char io_ins;
    unsigned char io_p1;
    unsigned char io_p2;
    unsigned char io_lc;
    unsigned char io_le;
    unsigned short io_length;
    unsigned short io_offset;
    unsigned short io_mark;
    unsigned short io_p1p2;
    union {
        unsigned char io_buffer[GPG_IO_BUFFER_LENGTH];
        struct {
            union {
                cx_rsa_public_key_t public;
                cx_rsa_2048_public_key_t public2048;
                cx_rsa_3072_public_key_t public3072;
#ifdef WITH_SUPPORT_RSA4096
                cx_rsa_4096_public_key_t public4096;
#endif
            };
            union {
                cx_rsa_private_key_t private;
                cx_rsa_2048_private_key_t private2048;
                cx_rsa_3072_private_key_t private3072;
#ifdef WITH_SUPPORT_RSA4096
                cx_rsa_4096_private_key_t private4096;
#endif
            };
        } rsa;

        struct {
            union {
                cx_ecfp_public_key_t public;
                cx_ecfp_256_public_key_t public256;
                cx_ecfp_384_public_key_t public384;
                cx_ecfp_512_public_key_t public512;
                cx_ecfp_640_public_key_t public640;
            };
            union {
                cx_ecfp_private_key_t private;
                cx_ecfp_256_private_key_t private256;
                cx_ecfp_384_private_key_t private384;
                cx_ecfp_512_private_key_t private512;
                cx_ecfp_640_private_key_t private640;
            };
        } ecfp;

        struct {
            unsigned char md_buffer[GPG_IO_BUFFER_LENGTH -
                                    (32 + MAX(sizeof(cx_sha3_t), sizeof(cx_sha256_t)))];
            unsigned char H[32];
            union {
                cx_sha3_t sha3;
                cx_sha256_t sha256;
            };
        } md;
    } work;

    /* data state */
    unsigned short DO_current;
    unsigned short DO_reccord;
    unsigned short DO_offset;

    /* PINs state */
    unsigned char verified_pin[5];
    unsigned char pinmode;
    unsigned char pinmode_req;

    /* ux menus */
    char menu[112];
    unsigned char ux_pinentry[GPG_MAX_PW_LENGTH];
    unsigned char ux_pinLen;
    unsigned int ux_key;
    unsigned int ux_type;

#ifdef TARGET_NANOS
    ux_menu_entry_t ui_dogsays[2];
#endif

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
    char ux_buff1[32];
    char ux_buff2[32];
    char ux_buff3[32];
#endif

#ifdef HAVE_NBGL
    char line[112];
    unsigned int ux_step;
    nbgl_layout_t *layoutCtx;
#endif

#ifdef GPG_LOG
    unsigned char log_buffer[256];
#endif
};
typedef struct gpg_v_state_s gpg_v_state_t;

/* ---  Identifiers  --- */

#define STATE_ACTIVATE  0x05
#define STATE_TERMINATE 0x03

#define IO_OFFSET_END  (unsigned int) -1
#define IO_OFFSET_MARK (unsigned int) -2

#define PIN_ID_PW1 0x81
#define PIN_ID_PW2 0x82
#define PIN_ID_PW3 0x83
#define PIN_ID_RC  0x84

// PIN_MODE_HOST not supported by Ledger App
#define PIN_MODE_SCREEN  0
#define PIN_MODE_CONFIRM 1
#define PIN_MODE_TRUST   2

/* ---  CLA  --- */
#define CLA_APP_DEF      0x00
#define CLA_APP_SM       0x0C
#define CLA_APP_CHAIN    0x10
#define CLA_APP_CHAIN_SM 0x1C
#define CLA_APP_APDU_PIN PIN_OPR_APDU_CLA

/* ---  INS  --- */
#ifdef GPG_LOG
#define INS_GET_LOG 0x04
#endif
#define INS_EXIT                  0x02
#define INS_VERIFY                0x20
#define INS_MSE                   0x22
#define INS_CHANGE_REFERENCE_DATA 0x24
#define INS_PSO                   0x2a
#define INS_RESET_RETRY_COUNTER   0x2c
#define INS_ACTIVATE_FILE         0x44
#define INS_GEN_ASYM_KEYPAIR      0x47
#define INS_GET_CHALLENGE         0x84
#define INS_INTERNAL_AUTHENTICATE 0x88
#define INS_SELECT                0xa4
#define INS_SELECT_DATA           0xa5
#define INS_GET_RESPONSE          0xc0
#define INS_GET_DATA              0xca
#define INS_GET_NEXT_DATA         0xcc
#define INS_PUT_DATA              0xda
#define INS_PUT_DATA_ODD          0xdb
#define INS_TERMINATE_DF          0xe6

/* ---  Error constants  --- */
// #define SW_LOGICAL_CHANNEL_NOT_SUPPORTED  0x6881
// #define SW_SECURE_MESSAGING_NOT_SUPPORTED 0x6882
// #define SW_COMMAND_CHAINING_NOT_SUPPORTED 0x6884
// #define SW_SM_DATA_MISSING                0x6987
// #define SW_SM_DATA_INCORRECT              0x6988
#define SW_STATE_TERMINATED              0x6285
#define SW_PWD_NOT_CHECKED               0x63c0
#define SW_MEMORY_FAILURE                0x6581
#define SW_SECURITY_UIF_ISSUE            0x6600
#define SW_WRONG_LENGTH                  0x6700
#define SW_LAST_COMMAND_CHAIN_EXPECTED   0x6883
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define SW_PIN_BLOCKED                   0x6983
#define SW_CONDITIONS_NOT_SATISFIED      0x6985
#define SW_WRONG_DATA                    0x6a80
#define SW_FILE_NOT_FOUND                0x6a82
#define SW_REFERENCED_DATA_NOT_FOUND     0x6a88
#define SW_WRONG_P1P2                    0x6b00
#define SW_INS_NOT_SUPPORTED             0x6d00
#define SW_CLA_NOT_SUPPORTED             0x6e00
#define SW_UNKNOWN                       0x6f00
#define SW_CORRECT_BYTES_AVAILABLE       0x6100
#define SW_OK                            0x9000

/* ---  P1/P2 constants  --- */
#define GEN_ASYM_KEY          0x8000
#define SEEDED_MODE           0x01
#define GEN_ASYM_KEY_SEED     (GEN_ASYM_KEY | SEEDED_MODE)
#define READ_ASYM_KEY         0x8100
#define PSO_CDS               0x9e9a
#define PSO_DEC               0x8086
#define PSO_ENC               0x8680
#define MSE_SET               0x41
#define GET_RESPONSE          0x00
#define PIN_NOT_VERIFIED      0xFF
#define PIN_VERIFY            0x00
#define SELECT_MAX_INSTANCE   0x02
#define SELECT_SKIP           0x04
#define RESET_RETRY_WITH_PW3  0x02
#define RESET_RETRY_WITH_CODE 0x00
#define PRIME_MODE            0x02
#define CHALLENGE_NOMINAL     0x00

/* ---  Keys constants  --- */
#define KEY_SIG 0xb6
#define KEY_DEC 0xb8
#define KEY_AUT 0xa4
#define KEY_NB  3

/* ---  Padding indicators  --- */
#define PAD_RSA  0x00
#define PAD_AES  0x02
#define PAD_ECDH 0xa6

#endif
