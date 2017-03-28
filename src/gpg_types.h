/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GPG_TYPES_H
#define GPG_TYPES_H

/* cannot send more that F0 bytes in CCID, why? do not know for now
 *  So set up length to F0 minus 2 bytes for SW
 */
#define GPG_APDU_LENGTH                       0xFE


/* big private DO */
#define GPG_EXT_PRIVATE_DO_LENGTH             512
/* will be fixed..1024 is not enougth */
#define GPG_EXT_CARD_HOLDER_CERT_LENTH        2560
/* random choice */
#define GPG_EXT_CHALLENGE_LENTH               254
/* accpet long PW, but less than one sha256 block */
#define GPG_MAX_PW_LENGTH                     12

#define GPG_KEYS_SLOTS                        3

#define  GPG_KEY_ATTRIBUTES_LENGTH            12


struct gpg_pin_s {
  //initial pin length, 0 means not set
  unsigned int length;
  unsigned int counter;
  //only store sha256 of PIN/RC
  unsigned char value[32];
};
typedef struct gpg_pin_s gpg_pin_t;



#define  LV(name,maxlen)                          \
  struct  {                                       \
    unsigned int  length;                         \
    unsigned char value[maxlen];                  \
  } name

typedef struct gpg_lv_s {
    unsigned int  length;
    unsigned char value[];
} gpg_lv_t;

typedef struct gpg_key_s {
  /*  C1 C2 C3 */
  LV(attributes,GPG_KEY_ATTRIBUTES_LENGTH);
  /*  key value */
  union {
    cx_rsa_1024_private_key_t  rsa1024;
    cx_rsa_2048_private_key_t  rsa2048;
    cx_rsa_3072_private_key_t  rsa3072;
    cx_rsa_4096_private_key_t  rsa4096;
    cx_ecfp_private_key_t      ecfp256;
  } key;
  union {
    unsigned char             rsa[4];
    cx_ecfp_public_key_t      ecfp256;
  } pub_key;
  /* C7 C8 C9 , C5 = C7|C8|C9*/
  unsigned char fingerprints[20];
  /* 7F21 */
  LV(CA,GPG_EXT_CARD_HOLDER_CERT_LENTH);
  /* C7 C8 C9, C6 = C7|C8|C9*/
  unsigned char CA_fingerprints[20];
   /* CE CF D0, CD = CE|CF|D0 */
  unsigned char date[4];
  /* D6/D7/D8- */
  unsigned char UIF[2];



} gpg_key_t;


typedef struct gpg_key_slot_s{
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

  /* 01F1 (01F2 is volatile)*/
  unsigned char config_slot[3];

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
  LV(name,39);
  /*  5F2D */
  LV(lang, 8);
  /*  5F35 */
  unsigned char sex[1];

  /* -- Application  Related Data -- */
   /*  4F */
  unsigned char AID[16];
  /*  5F52 */
  unsigned char histo[15];
  /*  7f66 */
  //unsigned char ext_length_info[8];
  /*  C0   */
  //unsigned char ext_capabilities[10];

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
} ;

typedef struct gpg_nv_state_s gpg_nv_state_t;

#define GPG_IO_BUFFER_LENGTH (1512)

struct gpg_v_state_s {
  /* app state */
  unsigned char   selected;
  unsigned char   slot; /* DO 01F2 */
  gpg_key_slot_t *kslot;
  unsigned char   seed_mode;

  /* io state*/
  unsigned char   io_cla;
  unsigned char   io_ins;
  unsigned char   io_p1;
  unsigned char   io_p2;
  unsigned char   io_lc;
  unsigned char   io_le;
  unsigned short  io_length;
  unsigned short  io_offset;
  unsigned short  io_mark;
  unsigned short  io_flags;
  union {
    unsigned char io_buffer[GPG_IO_BUFFER_LENGTH];
    struct {
      cx_rsa_1024_public_key_t public;
      cx_rsa_1024_private_key_t private;
    }rsa1024;
    struct {
      cx_rsa_2048_public_key_t public;
      cx_rsa_2048_private_key_t private;
    }rsa2048;
    struct {
      cx_rsa_3072_public_key_t public;
      cx_rsa_3072_private_key_t private;
    }rsa3072;
    struct {
      cx_rsa_4096_public_key_t public;
      cx_rsa_4096_private_key_t private;
    }rsa4096;
    struct {
      cx_ecfp_public_key_t public;
      cx_ecfp_private_key_t private;
    }ecfp256;
    struct {
      unsigned char md_buffer[GPG_IO_BUFFER_LENGTH-MAX(sizeof(cx_sha3_t),sizeof(cx_sha256_t))];
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


  /* ux menus */
  char          menu[64];
  unsigned int  ux_key;
  unsigned int  ux_type;


#ifdef GPG_DEBUG
  unsigned char print;
#endif
} ;
typedef struct  gpg_v_state_s gpg_v_state_t;

/* ---  Errors  --- */

#define ERROR(x)                            ((x)<<16)

#define ERROR_IO_OFFSET                     ERROR(1)
#define ERROR_IO_FULL                       ERROR(2)

/* ---  IDentifiers  --- */

#define ID_PW1                              1
#define ID_PW2                              2
#define ID_PW3                              3
#define ID_RC                               4

#define ID_AUTH                             1
#define ID_DEC                              2
#define ID_SIG                              3


#define STATE_ACTIVATE                      0x07
#define STATE_TERMINATE                     0x03

#define IO_OFFSET_END                       (unsigned int)-1
#define IO_OFFSET_MARK                      (unsigned int)-2


/* ---  INS  --- */
#define    INS_SELECT                       0xa4
#define    INS_TERMINATE_DF                 0xe6
#define    INS_ACTIVATE_FILE                0x44

#define    INS_SELECT_DATA                  0xa5
#define    INS_GET_DATA                     0xca
#define    INS_GET_NEXT_DATA                0xcc
#define    INS_PUT_DATA                     0xda
#define    INS_PUT_DATA_ODD                 0xdb

#define    INS_VERIFY                       0x20
#define    INS_CHANGE_REFERENCE_DATA        0x24
#define    INS_RESET_RETRY_COUNTER          0x2c

#define    INS_GEN_ASYM_KEYPAIR             0x47
#define    INS_PSO                          0x2a
//#define  INS_COMPUTEDIGSIG                0x2a
//#define  INS_DECIPHER                     0x2a
#define    INS_INTERNAL_AUTHENTICATE        0x88

#define    INS_GET_CHALLENGE                0x84
#define    INS_GET_RESPONSE                 0xc0


/* ---  IO constants  --- */
#define OFFSET_CLA                          0
#define OFFSET_INS                          1
#define OFFSET_P1                           2
#define OFFSET_P2                           3
#define OFFSET_P3                           4
#define OFFSET_CDATA                        5
#define OFFSET_EXT_CDATA                    7


#define SW_OK                               0x9000
#define SW_ALGORITHM_UNSUPPORTED            0x9484

#define SW_BYTES_REMAINING_00               0x6100

#define SW_WARNING_STATE_UNCHANGED          0x6200
#define SW_STATE_TERMINATED                 0x6285

#define SW_MORE_DATA_AVAILABLE              0x6310

#define SW_WRONG_LENGTH                     0x6700

#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED    0x6881
#define SW_SECURE_MESSAGING_NOT_SUPPORTED   0x6882
#define SW_LAST_COMMAND_EXPECTED            0x6883
#define SW_COMMAND_CHAINING_NOT_SUPPORTED   0x6884

#define SW_SECURITY_STATUS_NOT_SATISFIED    0x6982
#define SW_FILE_INVALID                     0x6983
#define SW_PIN_BLOCKED                      0x6983
#define SW_DATA_INVALID                     0x6984
#define SW_CONDITIONS_NOT_SATISFIED         0x6985
#define SW_COMMAND_NOT_ALLOWED              0x6986
#define SW_APPLET_SELECT_FAILED             0x6999

#define SW_WRONG_DATA                       0x6a80
#define SW_FUNC_NOT_SUPPORTED               0x6a81
#define SW_FILE_NOT_FOUND                   0x6a82
#define SW_RECORD_NOT_FOUND                 0x6a83
#define SW_FILE_FULL                        0x6a84
#define SW_INCORRECT_P1P2                   0x6a86
#define SW_REFERENCED_DATA_NOT_FOUND        0x6a88

#define SW_WRONG_P1P2                       0x6b00
#define SW_CORRECT_LENGTH_00                0x6c00
#define SW_INS_NOT_SUPPORTED                0x6d00
#define SW_CLA_NOT_SUPPORTED                0x6e00

#define SW_UNKNOWN                          0x6f00


#endif
