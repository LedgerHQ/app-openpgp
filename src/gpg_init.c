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

#include "os.h"
#include "cx.h"
#include "gpg_types.h"
#include "gpg_api.h"
#include "gpg_vars.h"
#include "usbd_impl.h"

#define SHORT(x) ((x) >> 8) & 0xFF, (x)&0xFF
/* ----------------------*/
/* -- A Kind of Magic -- */
/* ----------------------*/

const unsigned char C_MAGIC[8] = {'G', 'P', 'G', 'C', 'A', 'R', 'D', '3'};
/* ----------------------*/
/* --ECC OID -- */
/* ----------------------*/

// secp256r1 / NIST P256 /ansi-x9.62 : 1.2.840.10045.3.1.7
const unsigned char C_OID_SECP256R1[8] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
/*
//secp384r1 / NIST P384 /ansi-x9.62 :1.3.132.0.34
const unsigned char C_OID_SECP384R1[5] = {
  0x2B, 0x81, 0x04, 0x00 , 0x22
};
//secp521r1 / NIST P521 /ansi-x9.62 : 1.3.132.0.35
const unsigned char C_OID_SECP521R1[5] = {
  0x2B, 0x81, 0x04, 0x00, 0x23
};

//secp256k1: 1.3.132.0.10
const unsigned char C_OID_SECP256K1[5] = {
  0x2B, 0x81, 0x04, 0x00, 0x0A
};
*/

/*
//brainpool 256t1: 1.3.36.3.3.2.8.1.1.8
const unsigned char C_OID_BRAINPOOL256T1[9] = {
  0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07
};
//brainpool 256r1: 1.3.36.3.3.2.8.1.1.7
const unsigned char C_OID_BRAINPOOL256R1[9] = {
  0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08
};
//brainpool 284r1: 1.3.36.3.3.2.8.1.1.11
const unsigned char C_OID_BRAINPOOL384R1[9] = {
   0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
};
//brainpool 512r1: 1.3.36.3.3.2.8.1.1.13
const unsigned char C_OID_BRAINPOOL512R1[9] = {
  0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D
};
*/

// Ed25519/curve25519: 1.3.6.1.4.1.11591.15.1
const unsigned char C_OID_Ed25519[9] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
};

// Ed25519/curve25519: 1.3.6.1.4.1.11591.15.1
const unsigned char C_OID_cv25519[10] = {
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
};

unsigned int gpg_oid2curve(unsigned char *oid, unsigned int len) {
  if ((len == sizeof(C_OID_SECP256R1)) && (os_memcmp(oid, C_OID_SECP256R1, len) == 0)) {
    return CX_CURVE_SECP256R1;
  }
  /*
  if ( (len == sizeof(C_OID_SECP256K1)) && (os_memcmp(oid, C_OID_SECP256K1, len)==0) ) {
    return CX_CURVE_SECP256K1;
  }

  if ( (len == sizeof(C_OID_SECP384R1)) && (os_memcmp(oid, C_OID_SECP384R1, len)==0) ) {
    return CX_CURVE_SECP384R1;
  }
  if ( (len == sizeof(C_OID_SECP521R1)) && (os_memcmp(oid, C_OID_SECP521R1, len)==0) ) {
    return CX_CURVE_SECP521R1;
  }
 */

  /*
  if ( (len == sizeof(C_OID_BRAINPOOL256R1)) && (os_memcmp(oid, C_OID_BRAINPOOL256R1, len)==0) ) {
    return CX_CURVE_BrainPoolP256R1;
  }
  if ( (len == sizeof(C_OID_BRAINPOOL384R1)) && (os_memcmp(oid, C_OID_BRAINPOOL384R1, len)==0) ) {
    return CX_CURVE_BrainPoolP384R1;
  }
  if ( (len == sizeof(C_OID_BRAINPOOL512R1)) && (os_memcmp(oid, C_OID_BRAINPOOL512R1, len)==0) ) {
    return CX_CURVE_BrainPoolP512R1;
  }
 */
  if ((len == sizeof(C_OID_Ed25519)) && (os_memcmp(oid, C_OID_Ed25519, len) == 0)) {
    return CX_CURVE_Ed25519;
  }

  if ((len == sizeof(C_OID_cv25519)) && (os_memcmp(oid, C_OID_cv25519, len) == 0)) {
    return CX_CURVE_Curve25519;
  }

  /*
  if ( (len == sizeof(C_OID_SECP256K1)) && (os_memcmp(oid, C_OID_SECP256K1, len)==0) ) {
    return CX_CURVE_256K1;
  }
  if ( (len == sizeof(C_OID_BRAINPOOL256T1)) && (os_memcmp(oid, C_OID_BRAINPOOL256T1, len)==0) ) {
    return CX_CURVE_BrainPoolP256T1;
  }
  */
  return CX_CURVE_NONE;
}

unsigned char *gpg_curve2oid(unsigned int cv, unsigned int *len) {
  switch (cv) {
  case CX_CURVE_SECP256R1:
    *len = sizeof(C_OID_SECP256R1);
    return (unsigned char *)PIC(C_OID_SECP256R1);

  /*
  case CX_CURVE_SECP256K1:
    *len = sizeof(C_OID_SECP256K1);
    return   (unsigned char*)PIC(C_OID_SECP256K1);

  case CX_CURVE_SECP384R1:
    *len = sizeof(C_OID_SECP384R1);
    return   (unsigned char*)PIC(C_OID_SECP384R1);

  case CX_CURVE_SECP521R1:
    *len = sizeof(C_OID_SECP521R1);
    return   (unsigned char*)PIC(C_OID_SECP521R1);
  */

  /*
  case CX_CURVE_BrainPoolP256R1:
    *len = sizeof(C_OID_SECP256R1);
    return   (unsigned char*)PIC(C_OID_SECP256R1);

  case CX_CURVE_BrainPoolP384R1:
    *len = sizeof(C_OID_SECP384R1);
    return   (unsigned char*)PIC(C_OID_SECP384R1);

  case CX_CURVE_BrainPoolP512R1:
    *len = sizeof(C_OID_SECP521R1);
    return   (unsigned char*)PIC(C_OID_SECP521R1);
  */
  case CX_CURVE_Ed25519:
    *len = sizeof(C_OID_Ed25519);
    return (unsigned char *)PIC(C_OID_Ed25519);

  case CX_CURVE_Curve25519:
    *len = sizeof(C_OID_cv25519);
    return (unsigned char *)PIC(C_OID_cv25519);
  }

  *len = 0;
  return NULL;
}

unsigned int gpg_curve2domainlen(unsigned int cv) {
  switch (cv) {
  case CX_CURVE_SECP256R1:
  case CX_CURVE_Ed25519:
  case CX_CURVE_Curve25519:
    return 32;
  }
  return 0;
}

/* -------------------------------*/
/* -- Non Mutable Capabilities -- */
/* -------------------------------*/

const unsigned char C_ext_capabilities[10] = {
    //-SM, +getchallenge, +keyimport, +PWchangeable, +privateDO, +algAttrChangeable, +AES, -KDF
    0x7E,
    // No SM,
    0x00,
    // max challenge
    SHORT(GPG_EXT_CHALLENGE_LENTH),
    // max cert holder length
    SHORT(GPG_EXT_CARD_HOLDER_CERT_LENTH),
    // maximum do length
    SHORT(GPG_EXT_PRIVATE_DO_LENGTH),
    // PIN block formart 2 not supported
    0x00,
    // MSE
    0x01

};

const unsigned char C_ext_length[8] = {0x02, 0x02, SHORT(GPG_APDU_LENGTH), 0x02, 0x02, SHORT(GPG_APDU_LENGTH)};

/* ---------------------*/
/* -- default values -- */
/* ---------------------*/

const unsigned char C_default_AID[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
                                       // version
                                       0x03, 0x03,
                                       // manufacturer
                                       0x2C, 0x97,
                                       // serial
                                       0x00, 0x00, 0x00, 0x00,
                                       // RFU
                                       0x00, 0x00};

const unsigned char C_default_Histo[] = {0x00, 0x31,
                                         0xC5, // select method: by DF/partialDF; IO-file:readbinary; RFU???
                                         0x73,
                                         0xC0, // select method: by DF/partialDF ,
                                         0x01, // data coding style: ontime/byte
                                         0x80, // chaining
                                         0x7F, // zero state
                                         0x90, 0x00};

// Default template: RSA2048 010800002001 / 010800002001
#if 1
const unsigned char C_default_AlgoAttr_sig[] = {
    // RSA
    0x01,
    // Modulus default length 2048
    0x08, 0x00,
    // PubExp length  32
    0x00, 0x20,
    // std: e,p,q with modulus (n)
    0x01};
const unsigned char C_default_AlgoAttr_dec[] = {
    // RSA
    0x01,
    // Modulus default length 2048
    0x08, 0x00,
    // PubExp length  32
    0x00, 0x20,
    // std: e,p,q with modulus (n)
    0x01};
#endif

// Default template: NIST P256 132A8648CE3D030107 / 122A8648CE3D030107
#if 0
const unsigned char C_default_AlgoAttr_sig[]   = {
  // ecdsa
  0x13,
  // NIST-P256
  0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07
};
const unsigned char C_default_AlgoAttr_dec[]   = {
  // ecdh
  0x12,
  // NIST-P256
  0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07
};
#endif

// Default template: Ed/Cv-25519 162B06010401DA470F01 / 122B060104019755010501
#if 0
const unsigned char C_default_AlgoAttr_sig[]   = {
  // eddsa
  0x16,
  // ed25519
  0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
};
const unsigned char C_default_AlgoAttr_dec[]   = {
  // ecdh
  0x12,
  //cv25519
   0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
};
#endif

// sha256 0x3132343536
const unsigned char C_sha256_PW1[] = {
    0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf,
    0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92, 0x3a, 0xdc, 0x6c, 0x92,
};
// sha256 0x31323435363738
const unsigned char C_sha256_PW2[] = {
    0xef, 0x79, 0x7c, 0x81, 0x18, 0xf0, 0x2d, 0xfb, 0x64, 0x96, 0x07, 0xdd, 0x5d, 0x3f, 0x8c, 0x76,
    0x23, 0x04, 0x8c, 0x9c, 0x06, 0x3d, 0x53, 0x2c, 0xc9, 0x5c, 0x5e, 0xd7, 0xa8, 0x98, 0xa6, 0x4f,
};

/* ----------------------------------------------------------------------- */
/* --- boot init                                                       --- */
/* ----------------------------------------------------------------------- */

void gpg_init() {
  os_memset(&G_gpg_vstate, 0, sizeof(gpg_v_state_t));
  // first init ?
  if (os_memcmp((void *)(N_gpg_pstate->magic), (void *)C_MAGIC, sizeof(C_MAGIC)) != 0) {
    gpg_install(STATE_ACTIVATE);
    gpg_nvm_write((void *)(N_gpg_pstate->magic), (void *)C_MAGIC, sizeof(C_MAGIC));
    os_memset(&G_gpg_vstate, 0, sizeof(gpg_v_state_t));
  }

  // key conf
  G_gpg_vstate.slot  = N_gpg_pstate->config_slot[1];
  G_gpg_vstate.kslot = &N_gpg_pstate->keys[G_gpg_vstate.slot];
  gpg_mse_reset();
  // pin conf
  G_gpg_vstate.pinmode = N_gpg_pstate->config_pin[0];
  // ux conf
  gpg_init_ux();
}

void gpg_init_ux() {
  G_gpg_vstate.ux_type = -1;
  G_gpg_vstate.ux_key  = -1;
}

/* ----------------------------------------------------------------------- */
/* ---  Install/ReInstall GPGapp                                       --- */
/* ----------------------------------------------------------------------- */
void gpg_install_slot(gpg_key_slot_t *slot) {
  unsigned char tmp[4];
  unsigned int l;

  gpg_nvm_write(slot, 0, sizeof(gpg_key_slot_t));

  cx_rng(tmp, 4);
  gpg_nvm_write((void *)(slot->serial), tmp, 4);

  l      = sizeof(C_default_AlgoAttr_sig);
  gpg_nvm_write((void *)(&slot->sig.attributes.value), (void *)C_default_AlgoAttr_sig, l);
  gpg_nvm_write((void *)(&slot->sig.attributes.length), &l, sizeof(unsigned int));
  gpg_nvm_write((void *)(&slot->aut.attributes.value), (void *)C_default_AlgoAttr_sig, l);
  gpg_nvm_write((void *)(&slot->aut.attributes.length), &l, sizeof(unsigned int));

  l = sizeof(C_default_AlgoAttr_dec);
  gpg_nvm_write((void *)(&slot->dec.attributes.value), (void *)C_default_AlgoAttr_dec, l);
  gpg_nvm_write((void *)(&slot->dec.attributes.length), &l, sizeof(unsigned int));

  tmp[0] = 0x00;
  tmp[1] = 0x20;
  gpg_nvm_write((void *)(&slot->sig.UIF), &tmp, 2);
  gpg_nvm_write((void *)(&slot->dec.UIF), &tmp, 2);
  gpg_nvm_write((void *)(&slot->aut.UIF), &tmp, 2);
}

void gpg_install(unsigned char app_state) {
  gpg_pin_t    pin;

  // full reset data
  gpg_nvm_write((void *)(N_gpg_pstate), NULL, sizeof(gpg_nv_state_t));

  // historical bytes
  os_memmove(G_gpg_vstate.work.io_buffer, C_default_Histo, sizeof(C_default_Histo));
  G_gpg_vstate.work.io_buffer[7] = app_state;
  gpg_nvm_write((void *)(N_gpg_pstate->histo), G_gpg_vstate.work.io_buffer, sizeof(C_default_Histo));

  // AID
  os_memmove(G_gpg_vstate.work.io_buffer, C_default_AID, sizeof(C_default_AID));
  gpg_nvm_write((void *)(N_gpg_pstate->AID), &G_gpg_vstate.work.io_buffer, sizeof(C_default_AID));


  if (app_state == STATE_ACTIVATE) {
    // default sex: none
    G_gpg_vstate.work.io_buffer[0] = 0x39;
    gpg_nvm_write((void *)(&N_gpg_pstate->sex), G_gpg_vstate.work.io_buffer, 1);

    // default PW1/PW2: 1 2 3 4 5 6
    os_memmove(pin.value, C_sha256_PW1, sizeof(C_sha256_PW1));
    pin.length  = 6;
    pin.counter = 3;
    pin.ref     = PIN_ID_PW1;
    gpg_nvm_write((void *)(&N_gpg_pstate->PW1), &pin, sizeof(gpg_pin_t));

    // default PW3: 1 2 3 4 5 6 7 8
    os_memmove(pin.value, C_sha256_PW2, sizeof(C_sha256_PW2));
    pin.length  = 8;
    pin.counter = 3;
    pin.ref     = PIN_ID_PW3;
    gpg_nvm_write((void *)(&N_gpg_pstate->PW3), &pin, sizeof(gpg_pin_t));

    // PWs status
    G_gpg_vstate.work.io_buffer[0] = 1;
    G_gpg_vstate.work.io_buffer[1] = GPG_MAX_PW_LENGTH;
    G_gpg_vstate.work.io_buffer[2] = GPG_MAX_PW_LENGTH;
    G_gpg_vstate.work.io_buffer[3] = GPG_MAX_PW_LENGTH;
    gpg_nvm_write((void *)(&N_gpg_pstate->PW_status), G_gpg_vstate.work.io_buffer, 4);

    // config slot
    G_gpg_vstate.work.io_buffer[0] = GPG_KEYS_SLOTS;
    G_gpg_vstate.work.io_buffer[1] = 0;
    G_gpg_vstate.work.io_buffer[2] = 3; // 3: selection by APDU and screen
    gpg_nvm_write((void *)(&N_gpg_pstate->config_slot), G_gpg_vstate.work.io_buffer, 3);

    // config rsa pub
    G_gpg_vstate.work.io_buffer[0] = (GPG_RSA_DEFAULT_PUB >> 24) & 0xFF;
    G_gpg_vstate.work.io_buffer[1] = (GPG_RSA_DEFAULT_PUB >> 16) & 0xFF;
    G_gpg_vstate.work.io_buffer[2] = (GPG_RSA_DEFAULT_PUB >> 8) & 0xFF;
    G_gpg_vstate.work.io_buffer[3] = (GPG_RSA_DEFAULT_PUB >> 0) & 0xFF;
    nvm_write((void *)(&N_gpg_pstate->default_RSA_exponent), G_gpg_vstate.work.io_buffer, 4);

    // config pin
    G_gpg_vstate.work.io_buffer[0] = PIN_MODE_CONFIRM;
    gpg_nvm_write((void *)(&N_gpg_pstate->config_pin), G_gpg_vstate.work.io_buffer, 1);
    USBD_CCID_activate_pinpad(3);

    // default key template: RSA 2048)
    for (int s = 0; s < GPG_KEYS_SLOTS; s++) {
      gpg_install_slot(&N_gpg_pstate->keys[s]);
    }
  }
}

#define USBD_OFFSET_CfgDesc_bPINSupport (sizeof(USBD_CfgDesc) - 16)
void USBD_CCID_activate_pinpad(int enabled) {
#ifdef HAVE_USB_CLASS_CCID
  unsigned short length;
  uint8_t *      cfgDesc;
  unsigned char  e;
  e       = enabled ? 3 : 0;
  length  = 0;
  cfgDesc = USBD_GetCfgDesc_impl(&length);
  nvm_write(cfgDesc + (length - 16), &e, 1);
#endif
}
