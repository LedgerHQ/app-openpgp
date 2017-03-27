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

int gpg_apdu_select_data(unsigned  int ref, int reccord) {
  G_gpg_vstate.DO_current  = ref;
  G_gpg_vstate.DO_reccord  = reccord;
  G_gpg_vstate.DO_offset   = 0;
  return SW_OK;
}

int gpg_apdu_get_data(unsigned int ref)  {
  int sw;


  if (G_gpg_vstate.DO_current != ref) {
    G_gpg_vstate.DO_current = ref;
    G_gpg_vstate.DO_reccord = 0;
    G_gpg_vstate.DO_offset = 0;
  }
  sw = SW_OK;

  gpg_io_discard(1);
  switch (ref) {
    /* ----------------- Optional DO for private use ----------------- */
  case 0x0101:
    gpg_io_insert(N_gpg_pstate->private_DO1.value, N_gpg_pstate->private_DO1.length);
    break;
  case 0x0102:
    gpg_io_insert(N_gpg_pstate->private_DO2.value, N_gpg_pstate->private_DO2.length);
    break;
  case 0x0103:
    gpg_io_insert(N_gpg_pstate->private_DO3.value, N_gpg_pstate->private_DO3.length);
    break;
  case 0x0104:
    gpg_io_insert(N_gpg_pstate->private_DO4.value, N_gpg_pstate->private_DO4.length);
    break;

      /* ----------------- Config key slot ----------------- */
  case 0x01F0:
    gpg_io_insert(N_gpg_pstate->config_slot, 3);
    gpg_io_insert_u8(G_gpg_vstate.slot);
    break; 
  case 0x01F1:
    gpg_io_insert(N_gpg_pstate->config_slot, 3);
    break;
  case 0x01F2:
    gpg_io_insert_u8(G_gpg_vstate.slot);
    break;

   /* ----------------- Application ----------------- */
    /*  Full Application identifier  */
  case 0x004F:
    gpg_io_insert(N_gpg_pstate->AID, 16);
    break;
    /* Historical bytes, */
  case 0x5F52:
    gpg_io_insert(N_gpg_pstate->histo, 15);
    break;
    /* Extended length information */
  case 0x7F66:
    gpg_io_insert(C_ext_length, sizeof(C_ext_length));
    break;

    /* ----------------- User -----------------*/
    /* Login data */
  case 0x005E:
    gpg_io_insert(N_gpg_pstate->login.value, N_gpg_pstate->login.length);
    break;
    /* Uniform resource locator */
  case 0x5F50:
    gpg_io_insert(N_gpg_pstate->url.value, N_gpg_pstate->url.length);
    break;
    /* Name, Language, Sex */
  case 0x65:
    gpg_io_insert_tlv(0x5B,   N_gpg_pstate->name.length, N_gpg_pstate->name.value);
    gpg_io_insert_tlv(0x5F2D, N_gpg_pstate->lang.length, N_gpg_pstate->lang.value);
    gpg_io_insert_tlv(0x5F35, 1,                     N_gpg_pstate->sex);
    break;

    /* ----------------- aid, histo, ext_length, ... ----------------- */
  case 0x6E:
    gpg_io_insert_tlv(0x4F,   16, N_gpg_pstate->AID);
    gpg_io_insert_tlv(0x5F52, 15, N_gpg_pstate->histo);
    gpg_io_insert_tlv(0x7F66, sizeof(C_ext_length), C_ext_length);

    gpg_io_mark();

    gpg_io_insert_tlv(0xC0,
                      sizeof(C_ext_capabilities),
                      C_ext_capabilities);
    gpg_io_insert_tlv(0xC1, G_gpg_vstate.kslot->sig.attributes.length, G_gpg_vstate.kslot->sig.attributes.value);
    gpg_io_insert_tlv(0xC2, G_gpg_vstate.kslot->dec.attributes.length, G_gpg_vstate.kslot->dec.attributes.value);
    gpg_io_insert_tlv(0xC3, G_gpg_vstate.kslot->aut.attributes.length, G_gpg_vstate.kslot->aut.attributes.value);
    gpg_io_insert_tl(0xC4, 7);
    gpg_io_insert(N_gpg_pstate->PW_status,4);
    gpg_io_insert_u8(N_gpg_pstate->PW1.counter);
    gpg_io_insert_u8(N_gpg_pstate->RC.counter);
    gpg_io_insert_u8(N_gpg_pstate->PW3.counter);
    gpg_io_insert_tl(0xC5, 60);
    gpg_io_insert(G_gpg_vstate.kslot->sig.fingerprints, 20);
    gpg_io_insert(G_gpg_vstate.kslot->dec.fingerprints, 20);
    gpg_io_insert(G_gpg_vstate.kslot->aut.fingerprints, 20);
    gpg_io_insert_tl(0xC6, 60);
    gpg_io_insert(G_gpg_vstate.kslot->sig.CA_fingerprints, 20);
    gpg_io_insert(G_gpg_vstate.kslot->dec.CA_fingerprints, 20);
    gpg_io_insert(G_gpg_vstate.kslot->aut.CA_fingerprints, 20);
    gpg_io_insert_tl(0xCD, 12);
    gpg_io_insert(G_gpg_vstate.kslot->sig.date, 4);
    gpg_io_insert(G_gpg_vstate.kslot->dec.date, 4);
    gpg_io_insert(G_gpg_vstate.kslot->aut.date, 4);
    gpg_io_set_offset(IO_OFFSET_MARK);
    gpg_io_insert_tl(0x73, G_gpg_vstate.io_length- G_gpg_vstate.io_offset);
    gpg_io_set_offset(IO_OFFSET_END);
    break;

    /* ----------------- User Interaction Flag (UIF) for PSO:CDS ----------------- */
  case 0x00D6:
    gpg_io_insert(G_gpg_vstate.kslot->sig.UIF, 2);
    break;
  case 0x00D7:
    gpg_io_insert(G_gpg_vstate.kslot->dec.UIF, 2);
    break;
  case 0x00D8:
    gpg_io_insert(G_gpg_vstate.kslot->aut.UIF, 2);
    break;

    /* ----------------- Security support template ----------------- */
  case 0x7A:
    gpg_io_insert_tl(0x93,3);
    gpg_io_insert_u24(G_gpg_vstate.kslot->sig_count);
    break;

    /* ----------------- Cardholder certificate ----------------- */
  case 0x7F21:
    switch (G_gpg_vstate.DO_reccord) {
    case 0:
      gpg_io_insert(G_gpg_vstate.kslot->aut.CA.value,G_gpg_vstate.kslot->aut.CA.length);
      break;
    case 1:
      gpg_io_insert(G_gpg_vstate.kslot->dec.CA.value,G_gpg_vstate.kslot->dec.CA.length);
      break;
    case 2:
      gpg_io_insert(G_gpg_vstate.kslot->sig.CA.value,G_gpg_vstate.kslot->sig.CA.length);
      break;
    default :
      sw = SW_RECORD_NOT_FOUND;
    }
    break;

    /* ----------------- PW Status Bytes ----------------- */
  case 0x00C4:
    gpg_io_insert(N_gpg_pstate->PW_status,4);
    gpg_io_insert_u8(N_gpg_pstate->PW1.counter);
    gpg_io_insert_u8(N_gpg_pstate->RC.counter);
    gpg_io_insert_u8(N_gpg_pstate->PW3.counter);
    break;

    /* WAT */
  default:
    sw = SW_REFERENCED_DATA_NOT_FOUND;
    break;
  }

  return sw;
}

int gpg_apdu_get_next_data(unsigned int ref)  {
  int sw;

  if ((ref != 0x7F21) || (G_gpg_vstate.DO_current != 0x7F21)) {
    return SW_CONDITIONS_NOT_SATISFIED;
  }
  sw = gpg_apdu_get_data(ref);
  if (sw == SW_OK) {
    G_gpg_vstate.DO_reccord++;
  }
  return sw;
}

int gpg_apdu_put_data(unsigned int ref) {
  unsigned int   t,l,sw;
  unsigned int   *ptr_l;
  unsigned char  *ptr_v;

  G_gpg_vstate.DO_current = ref;
  sw = SW_OK;

  switch (ref) {
     /*  ----------------- Optional DO for private use ----------------- */
  case 0x0101:
    ptr_l = &N_gpg_pstate->private_DO1.length;
    ptr_v = N_gpg_pstate->private_DO1.value;
    goto WRITE_PRIVATE_DO;
  case 0x0102:
    ptr_l = &N_gpg_pstate->private_DO2.length;
    ptr_v = N_gpg_pstate->private_DO2.value;
    goto WRITE_PRIVATE_DO;
  case 0x0103:
    ptr_l = &N_gpg_pstate->private_DO3.length;
    ptr_v = N_gpg_pstate->private_DO3.value;
    goto WRITE_PRIVATE_DO;
  case 0x0104:
    ptr_l = &N_gpg_pstate->private_DO4.length;
    ptr_v = N_gpg_pstate->private_DO4.value;
    goto WRITE_PRIVATE_DO;
  WRITE_PRIVATE_DO:
    if (G_gpg_vstate.io_length > GPG_EXT_PRIVATE_DO_LENGTH) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;
    /*  ----------------- Config key slot ----------------- */
  case 0x01F1:
    if (G_gpg_vstate.io_length != 3) {
      THROW(SW_WRONG_LENGTH);
    }
    if ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset +0] != GPG_KEYS_SLOTS) ||
        (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset +1] >= GPG_KEYS_SLOTS) ||
        (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset +2] >  3)) {
       THROW(SW_WRONG_DATA);
    }
    gpg_nvm_write(N_gpg_pstate->config_slot, G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,3);
    sw = SW_OK;
    break;
  
  case 0x01F2:
    if ((N_gpg_pstate->config_slot[2] & 2) == 0) {
      THROW(SW_CONDITIONS_NOT_SATISFIED);
    }  
    if ((G_gpg_vstate.io_length != 1) || 
        (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset] >= GPG_KEYS_SLOTS))  {
       THROW(SW_WRONG_DATA);
    }
    G_gpg_vstate.slot = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];

    sw = SW_OK;
    break;

    /* ----------------- Serial -----------------*/
  case 0x4f:
    if (G_gpg_vstate.io_length != 4) {
      THROW(SW_WRONG_LENGTH);
    }
    nvm_write(&N_gpg_pstate->AID[10], &G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset], 4);
    sw = SW_OK;
    break;

    /* ----------------- Extended Header list -----------------*/
  case 0x3FFF: {
    void          *pkey,*vkey;
    unsigned int  len_e,len_p,len_q;
    unsigned int  endof,ksz,reset_cnt;
    gpg_key_t     *keygpg;
    unsigned int  dh;
    //fecth 4D
    gpg_io_fetch_tl(&t,&l);
    if (t!=0x4D) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
    }
    //fecth B8/B6/A4
    gpg_io_fetch_tl(&t,&l);
    dh = 0;
    reset_cnt = 0;
    switch(t) {
    case 0xB6:
      keygpg  = &G_gpg_vstate.kslot->sig;
      reset_cnt = 0x11111111;
      break;
    case 0xA4:
      keygpg  = &G_gpg_vstate.kslot->aut;
      break;
    case 0xB8:
      keygpg  = &G_gpg_vstate.kslot->dec;
      dh = 0x11;
      break;
    default:
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
    }
    //fecth 7f78
    gpg_io_fetch_tl(&t,&l);
    if (t!=0x7f48) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
    }
    len_e = 0; len_p = 0; len_q = 0;
    endof = G_gpg_vstate.io_offset+l;
    while (G_gpg_vstate.io_offset<endof) {
      gpg_io_fetch_tl(&t,&l);
      switch (t) {
      case 0x91:
        len_e = l;
        break;
      case 0x92:
        len_p = l;
        break;
      case 0x93:
        len_q = l;
        break;
        break;
      case 0x94:
      case 0x95:
      case 0x96:
      case 0x97:
        break;
      default:
        THROW(SW_REFERENCED_DATA_NOT_FOUND);
      }
    }
    //fecth 5f78
    gpg_io_fetch_tl(&t,&l);
    if (t!=0x5f48) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
    }

    // --- RSA KEY ---
    if (keygpg->attributes.value[0] == 0x01) {
      unsigned int         e;
      unsigned char        *p,*q,*pq;
      cx_rsa_public_key_t  *rsa_pub;
      cx_rsa_private_key_t *rsa_priv, *pkey;
      unsigned int         pkey_size;
      //check length
      ksz = (keygpg->attributes.value[1]<<8)|keygpg->attributes.value[2];
      ksz = ksz >> 3;
      switch(ksz) {
      case 1024/8:
        rsa_pub   = (cx_rsa_public_key_t*)&G_gpg_vstate.work.rsa1024.public;
        rsa_priv  = (cx_rsa_private_key_t*)&G_gpg_vstate.work.rsa1024.private; 
        pkey      = (cx_rsa_private_key_t*)&keygpg->key.rsa1024;
        pkey_size = sizeof(cx_rsa_1024_private_key_t);
        break;
      case 2048/8:
        rsa_pub   = (cx_rsa_public_key_t*)&G_gpg_vstate.work.rsa2048.public;
        rsa_priv  = (cx_rsa_private_key_t*)&G_gpg_vstate.work.rsa2048.private;
        pkey      = (cx_rsa_private_key_t*)&keygpg->key.rsa2048;
        pkey_size = sizeof(cx_rsa_2048_private_key_t);
        break;
      case 3072/8:
        rsa_pub   = (cx_rsa_public_key_t*)&G_gpg_vstate.work.rsa3072.public;
        rsa_priv  = (cx_rsa_private_key_t*)&G_gpg_vstate.work.rsa3072.private;
        pkey      = (cx_rsa_private_key_t*)&keygpg->key.rsa3072;
        pkey_size = sizeof(cx_rsa_3072_private_key_t);
        break;
      case 4096/8:
        rsa_pub   = (cx_rsa_public_key_t*)&G_gpg_vstate.work.rsa4096.public;
        rsa_priv  = (cx_rsa_private_key_t*)&G_gpg_vstate.work.rsa4096.private;
        pkey      = (cx_rsa_private_key_t*)&keygpg->key.rsa4096;
        pkey_size = sizeof(cx_rsa_4096_private_key_t);
        break;
      }
      ksz = ksz>>1;
      if ( (len_e>4)||(len_e==0)      ||
           (len_p > ksz )||
           (len_q > ksz)) {
        THROW(SW_WRONG_DATA);
      }
             
      //fetch e
      e = 0;
      switch(len_e) {
      case 4:
        e = (e<<8) | gpg_io_fetch_u8();
      case 3:
        e = (e<<8) | gpg_io_fetch_u8();
      case 2:
        e = (e<<8) | gpg_io_fetch_u8();
       case 1:
        e = (e<<8) | gpg_io_fetch_u8();
      }

      //move p,q over pub key, this only work because adr<rsa_pub> < adr<p>
      p = G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset;
      q = p + len_p;
      pq = (unsigned char*)rsa_pub;

      os_memmove(pq+ksz-len_p,   p, len_p);
      os_memmove(pq+2*ksz-len_q, q, len_q);
      os_memset(pq,     0, ksz-len_p);
      os_memset(pq+ksz, 0, ksz-len_q);
      //regenerate RSA private key
      cx_rsa_generate_pair(ksz<<1, rsa_pub, rsa_priv, e, pq);

      //write keys
      nvm_write(&keygpg->pub_key.rsa, rsa_pub->e, 4);
      nvm_write(pkey, rsa_priv, pkey_size);
      if (reset_cnt) {
        reset_cnt = 0;
        nvm_write(&G_gpg_vstate.kslot->sig_count,&reset_cnt,sizeof(unsigned int));
      }
    }
    // --- ECC KEY ---
    else if ((keygpg->attributes.value[0] == 19) || 
             (keygpg->attributes.value[0] == 18) ||
             (keygpg->attributes.value[0] == 22) ) {
      unsigned int curve;

      ksz = 0;
      curve = gpg_oid2curve(&keygpg->attributes.value[1], keygpg->attributes.length-1);
      if (curve == 0) {
       THROW(SW_WRONG_DATA);
      }
      ksz = 32;
      if (ksz == 32) {
        G_gpg_vstate.work.ecfp256.private.curve = curve;
        G_gpg_vstate.work.ecfp256.private.d_len = ksz;
        os_memmove(G_gpg_vstate.work.ecfp256.private.d, G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,ksz);
        cx_ecfp_generate_pair(curve, &G_gpg_vstate.work.ecfp256.public, &G_gpg_vstate.work.ecfp256.private, 1);
        nvm_write(&keygpg->pub_key.ecfp256,  &G_gpg_vstate.work.ecfp256.public, sizeof(cx_ecfp_public_key_t));
        nvm_write(&keygpg->key.ecfp256,  &G_gpg_vstate.work.ecfp256.private, sizeof(cx_ecfp_private_key_t));
        if (reset_cnt) {
          reset_cnt = 0;
          nvm_write(&G_gpg_vstate.kslot->sig_count,&reset_cnt,sizeof(unsigned int));
        }
      }

    }
    // --- UNSUPPORTED KEY ---
    else {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
    }
    break;
  } //endof of 3fff


  /* ----------------- User -----------------*/
    /* Name */
  case 0x5B:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->name.value)) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(N_gpg_pstate->name.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(&N_gpg_pstate->name.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;
    /* Login data */
  case 0x5E:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->login.value)) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(N_gpg_pstate->login.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(&N_gpg_pstate->login.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;
        /* Language preferences */
  case 0x5F2D:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->lang.value)) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(N_gpg_pstate->lang.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(&N_gpg_pstate->lang.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;
    /* Sex */
  case 0x5F35:
    if (G_gpg_vstate.io_length != sizeof(N_gpg_pstate->sex)) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(N_gpg_pstate->sex, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    sw = SW_OK;
    break;
    /* Uniform resource locator */
  case 0x5F50:
   if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->url.value)) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(N_gpg_pstate->url.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(&N_gpg_pstate->url.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;

    /* ----------------- Cardholder certificate ----------------- */
  case 0x7F21:
   ptr_v = NULL;
   switch ( G_gpg_vstate.DO_reccord) {
   case 0:
     ptr_l = &G_gpg_vstate.kslot->aut.CA.length;
     ptr_v = G_gpg_vstate.kslot->aut.CA.value;
     goto WRITE_CA;
   case 1:
     ptr_l = &G_gpg_vstate.kslot->sig.CA.length;
     ptr_v = G_gpg_vstate.kslot->sig.CA.value;
     goto WRITE_CA;
   case 2:
    ptr_l = &G_gpg_vstate.kslot->dec.CA.length;
    ptr_v = G_gpg_vstate.kslot->dec.CA.value;
    goto WRITE_CA;
   default:
     sw = SW_REFERENCED_DATA_NOT_FOUND;
     break;
   }
   WRITE_CA:
     if (G_gpg_vstate.io_length > GPG_EXT_CARD_HOLDER_CERT_LENTH) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;

    /* ----------------- Algorithm attributes ----------------- */
  case 0xC1:
    ptr_l = &G_gpg_vstate.kslot->sig.attributes.length;
    ptr_v = G_gpg_vstate.kslot->sig.attributes.value;
    goto WRITE_ATTRIBUTES;
  case 0xC2:
    ptr_l = &G_gpg_vstate.kslot->dec.attributes.length;
    ptr_v = G_gpg_vstate.kslot->dec.attributes.value;
    goto WRITE_ATTRIBUTES;
  case 0xC3:
    ptr_l = &G_gpg_vstate.kslot->aut.attributes.length;
    ptr_v = G_gpg_vstate.kslot->aut.attributes.value;
    goto WRITE_ATTRIBUTES;
  WRITE_ATTRIBUTES:
     if (G_gpg_vstate.io_length > 12) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;

    /* ----------------- PWS status ----------------- */
  case 0xC4:
    gpg_io_fetch_nv(N_gpg_pstate->PW_status, 1);
    break;

    /* ----------------- Fingerprints ----------------- */
  case 0xC7:
    ptr_v = G_gpg_vstate.kslot->sig.fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xC8:
    ptr_v = G_gpg_vstate.kslot->dec.fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xC9:
    ptr_v =G_gpg_vstate.kslot->aut.fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xCA:
    ptr_v = G_gpg_vstate.kslot->sig.CA_fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xCB:
    ptr_v = G_gpg_vstate.kslot->dec.CA_fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xCC:
    ptr_v = G_gpg_vstate.kslot->aut.CA_fingerprints;
    goto WRITE_FINGERPRINTS;
  WRITE_FINGERPRINTS:
    if (G_gpg_vstate.io_length != 20) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 20);
    sw = SW_OK;
    break;

    /* ----------------- Generation date/time ----------------- */
  case 0xCE:
    ptr_v = G_gpg_vstate.kslot->sig.date;
    goto WRITE_DATE;
  case 0xCF:
    ptr_v = G_gpg_vstate.kslot->dec.date;
    goto WRITE_DATE;
  case 0xD0:
    ptr_v = G_gpg_vstate.kslot->aut.date;
    goto WRITE_DATE;
  WRITE_DATE:
    if (G_gpg_vstate.io_length != 4) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 4);
    sw = SW_OK;
    break;

    /* ----------------- AES key ----------------- */
    {
    void           *pkey;
    cx_aes_key_t    aes_key;
  case 0xD1:
    pkey = &N_gpg_pstate->SM_enc;
    goto init_aes_key;
  case 0xD2:
    pkey = &N_gpg_pstate->SM_mac;
    goto init_aes_key;
  case 0xD5:
    pkey = &G_gpg_vstate.kslot->AES_dec;
    goto init_aes_key;
  init_aes_key:
    cx_aes_init_key(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length, &aes_key);
    gpg_nvm_write(pkey, &aes_key, sizeof(cx_aes_key_t));
    break;


    /* AES key: one shot */
  case 0xF4:
    cx_aes_init_key(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length, &aes_key);
    gpg_nvm_write(&N_gpg_pstate->SM_enc, &aes_key, sizeof(cx_aes_key_t));
    cx_aes_init_key(G_gpg_vstate.work.io_buffer+16, G_gpg_vstate.io_length, &aes_key);
    gpg_nvm_write(&N_gpg_pstate->SM_mac, &aes_key, sizeof(cx_aes_key_t));
    break;
    }

    /* ----------------- RC ----------------- */
  case 0xD3:
    sw = gpg_apdu_change_ref_data(ID_RC);
    break;

    /* ----------------- UIF ----------------- */
  case 0xD6:
    ptr_v = G_gpg_vstate.kslot->sig.UIF;
    goto WRITE_UIF;
  case 0xD7:
    ptr_v = G_gpg_vstate.kslot->dec.UIF;
    goto WRITE_UIF;
 case 0xD8:
    ptr_v = G_gpg_vstate.kslot->aut.UIF;
     goto WRITE_UIF;
 WRITE_UIF:
    if (G_gpg_vstate.io_length != 2) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 2);
    sw = SW_OK;
    break;

 /* ----------------- WAT ----------------- */
  default:
    sw = SW_REFERENCED_DATA_NOT_FOUND;
    break;
  }
  gpg_io_discard(1);
  return sw;


}
