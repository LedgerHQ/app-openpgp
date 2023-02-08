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

int gpg_apdu_select_data(unsigned int ref, int reccord) {
  G_gpg_vstate.DO_current = ref;
  G_gpg_vstate.DO_reccord = reccord;
  G_gpg_vstate.DO_offset  = 0;
  return SW_OK;
}

int gpg_apdu_get_data(unsigned int ref) {
  int sw;

  if (G_gpg_vstate.DO_current != ref) {
    G_gpg_vstate.DO_current = ref;
    G_gpg_vstate.DO_reccord = 0;
    G_gpg_vstate.DO_offset  = 0;
  }
  sw = SW_OK;

  gpg_io_discard(1);
  switch (ref) {
    /* ----------------- Optional DO for private use ----------------- */
  case 0x0101:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->private_DO1.value, N_gpg_pstate->private_DO1.length);
    break;
  case 0x0102:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->private_DO2.value, N_gpg_pstate->private_DO2.length);
    break;
  case 0x0103:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->private_DO3.value, N_gpg_pstate->private_DO3.length);
    break;
  case 0x0104:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->private_DO4.value, N_gpg_pstate->private_DO4.length);
    break;

    /* ----------------- Config key slot ----------------- */
  case 0x01F0:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->config_slot, 3);
    gpg_io_insert_u8(G_gpg_vstate.slot);
    break;
  case 0x01F1:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->config_slot, 3);
    break;
  case 0x01F2:
    gpg_io_insert_u8(G_gpg_vstate.slot);
    break;
    /* ----------------- Config RSA exponent ----------------- */
  case 0x01F8:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->default_RSA_exponent, 4);
    break;

    /* ----------------- Application ----------------- */
    /*  Full Application identifier  */
  case 0x004F:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->AID, 10);
    gpg_io_insert(G_gpg_vstate.kslot->serial, 4);
    gpg_io_insert_u16(0x0000);
    break;
    /* Historical bytes, */
  case 0x5F52:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->histo, 15);
    break;
    /* Extended length information */
  case 0x7F66:
    gpg_io_insert(C_ext_length, sizeof(C_ext_length));
    break;

    /* ----------------- User -----------------*/
    /* Login data */
  case 0x005E:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->login.value, N_gpg_pstate->login.length);
    break;
    /* Uniform resource locator */
  case 0x5F50:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->url.value, N_gpg_pstate->url.length);
    break;
    /* Name, Language, Sex */
  case 0x65:
    gpg_io_insert_tlv(0x5B, N_gpg_pstate->name.length, (const unsigned char *)N_gpg_pstate->name.value);
    gpg_io_insert_tlv(0x5F2D, N_gpg_pstate->lang.length, (const unsigned char *)N_gpg_pstate->lang.value);
    gpg_io_insert_tlv(0x5F35, 1, (const unsigned char *)N_gpg_pstate->sex);
    break;

    /* ----------------- aid, histo, ext_length, ... ----------------- */
  case 0x6E:
    gpg_io_insert_tlv(0x4F, 16, (const unsigned char *)N_gpg_pstate->AID);
    memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset - 6, G_gpg_vstate.kslot->serial, 4);
    gpg_io_insert_tlv(0x5F52, 15, (const unsigned char *)N_gpg_pstate->histo);
    gpg_io_insert_tlv(0x7F66, sizeof(C_ext_length), C_ext_length);

    gpg_io_mark();

    gpg_io_insert_tlv(0xC0, sizeof(C_ext_capabilities), C_ext_capabilities);
    gpg_io_insert_tlv(0xC1, G_gpg_vstate.kslot->sig.attributes.length, G_gpg_vstate.kslot->sig.attributes.value);
    gpg_io_insert_tlv(0xC2, G_gpg_vstate.kslot->dec.attributes.length, G_gpg_vstate.kslot->dec.attributes.value);
    gpg_io_insert_tlv(0xC3, G_gpg_vstate.kslot->aut.attributes.length, G_gpg_vstate.kslot->aut.attributes.value);
    gpg_io_insert_tl(0xC4, 7);
    gpg_io_insert((const unsigned char *)N_gpg_pstate->PW_status, 4);
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
    gpg_io_insert_tl(0x73, G_gpg_vstate.io_length - G_gpg_vstate.io_offset);
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
    gpg_io_insert_tl(0x93, 3);
    gpg_io_insert_u24(G_gpg_vstate.kslot->sig_count);
    break;

    /* ----------------- Cardholder certificate ----------------- */
  case 0x7F21:
    switch (G_gpg_vstate.DO_reccord) {
    case 0:
      gpg_io_insert(G_gpg_vstate.kslot->aut.CA.value, G_gpg_vstate.kslot->aut.CA.length);
      break;
    case 1:
      gpg_io_insert(G_gpg_vstate.kslot->dec.CA.value, G_gpg_vstate.kslot->dec.CA.length);
      break;
    case 2:
      gpg_io_insert(G_gpg_vstate.kslot->sig.CA.value, G_gpg_vstate.kslot->sig.CA.length);
      break;
    default:
      sw = SW_RECORD_NOT_FOUND;
    }
    break;

    /* ----------------- PW Status Bytes ----------------- */
  case 0x00C4:
    gpg_io_insert((const unsigned char *)N_gpg_pstate->PW_status, 4);
    gpg_io_insert_u8(N_gpg_pstate->PW1.counter);
    gpg_io_insert_u8(N_gpg_pstate->RC.counter);
    gpg_io_insert_u8(N_gpg_pstate->PW3.counter);
    break;

    /* WAT */
  default:
    THROW(SW_REFERENCED_DATA_NOT_FOUND);
    return 0;
  }

  return sw;
}

int gpg_apdu_get_next_data(unsigned int ref) {
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
  unsigned int   t, l, sw;
  unsigned int * ptr_l;
  unsigned char *ptr_v;

  G_gpg_vstate.DO_current = ref;
  sw                      = SW_OK;

  switch (ref) {
    /*  ----------------- Optional DO for private use ----------------- */
  case 0x0101:
    ptr_l = (unsigned int *)&N_gpg_pstate->private_DO1.length;
    ptr_v = (unsigned char *)N_gpg_pstate->private_DO1.value;
    goto WRITE_PRIVATE_DO;
  case 0x0102:
    ptr_l = (unsigned int *)&N_gpg_pstate->private_DO2.length;
    ptr_v = (unsigned char *)N_gpg_pstate->private_DO2.value;
    goto WRITE_PRIVATE_DO;
  case 0x0103:
    ptr_l = (unsigned int *)&N_gpg_pstate->private_DO3.length;
    ptr_v = (unsigned char *)N_gpg_pstate->private_DO3.value;
    goto WRITE_PRIVATE_DO;
  case 0x0104:
    ptr_l = (unsigned int *)&N_gpg_pstate->private_DO4.length;
    ptr_v = (unsigned char *)N_gpg_pstate->private_DO4.value;
    goto WRITE_PRIVATE_DO;
  WRITE_PRIVATE_DO:
    if (G_gpg_vstate.io_length > GPG_EXT_PRIVATE_DO_LENGTH) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
    sw = SW_OK;
    break;
    /*  ----------------- Config key slot ----------------- */
  case 0x01F1:
    if (G_gpg_vstate.io_length != 3) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    if ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] != GPG_KEYS_SLOTS) ||
        (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] >= GPG_KEYS_SLOTS) ||
        (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] > 3)) {
      THROW(SW_WRONG_DATA);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->config_slot, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, 3);
    break;

  case 0x01F2:
    if ((N_gpg_pstate->config_slot[2] & 2) == 0) {
      THROW(SW_CONDITIONS_NOT_SATISFIED);
      return 0;
    }
    if ((G_gpg_vstate.io_length != 1) || (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset] >= GPG_KEYS_SLOTS)) {
      THROW(SW_WRONG_DATA);
      return 0;
    }
    G_gpg_vstate.slot = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
    break;

  /* ----------------- Config RSA exponent ----------------- */
  case 0x01F8: {
    unsigned int e;
    if (G_gpg_vstate.io_length != 4) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    e = gpg_io_fetch_u32();
    nvm_write((void *)&N_gpg_pstate->default_RSA_exponent, &e, sizeof(unsigned int));
    break;
  }

    /* ----------------- Serial -----------------*/
  case 0x4f:
    if (G_gpg_vstate.io_length != 4) {
      THROW(SW_WRONG_LENGTH);
    }
    nvm_write(G_gpg_vstate.kslot->serial, &G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset], 4);
    break;

    /* ----------------- Extended Header list -----------------*/
  case 0x3FFF: {
    unsigned int len_e, len_p, len_q;
    unsigned int endof, ksz, reset_cnt;
    gpg_key_t *  keygpg;
    unsigned int dh;
    // fecth 4D
    gpg_io_fetch_tl(&t, &l);
    if (t != 0x4D) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }
    // fecth B8/B6/A4
    gpg_io_fetch_tl(&t, &l);
    dh        = 0;
    reset_cnt = 0;
    switch (t) {
    case 0xB6:
      keygpg    = &G_gpg_vstate.kslot->sig;
      reset_cnt = 0x11111111;
      break;
    case 0xA4:
      keygpg = &G_gpg_vstate.kslot->aut;
      break;
    case 0xB8:
      keygpg = &G_gpg_vstate.kslot->dec;
      dh     = 0x11;
      break;
    default:
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }
    // fecth 7f78
    gpg_io_fetch_tl(&t, &l);
    if (t != 0x7f48) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }
    len_e = 0;
    len_p = 0;
    len_q = 0;
    endof = G_gpg_vstate.io_offset + l;
    while (G_gpg_vstate.io_offset < endof) {
      gpg_io_fetch_tl(&t, &l);
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
      case 0x99:
        break;
      default:
        THROW(SW_REFERENCED_DATA_NOT_FOUND);
        return 0;
      }
    }
    // fecth 5f78
    gpg_io_fetch_tl(&t, &l);
    if (t != 0x5f48) {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }

    // --- RSA KEY ---
    if (keygpg->attributes.value[0] == 0x01) {
      unsigned int          e;
      unsigned char *       p, *q, *pq;
      cx_rsa_public_key_t * rsa_pub;
      cx_rsa_private_key_t *rsa_priv, *pkey;
      unsigned int          pkey_size;
      // check length
      ksz      = (keygpg->attributes.value[1] << 8) | keygpg->attributes.value[2];
      ksz      = ksz >> 3;
      rsa_pub  = (cx_rsa_public_key_t *)&G_gpg_vstate.work.rsa.public;
      rsa_priv = (cx_rsa_private_key_t *)&G_gpg_vstate.work.rsa.private;
      pkey     = &keygpg->priv_key.rsa;
      switch (ksz) {
      case 1024 / 8:
        pkey_size = sizeof(cx_rsa_1024_private_key_t);
        pq        = G_gpg_vstate.work.rsa.public1024.n;
        break;
      case 2048 / 8:
        pkey_size = sizeof(cx_rsa_2048_private_key_t);
        pq        = G_gpg_vstate.work.rsa.public2048.n;
        break;
      case 3072 / 8:
        pkey_size = sizeof(cx_rsa_3072_private_key_t);
        pq        = G_gpg_vstate.work.rsa.public3072.n;
        break;
      case 4096 / 8:
        pkey_size = sizeof(cx_rsa_4096_private_key_t);
        pq        = G_gpg_vstate.work.rsa.public4096.n;
        break;
      }
      ksz = ksz >> 1;

      // fetch e
      e = 0;
      switch (len_e) {
      case 4:
        e = gpg_io_fetch_u32();
        break;
      case 3:
        e = gpg_io_fetch_u24();
        break;
      case 2:
        e = gpg_io_fetch_u16();
        break;
      case 1:
        e = gpg_io_fetch_u8();
        break;
      default:
        THROW(SW_WRONG_DATA);
        return 0;
      }

      // move p,q over pub key, this only work because adr<rsa_pub> < adr<p>
      if ((len_p > ksz) || (len_q > ksz)) {
        THROW(SW_WRONG_DATA);
        return 0;
      }
      p = G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset;
      q = p + len_p;
      memmove(pq + ksz - len_p, p, len_p);
      memset(pq, 0, ksz - len_p);
      memmove(pq + 2 * ksz - len_q, q, len_q);
      memset(pq + ksz, 0, ksz - len_q);

      // regenerate RSA private key
      unsigned char _e[4];
      _e[0] = e >> 24;
      _e[1] = e >> 16;
      _e[2] = e >> 8;
      _e[3] = e >> 0;
      cx_rsa_generate_pair(ksz << 1, rsa_pub, rsa_priv, _e, 4, pq);

      // write keys
      nvm_write(&keygpg->pub_key.rsa, rsa_pub->e, 4);
      nvm_write(pkey, rsa_priv, pkey_size);
      if (reset_cnt) {
        reset_cnt = 0;
        nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
      }
    }
    // --- ECC KEY ---
    else if ((keygpg->attributes.value[0] == 19) || (keygpg->attributes.value[0] == 18) ||
             (keygpg->attributes.value[0] == 22)) {
      unsigned int curve;

      ksz   = 0;
      curve = gpg_oid2curve(&keygpg->attributes.value[1], keygpg->attributes.length - 1);
      if (curve == 0) {
        THROW(SW_WRONG_DATA);
        return 0;
      }
      ksz = gpg_curve2domainlen(curve);
      if (ksz == len_p) {
        G_gpg_vstate.work.ecfp.private.curve = curve;
        G_gpg_vstate.work.ecfp.private.d_len = ksz;
        memmove(G_gpg_vstate.work.ecfp.private.d, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, ksz);
        cx_ecfp_generate_pair(curve, &G_gpg_vstate.work.ecfp.public, &G_gpg_vstate.work.ecfp.private, 1);
        nvm_write(&keygpg->pub_key.ecfp, &G_gpg_vstate.work.ecfp.public, sizeof(cx_ecfp_public_key_t));
        nvm_write(&keygpg->priv_key.ecfp, &G_gpg_vstate.work.ecfp.private, sizeof(cx_ecfp_private_key_t));
        if (reset_cnt) {
          reset_cnt = 0;
          nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
        }
      }

    }
    // --- UNSUPPORTED KEY ---
    else {
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }
    break;
  } // endof of 3fff

    /* ----------------- User -----------------*/
    /* Name */
  case 0x5B:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->name.value)) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->name.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write((void *)&N_gpg_pstate->name.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    break;
    /* Login data */
  case 0x5E:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->login.value)) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->login.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write((void *)&N_gpg_pstate->login.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    break;
    /* Language preferences */
  case 0x5F2D:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->lang.value)) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->lang.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write((void *)&N_gpg_pstate->lang.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    break;
    /* Sex */
  case 0x5F35:
    if (G_gpg_vstate.io_length != sizeof(N_gpg_pstate->sex)) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->sex, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    break;
    /* Uniform resource locator */
  case 0x5F50:
    if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->url.value)) {
      THROW(SW_WRONG_LENGTH);
      return 0;
    }
    gpg_nvm_write((void *)N_gpg_pstate->url.value, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write((void *)&N_gpg_pstate->url.length, &G_gpg_vstate.io_length, sizeof(unsigned int));
    break;

    /* ----------------- Cardholder certificate ----------------- */
  case 0x7F21:
    ptr_v = NULL;
    switch (G_gpg_vstate.DO_reccord) {
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
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return 0;
    }
  WRITE_CA:
    if (G_gpg_vstate.io_length > GPG_EXT_CARD_HOLDER_CERT_LENTH) {
      THROW(SW_WRONG_LENGTH);
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
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
      return 0;
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
    gpg_nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
    break;

    /* ----------------- PWS status ----------------- */
  case 0xC4:
    gpg_io_fetch_nv((unsigned char *)N_gpg_pstate->PW_status, 1);
    break;

    /* ----------------- Fingerprints ----------------- */
  case 0xC7:
    ptr_v = G_gpg_vstate.kslot->sig.fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xC8:
    ptr_v = G_gpg_vstate.kslot->dec.fingerprints;
    goto WRITE_FINGERPRINTS;
  case 0xC9:
    ptr_v = G_gpg_vstate.kslot->aut.fingerprints;
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
      return 0;
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 20);
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
      return 0;
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 4);
    break;

    /* ----------------- AES key ----------------- */
    {
      void *       pkey;
      cx_aes_key_t aes_key;
    case 0xD1:
      pkey = (void *)&N_gpg_pstate->SM_enc;
      goto init_aes_key;
    case 0xD2:
      pkey = (void *)&N_gpg_pstate->SM_mac;
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
      gpg_nvm_write((void *)&N_gpg_pstate->SM_enc, &aes_key, sizeof(cx_aes_key_t));
      cx_aes_init_key(G_gpg_vstate.work.io_buffer + 16, G_gpg_vstate.io_length, &aes_key);
      gpg_nvm_write((void *)&N_gpg_pstate->SM_mac, &aes_key, sizeof(cx_aes_key_t));
      break;
    }

    /* ----------------- RC ----------------- */
  case 0xD3: {
    gpg_pin_t *pin;

    pin = gpg_pin_get_pin(PIN_ID_RC);
    if (G_gpg_vstate.io_length == 0) {
      gpg_nvm_write(pin, NULL, sizeof(gpg_pin_t));

    } else if ((G_gpg_vstate.io_length > GPG_MAX_PW_LENGTH) || (G_gpg_vstate.io_length < 8)) {
      THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    } else {
      gpg_pin_set(pin, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, G_gpg_vstate.io_length);
    }
    sw = SW_OK;
    break;
  }

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
      return 0;
    }
    gpg_nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 2);
    break;

    /* ----------------- WAT ----------------- */
  default:
    sw = SW_REFERENCED_DATA_NOT_FOUND;
    break;
  }

  gpg_io_discard(1);
  return sw;
}

static void gpg_init_keyenc(cx_aes_key_t *keyenc) {
  unsigned char seed[32];

  gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
  gpg_pso_derive_key_seed(seed, (unsigned char *)PIC("key "), 1, seed, 16);
  cx_aes_init_key(seed, 16, keyenc);
}

// cmd
// resp  TID API COMPAT len_pub len_priv priv
int gpg_apdu_get_key_data(unsigned int ref) {
  cx_aes_key_t keyenc;
  gpg_key_t *  keygpg;
  unsigned int len = 0;
  gpg_init_keyenc(&keyenc);

  switch (ref) {
  case 0x00B6:
    keygpg = &G_gpg_vstate.kslot->sig;
    break;
  case 0x00B8:
    keygpg = &G_gpg_vstate.kslot->dec;
    break;
  case 0x00A4:
    keygpg = &G_gpg_vstate.kslot->aut;
    break;
  default:
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  gpg_io_discard(1);
  // clear part
  gpg_io_insert_u32(TARGET_ID);
  gpg_io_insert_u32(CX_APILEVEL);
  gpg_io_insert_u32(CX_COMPAT_APILEVEL);
  // encrypted part
  switch (keygpg->attributes.value[0]) {
  case 0x01: // RSA
    // insert pubkey;
    gpg_io_insert_u32(4);
    gpg_io_insert(keygpg->pub_key.rsa, 4);

    // insert privkey
    gpg_io_mark();
    len = cx_aes(&keyenc, CX_ENCRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                 (unsigned char *)&keygpg->priv_key.rsa4096, sizeof(cx_rsa_4096_private_key_t),
                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, GPG_IO_BUFFER_LENGTH - G_gpg_vstate.io_offset);
    gpg_io_inserted(len);
    gpg_io_set_offset(IO_OFFSET_MARK);
    gpg_io_insert_u32(len);
    gpg_io_set_offset(IO_OFFSET_END);
    break;

  case 18: // ECC
  case 19:
  case 22:
    // insert pubkey;
    gpg_io_insert_u32(sizeof(cx_ecfp_640_public_key_t));
    gpg_io_insert((unsigned char *)&keygpg->pub_key.ecfp640, sizeof(cx_ecfp_640_public_key_t));

    // insert privkey
    gpg_io_mark();
    len = cx_aes(&keyenc, CX_ENCRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                 (unsigned char *)&keygpg->priv_key.ecfp640, sizeof(cx_ecfp_640_private_key_t),
                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, GPG_IO_BUFFER_LENGTH - G_gpg_vstate.io_offset);
    gpg_io_inserted(len);
    gpg_io_set_offset(IO_OFFSET_MARK);
    gpg_io_insert_u32(len);
    gpg_io_set_offset(IO_OFFSET_END);
    break;

  default:
    THROW(SW_REFERENCED_DATA_NOT_FOUND);
    return SW_REFERENCED_DATA_NOT_FOUND;
  }
  return SW_OK;
}

// cmd   TID API COMPAT len_pub len_priv priv
// resp  -
int gpg_apdu_put_key_data(unsigned int ref) {
  cx_aes_key_t keyenc;
  gpg_key_t *  keygpg;
  unsigned int len;
  unsigned int offset;
  gpg_init_keyenc(&keyenc);

  switch (ref) {
  case 0xB6:
    keygpg = &G_gpg_vstate.kslot->sig;
    break;
  case 0xB8:
    keygpg = &G_gpg_vstate.kslot->dec;
    break;
  case 0xA4:
    keygpg = &G_gpg_vstate.kslot->aut;
    break;
  default:
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  /* unsigned int target_id = */
  gpg_io_fetch_u32();
  /* unsigned int cx_apilevel = */
  gpg_io_fetch_u32();
  /* unsigned int cx_compat_apilevel = */
  gpg_io_fetch_u32();

  switch (keygpg->attributes.value[0]) {
  // RSA
  case 0x01:
    // insert pubkey;
    len = gpg_io_fetch_u32();
    if (len != 4) {
      THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    }
    gpg_io_fetch_nv(keygpg->pub_key.rsa, len);

    // insert privkey
    len = gpg_io_fetch_u32();
    if (len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
      THROW(SW_WRONG_DATA);
    }
    offset = G_gpg_vstate.io_offset;
    gpg_io_discard(0);
    len = cx_aes(&keyenc, CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST, G_gpg_vstate.work.io_buffer + offset,
                 len, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    if (len != sizeof(cx_rsa_4096_private_key_t)) {
      THROW(SW_WRONG_DATA);
    }
    gpg_nvm_write((unsigned char *)&keygpg->priv_key.rsa4096, G_gpg_vstate.work.io_buffer, len);
    break;

  // ECC
  case 18: /* 12h */
  case 19: /* 13h */
  case 22: /* 16h */
    // insert pubkey;
    len = gpg_io_fetch_u32();
    if (len != sizeof(cx_ecfp_640_public_key_t)) {
      THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    }
    gpg_io_fetch_nv((unsigned char *)&keygpg->pub_key.ecfp640, len);

    // insert privkey
    len = gpg_io_fetch_u32();
    if (len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
      THROW(SW_WRONG_DATA);
    }
    offset = G_gpg_vstate.io_offset;
    gpg_io_discard(0);

    len = cx_aes(&keyenc, CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST, G_gpg_vstate.work.io_buffer + offset,
                 len, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    if (len != sizeof(cx_ecfp_640_private_key_t)) {
      THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    }
    gpg_nvm_write((unsigned char *)&keygpg->priv_key.ecfp640, G_gpg_vstate.work.io_buffer, len);
    break;

  default:
    THROW(SW_REFERENCED_DATA_NOT_FOUND);
    return SW_REFERENCED_DATA_NOT_FOUND;
  }
  gpg_io_discard(1);
  return SW_OK;
}
