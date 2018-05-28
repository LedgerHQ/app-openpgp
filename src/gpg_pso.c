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
#include "gpg_ux_nanos.h"

const unsigned char gpg_oid_sha256[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
const unsigned char gpg_oid_sha512[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

static void gpg_pso_reset_PW1() {
  if (N_gpg_pstate->PW_status[0] ==0) {
     gpg_pin_set_verified(PIN_ID_PW1,0);
  }
}

static int gpg_sign(gpg_key_t *sigkey) {
    // --- RSA
    if (sigkey->attributes.value[0] == 1) {
      cx_rsa_private_key_t *key;
      unsigned int ksz,l;
      ksz = (sigkey->attributes.value[1]<<8) | sigkey->attributes.value[2];
      ksz = ksz>>3;
      switch(ksz) {
        case 1024/8:
          key = (cx_rsa_private_key_t *)&sigkey->priv_key.rsa1024;
          break;
        case 2048/8:
          key = (cx_rsa_private_key_t *)&sigkey->priv_key.rsa2048;
          break;
        case 3072/8:
          key = (cx_rsa_private_key_t *)&sigkey->priv_key.rsa3072;
          break;
        case 4096/8:
          key = (cx_rsa_private_key_t *)&sigkey->priv_key.rsa4096;
          break;
      }
      if (key->size != ksz) {
        THROW(SW_CONDITIONS_NOT_SATISFIED);
        return SW_CONDITIONS_NOT_SATISFIED;
      }

      //sign

      l = ksz - G_gpg_vstate.io_length;
      os_memmove(G_gpg_vstate.work.io_buffer+l,
                 G_gpg_vstate.work.io_buffer,
                 G_gpg_vstate.io_length);
      os_memset(G_gpg_vstate.work.io_buffer, 0xFF, l);
      G_gpg_vstate.work.io_buffer[0]   = 0;
      G_gpg_vstate.work.io_buffer[1]   = 1;
      G_gpg_vstate.work.io_buffer[l-1] = 0;
      ksz = cx_rsa_decrypt(key,
                           CX_PAD_NONE,
                           CX_NONE,
                           G_gpg_vstate.work.io_buffer, ksz,
                           G_gpg_vstate.work.io_buffer, ksz);
      //send
      gpg_io_discard(0);
      gpg_io_inserted(ksz);
      gpg_pso_reset_PW1();
      return SW_OK;
    }
    // --- ECDSA/EdDSA
    if ((sigkey->attributes.value[0] == 19) ||
        (sigkey->attributes.value[0] == 22)) {
      cx_ecfp_private_key_t *key;
      unsigned int sz,i,rs_len;
      unsigned char *rs;

      key = &sigkey->priv_key.ecfp;
      //sign
      if (sigkey->attributes.value[0] == 19) {
        sz = gpg_curve2domainlen(key->curve);
        if ((sz == 0) || (key->d_len != sz)) {
          THROW(SW_CONDITIONS_NOT_SATISFIED);
          return SW_CONDITIONS_NOT_SATISFIED;
        }
        sz = cx_ecdsa_sign(key,
                           CX_RND_TRNG,
                           CX_NONE,
                           G_gpg_vstate.work.io_buffer, sz,
                           G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH,
                           NULL);
        //reencode r,s in MPI format
        gpg_io_discard(0);
      
        rs_len =  G_gpg_vstate.work.io_buffer[3];
        rs     =  &G_gpg_vstate.work.io_buffer[4];
      
        for (i = 0; i<2; i++) {
          if (*rs == 0) {
            rs++;
            rs_len--;
          }
          gpg_io_insert_u8(0);
          gpg_io_insert(rs,rs_len);
          rs = rs+rs_len;
          rs_len = rs[1];
          rs += 2;
        }
      } else{
        sz = cx_eddsa_sign(key,
                           CX_NONE,
                           CX_SHA512, 
                           G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length,
                           NULL, 0,
                           G_gpg_vstate.work.io_buffer+128, GPG_IO_BUFFER_LENGTH-128,
                           NULL);
        gpg_io_discard(0);
        gpg_io_insert(G_gpg_vstate.work.io_buffer+128, sz);
      }
      
      //send
      gpg_pso_reset_PW1();
      return SW_OK;
    }
    // --- PSO:CDS NOT SUPPORTED
    THROW(SW_REFERENCED_DATA_NOT_FOUND);
    return SW_REFERENCED_DATA_NOT_FOUND;
}

int gpg_apdu_pso() {
  unsigned int t,l,ksz;

  unsigned int pso;

  pso = (G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2 ;

  //UIF HANDLE
  switch(pso) {
  // --- PSO:CDS ---
  case 0x9e9a: 
    if (G_gpg_vstate.kslot->sig.UIF[0]) {
      if ((G_gpg_vstate.UIF_flags)==0) {
        ui_menu_uifconfirm_display(0);
        return 0;
      } 
      G_gpg_vstate.UIF_flags = 0;
    }
    break;
  // --- PSO:DEC ---
  case 0x8096: 
    if (G_gpg_vstate.kslot->dec.UIF[0]) {
      if ((G_gpg_vstate.UIF_flags)==0) {
        ui_menu_uifconfirm_display(0);
        return 0;
      }
      G_gpg_vstate.UIF_flags = 0;
    }
    break;
  }

  // --- PSO:ENC ---
  switch(pso) {
  // --- PSO:CDS ---
  case 0x9e9a: {
    unsigned int cnt;
    int sw;
    sw =  gpg_sign(&G_gpg_vstate.kslot->sig);
    cnt = G_gpg_vstate.kslot->sig_count+1;
    nvm_write(&G_gpg_vstate.kslot->sig_count,&cnt,sizeof(unsigned int));
    return sw;
  }
  // --- PSO:ENC ---
  case 0x8680: {
    unsigned int msg_len;
    cx_aes_key_t *key;
    unsigned int sz;
    key = &G_gpg_vstate.kslot->AES_dec;
    if (!(key->size != 16)) {
      THROW(SW_CONDITIONS_NOT_SATISFIED+5);
      return SW_CONDITIONS_NOT_SATISFIED;
    }
    msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
    sz = cx_aes(key,
                CX_ENCRYPT|CX_CHAIN_CBC|CX_LAST,
                G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, msg_len,
                G_gpg_vstate.work.io_buffer+1, GPG_IO_BUFFER_LENGTH-1);
    //send
    gpg_io_discard(0);
    G_gpg_vstate.work.io_buffer[0] = 0x02;
    gpg_io_inserted(1+sz);
    return SW_OK;
  }

  // --- PSO:DEC ---
  case 0x8086: {
    unsigned int msg_len;
    unsigned int pad_byte;
    unsigned int sz;
    pad_byte = gpg_io_fetch_u8();

    switch(pad_byte) {
    // --- PSO:DEC:RSA
    case 0x00: {
      cx_rsa_private_key_t *key;
      if (G_gpg_vstate.mse_dec->attributes.value[0] != 0x01) {
        THROW(SW_CONDITIONS_NOT_SATISFIED);
        return SW_CONDITIONS_NOT_SATISFIED;
      }
      ksz = (G_gpg_vstate.mse_dec->attributes.value[1]<<8) | G_gpg_vstate.mse_dec->attributes.value[2];
      ksz = ksz>>3;
      key = NULL;
      switch(ksz) {
        case 1024/8:
          key = (cx_rsa_private_key_t *)&G_gpg_vstate.mse_dec->priv_key.rsa1024;
          break;
        case 2048/8:
          key = (cx_rsa_private_key_t *)&G_gpg_vstate.mse_dec->priv_key.rsa2048;
          break;
        case 3072/8:
          key = (cx_rsa_private_key_t *)&G_gpg_vstate.mse_dec->priv_key.rsa3072;
          break;
        case 4096/8:
          key = (cx_rsa_private_key_t *)&G_gpg_vstate.mse_dec->priv_key.rsa4096;
          break;
      }
     
      if ((key == NULL) || (key->size != ksz)) {
        THROW(SW_CONDITIONS_NOT_SATISFIED);
        return SW_CONDITIONS_NOT_SATISFIED;
      }
      msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
      sz = cx_rsa_decrypt(key,
                          CX_PAD_PKCS1_1o5,
                          CX_NONE,
                          G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, msg_len,
                          G_gpg_vstate.work.io_buffer,ksz);
      //send
      gpg_io_discard(0);
      gpg_io_inserted(sz);
      return SW_OK;
    }

    // --- PSO:DEC:AES
    case 0x02: {
      cx_aes_key_t *key;
      unsigned int sz;
      key = &G_gpg_vstate.kslot->AES_dec;
      if (!(key->size != 16)) {
        THROW(SW_CONDITIONS_NOT_SATISFIED+5);
        return SW_CONDITIONS_NOT_SATISFIED;
      }
      msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
      sz = cx_aes(key,
                  CX_DECRYPT|CX_CHAIN_CBC|CX_LAST,
                  G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, msg_len,
                  G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
      //send
      gpg_io_discard(0);
      gpg_io_inserted(sz);
      return SW_OK;
    }

    // --- PSO:DEC:ECDH
    case 0xA6: {
      cx_ecfp_private_key_t *key;
      unsigned int sz;
      unsigned int curve;
      if (G_gpg_vstate.mse_dec->attributes.value[0] != 0x12) {
        THROW(SW_CONDITIONS_NOT_SATISFIED);
        return SW_CONDITIONS_NOT_SATISFIED;
      }
      key = &G_gpg_vstate.mse_dec->priv_key.ecfp;
      gpg_io_fetch_l(&l);
      gpg_io_fetch_tl(&t, &l);
      if (t != 0x7f49) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
      }
      gpg_io_fetch_tl(&t, &l);
      if (t != 0x86) {
        THROW(SW_WRONG_DATA);
        return SW_WRONG_DATA;
      }
            
      curve = gpg_oid2curve(G_gpg_vstate.mse_dec->attributes.value+1, G_gpg_vstate.mse_dec->attributes.length-1);
      if (key->curve != curve) {
        THROW(SW_CONDITIONS_NOT_SATISFIED);
        return SW_CONDITIONS_NOT_SATISFIED; 
      }
      if (curve == CX_CURVE_Curve25519) {
        unsigned int i;
        
        for (i = 0; i <=31; i++) {
          G_gpg_vstate.work.io_buffer[512+i] = (G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset)[31-i];
        }
        G_gpg_vstate.work.io_buffer[511] = 0x02;
        sz = cx_ecdh(key,
                    CX_ECDH_X,
                    G_gpg_vstate.work.io_buffer+511, 65, 
                    G_gpg_vstate.work.io_buffer+256, 160);
        for (i = 0; i <=31; i++) { 
          G_gpg_vstate.work.io_buffer[128+i] = G_gpg_vstate.work.io_buffer[287-i];
        }
        sz = 32;
      } else {
        sz = cx_ecdh(key,
                    CX_ECDH_X,
                    G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, 65,
                    G_gpg_vstate.work.io_buffer+128, 160);
      }
      //send
      gpg_io_discard(0);
      gpg_io_insert( G_gpg_vstate.work.io_buffer+128,sz);
      return SW_OK;
    }

    // --- PSO:DEC:xx NOT SUPPORTDED
    default: 
      THROW(SW_REFERENCED_DATA_NOT_FOUND);
      return SW_REFERENCED_DATA_NOT_FOUND;
    } 
  }
  
  //--- PSO:yy NOT SUPPPORTED ---
  default:
    THROW(SW_REFERENCED_DATA_NOT_FOUND);
    return SW_REFERENCED_DATA_NOT_FOUND;
  }
  THROW(SW_REFERENCED_DATA_NOT_FOUND);
  return SW_REFERENCED_DATA_NOT_FOUND;
}


int gpg_apdu_internal_authenticate() {
    // --- PSO:AUTH ---
  if (G_gpg_vstate.kslot->aut.UIF[0]) {
    if ((G_gpg_vstate.UIF_flags)==0) {
      ui_menu_uifconfirm_display(0);
      return 0;
    }
    G_gpg_vstate.UIF_flags = 0;
  }

  if (G_gpg_vstate.mse_aut->attributes.value[0] == 1) {
    if ( G_gpg_vstate.io_length > ((G_gpg_vstate.mse_aut->attributes.value[1]<<8)|G_gpg_vstate.mse_aut->attributes.value[2])*40/100) {
      THROW(SW_WRONG_LENGTH);
      return SW_WRONG_LENGTH;
    } 
  }  
  return gpg_sign(G_gpg_vstate.mse_aut);
}
