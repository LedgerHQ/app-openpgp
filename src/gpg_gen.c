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

/* @in slot     slot num [0 ; GPG_KEYS_SLOTS[
 * @out seed    32 bytes master seed for given slot
 */
void gpg_pso_derive_slot_seed(int slot, unsigned char *seed) {
  unsigned int  path[2];
  unsigned char chain[32];

  os_memset(chain, 0, 32);
  path[0] = 0x80475047;
  path[1] = slot + 1;
  os_perso_derive_node_bip32(CX_CURVE_SECP256K1, path, 2, seed, chain);
}

/* @in  Sn         master seed slot number
 * @in  key_name   key name: 'sig ', 'auth ', 'dec '
 * @in  idx        sub-seed index
 * @out Ski        generated sub_seed
 * @in  Ski_len    sub-seed length
 */
void gpg_pso_derive_key_seed(unsigned char *Sn,
                             unsigned char *key_name,
                             unsigned int   idx,
                             unsigned char *Ski,
                             unsigned int   Ski_len) {
  unsigned char h[32];
  h[0] = idx >> 8;
  h[1] = idx;

  cx_sha256_init(&G_gpg_vstate.work.md.sha256);
  cx_hash((cx_hash_t *)&G_gpg_vstate.work.md.sha256, 0, Sn, 32, NULL, 0);
  cx_hash((cx_hash_t *)&G_gpg_vstate.work.md.sha256, 0, (unsigned char *)key_name, 4, NULL, 0);
  cx_hash((cx_hash_t *)&G_gpg_vstate.work.md.sha256, CX_LAST, h, 2, h, 32);
#ifdef GPG_SHAKE256
  cx_shake256_init(&G_gpg_vstate.work.md.sha3, Ski_len);
  cx_shake256_update(&G_gpg_vstate.work.md.sha3, h, 32);
  cx_shake256_final(&G_gpg_vstate.work.md.sha3, Ski);
#else
  cx_sha3_xof_init(&G_gpg_vstate.work.md.sha3, 256, Ski_len);
  cx_hash((cx_hash_t *)&G_gpg_vstate.work.md.sha3, CX_LAST, h, 32, Ski, Ski_len);
#endif
}

/* assume command is fully received */
int gpg_apdu_gen() {
  unsigned int   t, l, ksz, reset_cnt;
  gpg_key_t *    keygpg;
  unsigned char  seed[66];
  unsigned char *name;

  switch ((G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2) {
  case 0x8000:
  case 0x8001:
  case 0x8100:
    break;
  default:
    THROW(SW_INCORRECT_P1P2);
    return SW_INCORRECT_P1P2;
  }

  if (G_gpg_vstate.io_lc != 2) {
    THROW(SW_WRONG_LENGTH);
    return SW_WRONG_LENGTH;
  }

  gpg_io_fetch_tl(&t, &l);
  gpg_io_discard(1);
  reset_cnt = 0;
  switch (t) {
  case 0xB6:
    keygpg    = &G_gpg_vstate.kslot->sig;
    name      = (unsigned char *)PIC("sig ");
    reset_cnt = 0;
    break;
  case 0xA4:
    keygpg = &G_gpg_vstate.kslot->aut;
    name   = (unsigned char *)PIC("aut ");
    break;
  case 0xB8:
    keygpg = &G_gpg_vstate.kslot->dec;
    name   = (unsigned char *)PIC("dec ");
    break;
  default:
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  switch ((G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2) {
  // -- generate keypair ---
  case 0x8000:
  case 0x8001:
    // RSA
    if (keygpg->attributes.value[0] == 0x01) {
      unsigned char *       pq;
      cx_rsa_public_key_t * rsa_pub;
      cx_rsa_private_key_t *rsa_priv, *pkey;
      unsigned int          pkey_size;

      ksz      = (keygpg->attributes.value[1] << 8) | keygpg->attributes.value[2];
      ksz      = ksz >> 3;
      rsa_pub  = (cx_rsa_public_key_t *)&G_gpg_vstate.work.rsa.public;
      rsa_priv = (cx_rsa_private_key_t *)&G_gpg_vstate.work.rsa.private;
      pkey     = &keygpg->priv_key.rsa;
      switch (ksz) {
      case 1024 / 8:
        pkey_size = sizeof(cx_rsa_1024_private_key_t);
        break;
      case 2048 / 8:
        pkey_size = sizeof(cx_rsa_2048_private_key_t);
        break;
      case 3072 / 8:
        pkey_size = sizeof(cx_rsa_3072_private_key_t);
        break;
      case 4096 / 8:
        pkey_size = sizeof(cx_rsa_4096_private_key_t);
        break;
      }
      pq = NULL;
      if ((G_gpg_vstate.io_p2 == 0x01) || (G_gpg_vstate.seed_mode)) {
        pq = &rsa_pub->n[0];
        unsigned int size;
        size = ksz >> 1;
        gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
        gpg_pso_derive_key_seed(seed, name, 1, pq, size);
        gpg_pso_derive_key_seed(seed, name, 2, pq + size, size);
        *pq |= 0x80;
        *(pq + size) |= 0x80;
        cx_math_next_prime(pq, size);
        cx_math_next_prime(pq + size, size);
      }

      cx_rsa_generate_pair(ksz, rsa_pub, rsa_priv, N_gpg_pstate->default_RSA_exponent, 4, pq);

      nvm_write(pkey, rsa_priv, pkey_size);
      nvm_write(&keygpg->pub_key.rsa[0], rsa_pub->e, 4);
      if (reset_cnt) {
        reset_cnt = 0;
        nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
      }
      gpg_io_clear();

      goto send_rsa_pub;
    }
    // ECC
    if ((keygpg->attributes.value[0] == 18) || (keygpg->attributes.value[0] == 19) ||
        (keygpg->attributes.value[0] == 22)) {
      unsigned int curve, keepprivate;
      keepprivate = 0;
      curve       = gpg_oid2curve(keygpg->attributes.value + 1, keygpg->attributes.length - 1);
      if (curve == CX_CURVE_NONE) {
        THROW(SW_REFERENCED_DATA_NOT_FOUND);
        return SW_REFERENCED_DATA_NOT_FOUND;
      }
      if ((G_gpg_vstate.io_p2 == 0x01) || (G_gpg_vstate.seed_mode)) {
        ksz = gpg_curve2domainlen(curve);
        gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
        gpg_pso_derive_key_seed(seed, name, 1, seed, ksz);
        cx_ecfp_init_private_key(curve, seed, ksz, &G_gpg_vstate.work.ecfp.private);
        keepprivate = 1;
      }

      cx_ecfp_generate_pair(curve, &G_gpg_vstate.work.ecfp.public, &G_gpg_vstate.work.ecfp.private, keepprivate);
      nvm_write(&keygpg->priv_key.ecfp, &G_gpg_vstate.work.ecfp.private, sizeof(cx_ecfp_private_key_t));
      nvm_write(&keygpg->pub_key.ecfp, &G_gpg_vstate.work.ecfp.public, sizeof(cx_ecfp_public_key_t));
      if (reset_cnt) {
        reset_cnt = 0;
        nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
      }
      gpg_io_clear();
      goto send_ecc_pub;
    }
    break;

  // --- read pubkey ---
  case 0x8100:
    if (keygpg->attributes.value[0] == 0x01) {
      /// read RSA
    send_rsa_pub:
      gpg_io_discard(1);
      // check length
      ksz = (keygpg->attributes.value[1] << 8) | keygpg->attributes.value[2];
      ksz = ksz >> 3;
      gpg_io_mark();
      switch (ksz) {
      case 1024 / 8:
        if (keygpg->priv_key.rsa1024.size == 0) {
          THROW(SW_REFERENCED_DATA_NOT_FOUND);
          return SW_REFERENCED_DATA_NOT_FOUND;
        }
        gpg_io_insert_tlv(0x81, ksz, (unsigned char *)&keygpg->priv_key.rsa1024.n);
        break;
      case 2048 / 8:
        if (keygpg->priv_key.rsa2048.size == 0) {
          THROW(SW_REFERENCED_DATA_NOT_FOUND);
          return SW_REFERENCED_DATA_NOT_FOUND;
        }
        gpg_io_insert_tlv(0x81, ksz, (unsigned char *)&keygpg->priv_key.rsa2048.n);
        break;
      case 3072 / 8:
        if (keygpg->priv_key.rsa3072.size == 0) {
          THROW(SW_REFERENCED_DATA_NOT_FOUND);
          return SW_REFERENCED_DATA_NOT_FOUND;
        }
        gpg_io_insert_tlv(0x81, ksz, (unsigned char *)&keygpg->priv_key.rsa3072.n);
        break;
      case 4096 / 8:
        if (keygpg->priv_key.rsa4096.size == 0) {
          THROW(SW_REFERENCED_DATA_NOT_FOUND);
          return SW_REFERENCED_DATA_NOT_FOUND;
        }
        gpg_io_insert_tlv(0x81, ksz, (unsigned char *)&keygpg->priv_key.rsa4096.n);
        break;
      }
      gpg_io_insert_tlv(0x82, 4, keygpg->pub_key.rsa);

      l = G_gpg_vstate.io_length;
      gpg_io_set_offset(IO_OFFSET_MARK);
      gpg_io_insert_tl(0x7f49, l);
      gpg_io_set_offset(IO_OFFSET_END);

      return SW_OK;
    }

    if ((keygpg->attributes.value[0] == 18) || (keygpg->attributes.value[0] == 19) ||
        (keygpg->attributes.value[0] == 22)) {
      unsigned int curve;
      /// read ECC
    send_ecc_pub:

      if (keygpg->pub_key.ecfp256.W_len == 0) {
        THROW(SW_REFERENCED_DATA_NOT_FOUND);
        return 0;
      }
      gpg_io_discard(1);
      gpg_io_mark();
      curve = gpg_oid2curve(keygpg->attributes.value + 1, keygpg->attributes.length - 1);
      if (curve == CX_CURVE_Ed25519) {
        os_memmove(G_gpg_vstate.work.io_buffer + 128, keygpg->pub_key.ecfp256.W, keygpg->pub_key.ecfp256.W_len);
        cx_edward_compress_point(CX_CURVE_Ed25519, G_gpg_vstate.work.io_buffer + 128, 65);
        gpg_io_insert_tlv(0x86, 32, G_gpg_vstate.work.io_buffer + 129); // 129: discard 02
      } else if (curve == CX_CURVE_Curve25519) {
        unsigned int i, len;
        len = keygpg->pub_key.ecfp256.W_len - 1;
        for (i = 0; i <= len; i++) {
          G_gpg_vstate.work.io_buffer[128 + i] = keygpg->pub_key.ecfp256.W[len - i];
        }
        gpg_io_insert_tlv(0x86, 32, G_gpg_vstate.work.io_buffer + 128);
      } else {
        gpg_io_insert_tlv(0x86, keygpg->pub_key.ecfp256.W_len, (unsigned char *)&keygpg->pub_key.ecfp256.W);
      }
      l = G_gpg_vstate.io_length;
      gpg_io_set_offset(IO_OFFSET_MARK);
      gpg_io_insert_tl(0x7f49, l);
      gpg_io_set_offset(IO_OFFSET_END);
      return SW_OK;
    }
    break;
  }

  THROW(SW_WRONG_DATA);
  return SW_WRONG_DATA;
}
