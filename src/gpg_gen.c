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

#include "gpg_vars.h"
#include "cx_ram.h"
#include "cx_errors.h"

/* @in slot     slot num [0 ; GPG_KEYS_SLOTS[
 * @out seed    32 bytes master seed for given slot
 */
int gpg_pso_derive_slot_seed(int slot, unsigned char *seed) {
    unsigned int path[2];
    unsigned char chain[32];
    cx_err_t error = CX_INTERNAL_ERROR;

    memset(chain, 0, 32);
    path[0] = 0x80475047;
    path[1] = slot + 1;
    CX_CHECK(os_derive_bip32_no_throw(CX_CURVE_SECP256K1, path, 2, seed, chain));

end:
    if (error != CX_OK) {
        return error;
    }
    return SW_OK;
}

/* @in  Sn         master seed slot number
 * @in  key_name   key name: 'sig ', 'auth ', 'dec '
 * @in  idx        sub-seed index
 * @out Ski        generated sub_seed
 * @in  Ski_len    sub-seed length
 */
int gpg_pso_derive_key_seed(unsigned char *Sn,
                            unsigned char *key_name,
                            unsigned int idx,
                            unsigned char *Ski,
                            unsigned int Ski_len) {
    unsigned char h[32];
    cx_err_t error = CX_INTERNAL_ERROR;
    U2BE_ENCODE(h, 0, idx);

    cx_sha256_init(&G_gpg_vstate.work.md.sha256);
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, Sn, 32, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256,
                              0,
                              (unsigned char *) key_name,
                              4,
                              NULL,
                              0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, CX_LAST, h, 2, h, 32));
    CX_CHECK(cx_shake256_init_no_throw(&G_gpg_vstate.work.md.sha3, Ski_len));
    CX_CHECK(cx_sha3_update(&G_gpg_vstate.work.md.sha3, h, 32));
    CX_CHECK(cx_sha3_final(&G_gpg_vstate.work.md.sha3, Ski));

end:
    if (error != CX_OK) {
        return error;
    }
    return SW_OK;
}

static int gpg_gen_rsa_kyey(gpg_key_t *keygpg, uint8_t *name) {
    cx_rsa_public_key_t *rsa_pub = NULL;
    cx_rsa_private_key_t *rsa_priv = NULL;
    uint8_t *pq = NULL;
    uint32_t ksz = 0, reset_cnt = 0, pkey_size = 0;
    int sw = SW_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;
    uint8_t seed[66] = {0};

    ksz = U2BE(keygpg->attributes.value, 1) >> 3;
    rsa_pub = (cx_rsa_public_key_t *) &G_gpg_vstate.work.rsa.public;
    rsa_priv = (cx_rsa_private_key_t *) &G_gpg_vstate.work.rsa.private;
    switch (ksz) {
        case 2048 / 8:
            pkey_size = sizeof(cx_rsa_2048_private_key_t);
            break;
        case 3072 / 8:
            pkey_size = sizeof(cx_rsa_3072_private_key_t);
            break;
#ifdef WITH_SUPPORT_RSA4096
        case 4096 / 8:
            pkey_size = sizeof(cx_rsa_4096_private_key_t);
            break;
#endif
        default:
            break;
    }
    if (pkey_size == 0) {
        return SW_WRONG_DATA;
    }

    if ((G_gpg_vstate.io_p2 == SEEDED_MODE) || (G_gpg_vstate.seed_mode)) {
        pq = &rsa_pub->n[0];
        unsigned int size;
        size = ksz >> 1;
        sw = gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
        if (sw != SW_OK) {
            return sw;
        }
        sw = gpg_pso_derive_key_seed(seed, name, 1, pq, size);
        if (sw != SW_OK) {
            return sw;
        }
        sw = gpg_pso_derive_key_seed(seed, name, 2, pq + size, size);
        if (sw != SW_OK) {
            return sw;
        }
        *pq |= 0x80;
        *(pq + size) |= 0x80;
        CX_CHECK(cx_math_next_prime_no_throw(pq, size));
        CX_CHECK(cx_math_next_prime_no_throw(pq + size, size));
    }

    CX_CHECK(
        cx_rsa_generate_pair_no_throw(ksz,
                                      rsa_pub,
                                      rsa_priv,
                                      (const unsigned char *) N_gpg_pstate->default_RSA_exponent,
                                      4,
                                      pq));

    nvm_write(&keygpg->priv_key.rsa, rsa_priv, pkey_size);
    nvm_write(&keygpg->pub_key.rsa[0], rsa_pub->e, 4);

    nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
    gpg_io_clear();
    return SW_OK;

end:
    return error;
}

static int gpg_read_rsa_kyey(gpg_key_t *keygpg) {
    uint32_t ksz = 0;

    gpg_io_discard(1);
    // check length
    ksz = U2BE(keygpg->attributes.value, 1) >> 3;
    gpg_io_mark();
    switch (ksz) {
        case 2048 / 8:
            if (keygpg->priv_key.rsa2048.size == 0) {
                return SW_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa2048.n);
            break;
        case 3072 / 8:
            if (keygpg->priv_key.rsa3072.size == 0) {
                return SW_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa3072.n);
            break;
#ifdef WITH_SUPPORT_RSA4096
        case 4096 / 8:
            if (keygpg->priv_key.rsa4096.size == 0) {
                return SW_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa4096.n);
            break;
#endif
        default:
            return SW_REFERENCED_DATA_NOT_FOUND;
    }
    gpg_io_insert_tlv(0x82, 4, keygpg->pub_key.rsa);

    return SW_OK;
}

static int gpg_gen_ecc_kyey(gpg_key_t *keygpg, uint8_t *name) {
    uint32_t curve = 0, keepprivate = 0;
    uint32_t ksz = 0, reset_cnt = 0;
    int sw = SW_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;
    uint8_t seed[66] = {0};

    curve = gpg_oid2curve(keygpg->attributes.value + 1, keygpg->attributes.length - 1);
    if (curve == CX_CURVE_NONE) {
        return SW_REFERENCED_DATA_NOT_FOUND;
    }
    if ((G_gpg_vstate.io_p2 == SEEDED_MODE) || (G_gpg_vstate.seed_mode)) {
        ksz = gpg_curve2domainlen(curve);
        sw = gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
        if (sw != SW_OK) {
            return sw;
        }
        sw = gpg_pso_derive_key_seed(seed, name, 1, seed, ksz);
        if (sw != SW_OK) {
            return sw;
        }
        CX_CHECK(
            cx_ecfp_init_private_key_no_throw(curve, seed, ksz, &G_gpg_vstate.work.ecfp.private));
        keepprivate = 1;
    }

    CX_CHECK(cx_ecfp_generate_pair_no_throw(curve,
                                            &G_gpg_vstate.work.ecfp.public,
                                            &G_gpg_vstate.work.ecfp.private,
                                            keepprivate));
    nvm_write(&keygpg->priv_key.ecfp,
              &G_gpg_vstate.work.ecfp.private,
              sizeof(cx_ecfp_private_key_t));
    nvm_write(&keygpg->pub_key.ecfp, &G_gpg_vstate.work.ecfp.public, sizeof(cx_ecfp_public_key_t));

    nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
    gpg_io_clear();
    return SW_OK;

end:
    return error;
}

static int gpg_read_ecc_kyey(gpg_key_t *keygpg) {
    uint32_t curve = 0;
    uint32_t i, len;
    cx_err_t error = CX_INTERNAL_ERROR;

    if (keygpg->pub_key.ecfp.W_len == 0) {
        return SW_REFERENCED_DATA_NOT_FOUND;
    }
    gpg_io_discard(1);
    gpg_io_mark();
    curve = gpg_oid2curve(keygpg->attributes.value + 1, keygpg->attributes.length - 1);
    if (curve == CX_CURVE_Ed25519) {
        memmove(G_gpg_vstate.work.io_buffer + 128,
                keygpg->pub_key.ecfp.W,
                keygpg->pub_key.ecfp.W_len);
        CX_CHECK(cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519,
                                                    G_gpg_vstate.work.io_buffer + 128,
                                                    65));
        gpg_io_insert_tlv(0x86, 32,
                          G_gpg_vstate.work.io_buffer + 129);  // 129: discard 02
    } else if (curve == CX_CURVE_Curve25519) {
        len = keygpg->pub_key.ecfp.W_len - 1;
        for (i = 0; i <= len; i++) {
            G_gpg_vstate.work.io_buffer[128 + i] = keygpg->pub_key.ecfp.W[len - i];
        }
        gpg_io_insert_tlv(0x86, 32, G_gpg_vstate.work.io_buffer + 128);
    } else {
        gpg_io_insert_tlv(0x86,
                          keygpg->pub_key.ecfp.W_len,
                          (unsigned char *) &keygpg->pub_key.ecfp.W);
    }
    return SW_OK;

end:
    return error;
}

/* assume command is fully received */
int gpg_apdu_gen() {
    uint32_t t, l;
    gpg_key_t *keygpg = NULL;
    uint8_t *name = NULL;
    int sw = SW_UNKNOWN;

    switch (G_gpg_vstate.io_p1p2) {
        case GEN_ASYM_KEY:
        case GEN_ASYM_KEY_SEED:
        case READ_ASYM_KEY:
            break;
        default:
            return SW_WRONG_P1P2;
    }

    if (G_gpg_vstate.io_lc != 2) {
        return SW_WRONG_LENGTH;
    }

    gpg_io_fetch_tl(&t, &l);
    gpg_io_discard(1);
    switch (t) {
        case KEY_SIG:
            keygpg = &G_gpg_vstate.kslot->sig;
            name = (unsigned char *) PIC("sig ");
            break;
        case KEY_AUT:
            keygpg = &G_gpg_vstate.kslot->aut;
            name = (unsigned char *) PIC("aut ");
            break;
        case KEY_DEC:
            keygpg = &G_gpg_vstate.kslot->dec;
            name = (unsigned char *) PIC("dec ");
            break;
        default:
            break;
    }
    if (keygpg == NULL) {
        return SW_WRONG_DATA;
    }

    switch (G_gpg_vstate.io_p1p2) {
        // -- generate keypair ---
        case GEN_ASYM_KEY:
        case GEN_ASYM_KEY_SEED:

            if (keygpg->attributes.value[0] == KEY_ID_RSA) {
                sw = gpg_gen_rsa_kyey(keygpg, name);
                if (sw != SW_OK) {
                    break;
                }
            } else if ((keygpg->attributes.value[0] == KEY_ID_ECDH) ||
                       (keygpg->attributes.value[0] == KEY_ID_ECDSA) ||
                       (keygpg->attributes.value[0] == KEY_ID_EDDSA)) {
                sw = gpg_gen_ecc_kyey(keygpg, name);
                if (sw != SW_OK) {
                    break;
                }
            }

            __attribute__((fallthrough));
        // --- read pubkey ---
        case READ_ASYM_KEY:
            if (keygpg->attributes.value[0] == KEY_ID_RSA) {
                sw = gpg_read_rsa_kyey(keygpg);
            } else if ((keygpg->attributes.value[0] == KEY_ID_ECDH) ||
                       (keygpg->attributes.value[0] == KEY_ID_ECDSA) ||
                       (keygpg->attributes.value[0] == KEY_ID_EDDSA)) {
                sw = gpg_read_ecc_kyey(keygpg);
            }
            l = G_gpg_vstate.io_length;
            gpg_io_set_offset(IO_OFFSET_MARK);
            gpg_io_insert_tl(0x7f49, l);
            gpg_io_set_offset(IO_OFFSET_END);
            break;
    }
    return sw;
}
