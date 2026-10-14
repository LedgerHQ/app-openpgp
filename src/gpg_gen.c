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
#include "bip32.h"

typedef enum {
    KEY_SOURCE_RANDOM,
    KEY_SOURCE_SEED_LEGACY,
    KEY_SOURCE_SEED_V2,
} gpg_key_source_t;

/**
 * Derivate the App Path from the Master Seed for a specific slot
 *
 * @param[in] slot Selected slot, with BIP32_HARDENED_MASK for a hardened derivation
 * @param[out] seed 32 bytes seed for given slot
 *
 * @return Status Word
 *
 */
int gpg_pso_derive_slot_seed(unsigned int slot, unsigned char *seed) {
    unsigned int path[2];
    unsigned char chain[32];
    cx_err_t error = CX_INTERNAL_ERROR;

    explicit_bzero(chain, 32);
    path[0] = 0x80475047;
    path[1] = slot + 1;
    CX_CHECK(os_derive_bip32_no_throw(CX_CURVE_SECP256K1, path, 2, seed, chain));

end:
    explicit_bzero(chain, sizeof(chain));
    if (error != CX_OK) {
        return error;
    }
    return SWO_SUCCESS;
}

/**
 * Derivate the seed of the selected slot for a seeded key
 *
 * @param[in] source legacy or v2 key derivation
 * @param[out] seed 32 bytes seed for the selected slot
 *
 * @return Status Word
 *
 */
static int gpg_gen_slot_seed(gpg_key_source_t source, unsigned char *seed) {
    unsigned int slot;

    switch (source) {
        case KEY_SOURCE_SEED_LEGACY:
            slot = G_gpg_vstate.slot;
            break;
        case KEY_SOURCE_SEED_V2:
            slot = G_gpg_vstate.slot | BIP32_HARDENED_MASK;
            break;
        default:
            return SWO_CONDITIONS_NOT_SATISFIED;
    }
    return gpg_pso_derive_slot_seed(slot, seed);
}

/**
 * Derivate a sub-seed from the Generated Seed with SHAKE256
 *
 * @param[in]  Sn Seed for the selected slot
 * @param[in]  key_name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  idx sub-seed index
 * @param[out] Ski generated sub_seed
 * @param[in]  out_bits SHAKE256 output length, in bits
 *
 * @return Status Word
 *
 */
static int gpg_derive_shake(unsigned char *Sn,
                            unsigned char *key_name,
                            unsigned int idx,
                            unsigned char *Ski,
                            unsigned int out_bits) {
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
    CX_CHECK(cx_shake256_init_no_throw(&G_gpg_vstate.work.md.sha3, out_bits));
    CX_CHECK(cx_sha3_update(&G_gpg_vstate.work.md.sha3, h, 32));
    CX_CHECK(cx_sha3_final(&G_gpg_vstate.work.md.sha3, Ski));

end:
    explicit_bzero(h, sizeof(h));
    explicit_bzero(&G_gpg_vstate.work.md.sha3, MAX(sizeof(cx_sha3_t), sizeof(cx_sha256_t)));
    if (error != CX_OK) {
        return error;
    }
    return SWO_SUCCESS;
}

/**
 * Derivate the Key from the Generated Seed
 * Only the first Ski_len / 8 bytes of Ski are derived, the others are left unchanged.
 *
 * @param[in]  Sn Seed for the selected slot
 * @param[in]  key_name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  idx sub-seed index
 * @param[out] Ski generated sub_seed
 * @param[in]  Ski_len sub-seed length
 *
 * @return Status Word
 *
 */
int gpg_pso_derive_key_seed(unsigned char *Sn,
                            unsigned char *key_name,
                            unsigned int idx,
                            unsigned char *Ski,
                            unsigned int Ski_len) {
    return gpg_derive_shake(Sn, key_name, idx, Ski, Ski_len);
}

/**
 * Derivate the Key from the Generated Seed, on its full length
 *
 * @param[in]  Sn Seed for the selected slot
 * @param[in]  key_name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  idx sub-seed index
 * @param[out] Ski generated sub_seed
 * @param[in]  Ski_len sub-seed length
 *
 * @return Status Word
 *
 */
int gpg_pso_derive_key_seed_full(unsigned char *Sn,
                                 unsigned char *key_name,
                                 unsigned int idx,
                                 unsigned char *Ski,
                                 unsigned int Ski_len) {
    return gpg_derive_shake(Sn, key_name, idx, Ski, Ski_len * 8);
}

/**
 * Derivate key material from the Generated Seed, bound to the key algorithm and size
 *
 * Ski = SHAKE256(SHA256("kdf2" || Sn || key_name || idx || ctx_len || ctx)), on Ski_len bytes,
 * where ctx is the algorithm with the RSA modulus size or the curve OID.
 *
 * @param[in]  Sn Seed for the selected slot
 * @param[in]  keygpg key whose attributes are bound to the derivation
 * @param[in]  key_name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  idx sub-seed index
 * @param[out] Ski generated sub_seed
 * @param[in]  Ski_len sub-seed length
 *
 * @return Status Word
 *
 */
static int gpg_derive_key_seed_v2(const unsigned char *Sn,
                                  const gpg_key_t *keygpg,
                                  const unsigned char *key_name,
                                  unsigned int idx,
                                  unsigned char *Ski,
                                  unsigned int Ski_len) {
    unsigned char h[32];
    unsigned char hdr[3];
    unsigned int ctx_len;
    cx_err_t error = CX_INTERNAL_ERROR;

    switch (keygpg->attributes.value[0]) {
        case KEY_ID_RSA:
            ctx_len = 3;
            break;
        case KEY_ID_ECDH:
        case KEY_ID_ECDSA:
        case KEY_ID_EDDSA:
            ctx_len = keygpg->attributes.length;
            break;
        default:
            return SWO_CONDITIONS_NOT_SATISFIED;
    }
    if ((ctx_len < 3) || (ctx_len > keygpg->attributes.length)) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    U2BE_ENCODE(hdr, 0, idx);
    hdr[2] = ctx_len;

    cx_sha256_init(&G_gpg_vstate.work.md.sha256);
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256,
                              0,
                              (const unsigned char *) PIC("kdf2"),
                              4,
                              NULL,
                              0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, Sn, 32, NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, key_name, 4, NULL, 0));
    CX_CHECK(
        cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, hdr, sizeof(hdr), NULL, 0));
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256,
                              CX_LAST,
                              keygpg->attributes.value,
                              ctx_len,
                              h,
                              sizeof(h)));
    CX_CHECK(cx_shake256_init_no_throw(&G_gpg_vstate.work.md.sha3, Ski_len * 8));
    CX_CHECK(cx_sha3_update(&G_gpg_vstate.work.md.sha3, h, sizeof(h)));
    CX_CHECK(cx_sha3_final(&G_gpg_vstate.work.md.sha3, Ski));

end:
    explicit_bzero(h, sizeof(h));
    explicit_bzero(&G_gpg_vstate.work.md.sha3, MAX(sizeof(cx_sha3_t), sizeof(cx_sha256_t)));
    if (error != CX_OK) {
        return error;
    }
    return SWO_SUCCESS;
}

/**
 * Select how GEN ASYM KEY builds the key, from P2 and the Seed mode setting
 *
 * @param[out] source selected key source
 *
 * @return Status Word
 *
 */
static int gpg_gen_key_source(gpg_key_source_t *source) {
    switch (G_gpg_vstate.io_p2) {
        case DEFAULT_GEN_MODE:
            *source = G_gpg_vstate.seed_mode ? KEY_SOURCE_SEED_V2 : KEY_SOURCE_RANDOM;
            return SWO_SUCCESS;
        case SEEDED_MODE:
            *source = KEY_SOURCE_SEED_LEGACY;
            return SWO_SUCCESS;
        case SEEDED_MODE_V2:
            *source = KEY_SOURCE_SEED_V2;
            return SWO_SUCCESS;
        default:
            return SWO_WRONG_P1_P2;
    }
}

/**
 * Check a RSA public exponent
 *
 * @param[in]  e 4 bytes big-endian exponent
 *
 * @return true if the exponent is odd and at least 3
 *
 */
bool gpg_rsa_exponent_is_valid(const unsigned char *e) {
    uint32_t value = U4BE(e, 0);
    return ((value & 1) != 0) && (value >= 3);
}

/**
 * Erase a key, keeping its User Interaction Flag
 *
 * @param[in]  key key to erase
 *
 */
void gpg_key_erase(gpg_key_t *key) {
    unsigned char uif[sizeof(key->UIF)];

    memmove(uif, key->UIF, sizeof(uif));
    nvm_write(key, NULL, sizeof(gpg_key_t));
    nvm_write(key->UIF, uif, sizeof(uif));
}

/**
 * Check whether a key holds key material, whatever its attributes
 *
 * @param[in]  key key to check
 *
 * @return true if its private or public part is not erased
 *
 */
bool gpg_key_is_present(const gpg_key_t *key) {
    return !is_zeroes_buffer(&key->priv_key, sizeof(key->priv_key)) ||
           !is_zeroes_buffer(&key->pub_key, sizeof(key->pub_key));
}

/**
 * Derive the RSA primes p and q from the Generated Seed
 *
 * @param[in]  keygpg pointer on key structure
 * @param[in]  name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  source legacy or v2 key derivation
 * @param[out] pq p then q, size bytes each
 * @param[in]  size prime length
 *
 * @return Status Word
 *
 */
static int gpg_gen_rsa_seed_primes(const gpg_key_t *keygpg,
                                   uint8_t *name,
                                   gpg_key_source_t source,
                                   uint8_t *pq,
                                   unsigned int size) {
    uint8_t seed[32] = {0};
    uint8_t top_bits = 0;
    int sw = SWO_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;

    sw = gpg_gen_slot_seed(source, seed);
    if (sw != SWO_SUCCESS) {
        goto end;
    }
    switch (source) {
        case KEY_SOURCE_SEED_LEGACY:
            sw = gpg_pso_derive_key_seed(seed, name, 1, pq, size);
            if (sw == SWO_SUCCESS) {
                sw = gpg_pso_derive_key_seed(seed, name, 2, pq + size, size);
            }
            top_bits = 0x80;
            break;
        case KEY_SOURCE_SEED_V2:
            sw = gpg_derive_key_seed_v2(seed, keygpg, name, 1, pq, size);
            if (sw == SWO_SUCCESS) {
                sw = gpg_derive_key_seed_v2(seed, keygpg, name, 2, pq + size, size);
            }
            // full-size modulus, as for a random key
            top_bits = 0xC0;
            break;
        default:
            sw = SWO_CONDITIONS_NOT_SATISFIED;
            break;
    }
    if (sw != SWO_SUCCESS) {
        goto end;
    }
    *pq |= top_bits;
    *(pq + size) |= top_bits;
    error = cx_math_next_prime_no_throw(pq, size);
    if (error == CX_OK) {
        error = cx_math_next_prime_no_throw(pq + size, size);
    }
    sw = (error == CX_OK) ? SWO_SUCCESS : (int) error;

end:
    explicit_bzero(seed, sizeof(seed));
    return sw;
}

/**
 * Generate a RSA key pair and writes it in NVRam
 *
 * @param[in]  keygpg pointer on key structure
 * @param[in]  name key name: 'sig ', 'auth ', 'dec '
 *
 * @return Status Word
 *
 */
static int gpg_gen_rsa_kyey(gpg_key_t *keygpg, uint8_t *name) {
    cx_rsa_public_key_t *rsa_pub = NULL;
    cx_rsa_private_key_t *rsa_priv = NULL;
    uint8_t *pq = NULL;
    uint32_t ksz = 0, reset_cnt = 0, pkey_size = 0;
    int sw = SWO_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;
    gpg_key_source_t source = KEY_SOURCE_RANDOM;

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
        case 4096 / 8:
            pkey_size = sizeof(cx_rsa_4096_private_key_t);
            break;
        default:
            break;
    }
    if (pkey_size == 0) {
        return SWO_INCORRECT_DATA;
    }
    if (!gpg_rsa_exponent_is_valid((const unsigned char *) N_gpg_pstate->default_RSA_exponent)) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }

    sw = gpg_gen_key_source(&source);
    if (sw != SWO_SUCCESS) {
        return sw;
    }
    if (source != KEY_SOURCE_RANDOM) {
        pq = &rsa_pub->n[0];
        sw = gpg_gen_rsa_seed_primes(keygpg, name, source, pq, ksz >> 1);
        if (sw != SWO_SUCCESS) {
            return sw;
        }
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

    // A new signature key restarts the signature counter
    if (keygpg == &G_gpg_vstate.kslot->sig) {
        nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
    }
    gpg_io_clear();
    return SWO_SUCCESS;

end:
    return error;
}

/**
 * Read a RSA key pair
 *
 * @param[in]  keygpg pointer on key structure
 *
 * @return Status Word
 *
 */
static int gpg_read_rsa_kyey(gpg_key_t *keygpg) {
    uint32_t ksz = 0;

    gpg_io_discard(1);
    // check length
    ksz = U2BE(keygpg->attributes.value, 1) >> 3;
    gpg_io_mark();
    switch (ksz) {
        case 2048 / 8:
            if (keygpg->priv_key.rsa2048.size != ksz) {
                return SWO_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa2048.n);
            break;
        case 3072 / 8:
            if (keygpg->priv_key.rsa3072.size != ksz) {
                return SWO_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa3072.n);
            break;
        case 4096 / 8:
            if (keygpg->priv_key.rsa4096.size != ksz) {
                return SWO_REFERENCED_DATA_NOT_FOUND;
            }
            gpg_io_insert_tlv(0x81, ksz, (unsigned char *) &keygpg->priv_key.rsa4096.n);
            break;
        default:
            return SWO_REFERENCED_DATA_NOT_FOUND;
    }
    gpg_io_insert_tlv(0x82, 4, keygpg->pub_key.rsa);

    return SWO_SUCCESS;
}

/**
 * Derive an Elliptic Curve private scalar from the Generated Seed
 *
 * @param[in]  keygpg pointer on key structure
 * @param[in]  name key name: 'sig ', 'auth ', 'dec '
 * @param[in]  curve key curve
 * @param[in]  source legacy or v2 key derivation
 * @param[out] d private scalar, in a 66 bytes buffer
 * @param[in]  ksz curve domain length
 *
 * @return Status Word
 *
 */
static int gpg_gen_ecc_seed_scalar(const gpg_key_t *keygpg,
                                   uint8_t *name,
                                   uint32_t curve,
                                   gpg_key_source_t source,
                                   uint8_t *d,
                                   unsigned int ksz) {
    uint8_t wide[2 * 32] = {0};
    uint8_t order[32] = {0};
    int sw = SWO_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;

    sw = gpg_gen_slot_seed(source, d);
    if (sw != SWO_SUCCESS) {
        return sw;
    }
    switch (source) {
        case KEY_SOURCE_SEED_LEGACY:
            // derived in place
            sw = gpg_pso_derive_key_seed(d, name, 1, d, ksz);
            break;
        case KEY_SOURCE_SEED_V2:
            if ((ksz == 0) || (ksz > sizeof(order))) {
                sw = SWO_CONDITIONS_NOT_SATISFIED;
                break;
            }
            // reduced and clamped as for a random key
            sw = gpg_derive_key_seed_v2(d, keygpg, name, 1, wide, 2 * ksz);
            if (sw != SWO_SUCCESS) {
                break;
            }
            CX_CHECK(cx_ecdomain_parameter(curve, CX_CURVE_PARAM_Order, order, ksz));
            CX_CHECK(cx_math_modm_no_throw(wide, 2 * ksz, order, ksz));
            memmove(d, wide + ksz, ksz);
            if (curve == CX_CURVE_Curve25519) {
                d[ksz - 1] &= 0xF8;
                d[0] = (d[0] & 0x7F) | 0x40;
            }
            break;
        default:
            sw = SWO_CONDITIONS_NOT_SATISFIED;
            break;
    }
    goto clear;

end:
    sw = error;
clear:
    explicit_bzero(wide, sizeof(wide));
    return sw;
}

/**
 * Generate an Elliptic Curve key pair and writes it in NVRam
 *
 * @param[in]  keygpg pointer on key structure
 * @param[in]  name key name: 'sig ', 'auth ', 'dec '
 *
 * @return Status Word
 *
 */
static int gpg_gen_ecc_kyey(gpg_key_t *keygpg, uint8_t *name) {
    uint32_t curve = 0, keepprivate = 0;
    uint32_t ksz = 0, reset_cnt = 0;
    int sw = SWO_UNKNOWN;
    cx_err_t error = CX_INTERNAL_ERROR;
    uint8_t seed[66] = {0};
    gpg_key_source_t source = KEY_SOURCE_RANDOM;

    curve = gpg_attributes2curve(keygpg->attributes.value, keygpg->attributes.length);
    if (curve == CX_CURVE_NONE) {
        return SWO_REFERENCED_DATA_NOT_FOUND;
    }
    sw = gpg_gen_key_source(&source);
    if (sw != SWO_SUCCESS) {
        return sw;
    }
    if (source != KEY_SOURCE_RANDOM) {
        ksz = gpg_curve2domainlen(curve);
        sw = gpg_gen_ecc_seed_scalar(keygpg, name, curve, source, seed, ksz);
        if (sw != SWO_SUCCESS) {
            explicit_bzero(seed, sizeof(seed));
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

    // A new signature key restarts the signature counter
    if (keygpg == &G_gpg_vstate.kslot->sig) {
        nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
    }
    gpg_io_clear();
    error = SWO_SUCCESS;

end:
    explicit_bzero(seed, sizeof(seed));
    return error;
}

/**
 * Read an Elliptic Curve key pair
 *
 * @param[in]  keygpg pointer on key structure
 *
 * @return Status Word
 *
 */
static int gpg_read_ecc_kyey(gpg_key_t *keygpg) {
    uint32_t i = 0;
    cx_err_t error = CX_INTERNAL_ERROR;
    const unsigned char *x = NULL;

    if (keygpg->pub_key.ecfp.W_len == 0) {
        return SWO_REFERENCED_DATA_NOT_FOUND;
    }
    // W_len comes from imported key material and is attacker-controlled: reject any
    // value that would over-read the stored union or overflow the work IO buffer used
    // as memmove destination below (offset 128).
    if ((keygpg->pub_key.ecfp.W_len > sizeof(keygpg->pub_key.ecfp640.W)) ||
        (keygpg->pub_key.ecfp.W_len > (GPG_IO_BUFFER_LENGTH - 128))) {
        return SWO_INCORRECT_DATA;
    }
    gpg_io_discard(1);
    gpg_io_mark();
    // the stored key must be on the curve advertised by the key attributes
    if (!gpg_key_curve_matches_attributes(keygpg, keygpg->pub_key.ecfp.curve)) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    if (keygpg->pub_key.ecfp.curve == CX_CURVE_Ed25519) {
        // cx_edwards_compress_point_no_throw is called with a hardcoded length of 65
        // (uncompressed SEC1 point: 0x04 || X(32) || Y(32)). Enforce that the imported
        // key matches this exact format, otherwise the compression would consume
        // uninitialized bytes from the IO buffer or a malformed point.
        if ((keygpg->pub_key.ecfp.W_len != 65) || (keygpg->pub_key.ecfp.W[0] != 0x04)) {
            return SWO_INCORRECT_DATA;
        }
        memmove(G_gpg_vstate.work.io_buffer + 128,
                keygpg->pub_key.ecfp.W,
                keygpg->pub_key.ecfp.W_len);
        CX_CHECK(cx_edwards_compress_point_no_throw(CX_CURVE_Ed25519,
                                                    G_gpg_vstate.work.io_buffer + 128,
                                                    65));
        gpg_io_insert_tlv(0x86, 32,
                          G_gpg_vstate.work.io_buffer + 129);  // 129: discard 02
    } else if (keygpg->pub_key.ecfp.curve == CX_CURVE_Curve25519) {
        if ((keygpg->pub_key.ecfp.W_len == 65) && (keygpg->pub_key.ecfp.W[0] == 0x04)) {
            x = keygpg->pub_key.ecfp.W + 1;
        } else if ((keygpg->pub_key.ecfp.W_len == 33) && (keygpg->pub_key.ecfp.W[0] == 0x04)) {
            x = keygpg->pub_key.ecfp.W + 1;
        } else if (keygpg->pub_key.ecfp.W_len == 32) {
            x = keygpg->pub_key.ecfp.W;
        } else {
            return SWO_INCORRECT_DATA;
        }
        // OpenPGP expects X25519 public keys as 32-byte little-endian.
        for (i = 0; i < 32; i++) {
            G_gpg_vstate.work.io_buffer[128 + i] = x[31 - i];
        }
        gpg_io_insert_tlv(0x86, 32, G_gpg_vstate.work.io_buffer + 128);
    } else {
        gpg_io_insert_tlv(0x86,
                          keygpg->pub_key.ecfp.W_len,
                          (unsigned char *) &keygpg->pub_key.ecfp.W);
    }
    error = SWO_SUCCESS;

end:
    return error;
}

/**
 * APDU handler to Generate/Read key pair
 *
 * @return Status Word
 *
 */
int gpg_apdu_gen() {
    uint32_t t, l;
    gpg_key_t *keygpg = NULL;
    uint8_t *name = NULL;
    int sw = SWO_UNKNOWN;

    switch (G_gpg_vstate.io_p1p2) {
        case GEN_ASYM_KEY:
        case GEN_ASYM_KEY_SEED:
        case GEN_ASYM_KEY_SEED_V2:
        case READ_ASYM_KEY:
            break;
        default:
            return SWO_WRONG_P1_P2;
    }

    // Control Reference Template: a single byte tag and an empty value
    if (G_gpg_vstate.io_length != 2) {
        return SWO_WRONG_LENGTH;
    }

    t = G_gpg_vstate.work.io_buffer[0];
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
        return SWO_INCORRECT_DATA;
    }

    switch (G_gpg_vstate.io_p1p2) {
        // -- generate keypair ---
        case GEN_ASYM_KEY:
        case GEN_ASYM_KEY_SEED:
        case GEN_ASYM_KEY_SEED_V2:

            if (keygpg->attributes.value[0] == KEY_ID_RSA) {
                sw = gpg_gen_rsa_kyey(keygpg, name);
                if (sw != SWO_SUCCESS) {
                    // no key material left in RAM
                    explicit_bzero(&G_gpg_vstate.work, sizeof(G_gpg_vstate.work));
                    break;
                }
            } else if ((keygpg->attributes.value[0] == KEY_ID_ECDH) ||
                       (keygpg->attributes.value[0] == KEY_ID_ECDSA) ||
                       (keygpg->attributes.value[0] == KEY_ID_EDDSA)) {
                sw = gpg_gen_ecc_kyey(keygpg, name);
                if (sw != SWO_SUCCESS) {
                    // no key material left in RAM
                    explicit_bzero(&G_gpg_vstate.work, sizeof(G_gpg_vstate.work));
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
