#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "Mockgpg_ux.h"
#include "Mocklcx_aes.h"
#include "Mocklcx_ecdh.h"
#include "Mocklcx_ecdsa.h"
#include "Mocklcx_eddsa.h"
#include "Mocklcx_rsa.h"

#define RSA2048_LEN 256
#define ECC_LEN     32

static const uint8_t DIGEST_INFO[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01};

static void mocks_reset(void) {
    Mockgpg_ux_Destroy();
    Mocklcx_aes_Destroy();
    Mocklcx_ecdh_Destroy();
    Mocklcx_ecdsa_Destroy();
    Mocklcx_eddsa_Destroy();
    Mocklcx_rsa_Destroy();
    Mockgpg_ux_Init();
    Mocklcx_aes_Init();
    Mocklcx_ecdh_Init();
    Mocklcx_ecdsa_Init();
    Mocklcx_eddsa_Init();
    Mocklcx_rsa_Init();
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    mocks_reset();
    G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[0];
    gpg_mse_reset();
    N_gpg_pstate->PW_status[0] = 1;
    gpg_pin_set_verified(PIN_ID_PW1, 1);
}

void tearDown(void) {
    Mockgpg_ux_Verify();
    Mocklcx_aes_Verify();
    Mocklcx_ecdh_Verify();
    Mocklcx_ecdsa_Verify();
    Mocklcx_eddsa_Verify();
    Mocklcx_rsa_Verify();
}

/* ----------------------------------------------------------------------- */
/* Keys and commands                                                       */
/* ----------------------------------------------------------------------- */

static void set_rsa2048(gpg_key_t *key) {
    const uint8_t attr[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};

    memcpy((void *) key->attributes.value, attr, sizeof(attr));
    key->attributes.length = sizeof(attr);
    key->priv_key.rsa2048.size = RSA2048_LEN;
}

static void set_ecc(gpg_key_t *key,
                    uint8_t algo,
                    const uint8_t *oid,
                    size_t oid_len,
                    cx_curve_t curve) {
    key->attributes.value[0] = algo;
    memcpy((void *) (key->attributes.value + 1), oid, oid_len);
    key->attributes.length = 1 + oid_len;
    key->priv_key.ecfp.curve = curve;
    key->priv_key.ecfp.d_len = ECC_LEN;
}

static void set_aes(cx_aes_key_t *key, unsigned int size) {
    key->size = size;
}

// Load a received command, as left by gpg_io_do()
static void command(unsigned int p1p2, const uint8_t *data, size_t len) {
    G_gpg_vstate.io_p1p2 = p1p2;
    G_gpg_vstate.io_p1 = p1p2 >> 8;
    G_gpg_vstate.io_p2 = p1p2 & 0xFF;
    gpg_io_discard(1);
    if (len != 0) {
        gpg_io_insert(data, len);
        gpg_io_set_offset(0);
    }
}

static int pso(unsigned int p1p2, const uint8_t *data, size_t len) {
    command(p1p2, data, len);
    return gpg_apdu_pso();
}

static void assert_response_length(size_t len) {
    TEST_ASSERT_EQUAL_UINT(len, G_gpg_vstate.io_length);
}

/* ----------------------------------------------------------------------- */
/* Crypto stand-ins                                                        */
/* ----------------------------------------------------------------------- */

// RSA private operation: checks the PKCS#1 v1.5 type 1 block, returns 0xAB bytes
static cx_err_t fake_rsa_sign(const cx_rsa_private_key_t *key,
                              uint32_t mode,
                              cx_md_t hashID,
                              const uint8_t *mesg,
                              size_t mesg_len,
                              uint8_t *dec,
                              size_t *dec_len,
                              int num_calls) {
    size_t ps_len = RSA2048_LEN - 3 - sizeof(DIGEST_INFO);

    (void) key;
    (void) hashID;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT32(CX_PAD_NONE, mode);
    TEST_ASSERT_EQUAL_UINT(RSA2048_LEN, mesg_len);
    TEST_ASSERT_EQUAL_HEX8(0x00, mesg[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, mesg[1]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xFF, mesg + 2, ps_len);
    TEST_ASSERT_EQUAL_HEX8(0x00, mesg[2 + ps_len]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DIGEST_INFO, mesg + 3 + ps_len, sizeof(DIGEST_INFO));
    memset(dec, 0xAB, RSA2048_LEN);
    *dec_len = RSA2048_LEN;
    return CX_OK;
}

// RSA decryption: returns a 32-byte session key
static cx_err_t fake_rsa_decrypt(const cx_rsa_private_key_t *key,
                                 uint32_t mode,
                                 cx_md_t hashID,
                                 const uint8_t *mesg,
                                 size_t mesg_len,
                                 uint8_t *dec,
                                 size_t *dec_len,
                                 int num_calls) {
    (void) key;
    (void) hashID;
    (void) mesg;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT32(CX_PAD_PKCS1_1o5, mode);
    TEST_ASSERT_EQUAL_UINT(RSA2048_LEN, mesg_len);
    memset(dec, 0x5E, 32);
    *dec_len = 32;
    return CX_OK;
}

// ECDSA: returns the DER encoding of the r and s set by the test
static uint8_t ecdsa_r[ECC_LEN];
static uint8_t ecdsa_s[ECC_LEN];
static size_t ecdsa_hash_len;
static uint8_t ecdsa_hash[ECC_LEN];

static size_t der_integer(uint8_t *out, const uint8_t *value, size_t len) {
    size_t skip = 0;
    size_t n = 0;

    while ((skip < len - 1) && (value[skip] == 0)) {
        skip++;
    }
    out[n++] = 0x02;
    out[n++] = (uint8_t) (len - skip + ((value[skip] & 0x80) ? 1 : 0));
    if (value[skip] & 0x80) {
        out[n++] = 0x00;
    }
    memcpy(out + n, value + skip, len - skip);
    return n + len - skip;
}

static cx_err_t fake_ecdsa_sign(const cx_ecfp_private_key_t *pvkey,
                                uint32_t mode,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t *sig_len,
                                uint32_t *info,
                                int num_calls) {
    size_t n = 2;

    (void) pvkey;
    (void) mode;
    (void) hashID;
    (void) hash;
    (void) num_calls;
    ecdsa_hash_len = hash_len;
    memcpy(ecdsa_hash, hash, sizeof(ecdsa_hash));
    n += der_integer(sig + n, ecdsa_r, sizeof(ecdsa_r));
    n += der_integer(sig + n, ecdsa_s, sizeof(ecdsa_s));
    sig[0] = 0x30;
    sig[1] = (uint8_t) (n - 2);
    *sig_len = n;
    *info = 0;
    return CX_OK;
}

static cx_err_t fake_eddsa_sign(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len,
                                int num_calls) {
    (void) pvkey;
    (void) hash;
    (void) num_calls;
    TEST_ASSERT_EQUAL_INT(CX_SHA512, hashID);
    TEST_ASSERT_EQUAL_UINT(3, hash_len);
    TEST_ASSERT_TRUE(sig_len >= 2 * ECC_LEN);
    memset(sig, 0xED, 2 * ECC_LEN);
    return CX_OK;
}

// ECDH: checks the point given by the host, returns 0xEC bytes then 0xFF bytes
static uint8_t ecdh_point[65];

static cx_err_t fake_ecdh(const cx_ecfp_private_key_t *pvkey,
                          uint32_t mode,
                          const uint8_t *P,
                          size_t P_len,
                          uint8_t *secret,
                          size_t secret_len,
                          int num_calls) {
    (void) pvkey;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT32(CX_ECDH_X, mode);
    TEST_ASSERT_EQUAL_UINT(sizeof(ecdh_point), P_len);
    memcpy(ecdh_point, P, P_len);
    memset(secret, 0xEC, ECC_LEN);
    memset(secret + ECC_LEN, 0xFF, secret_len - ECC_LEN);
    secret[0] = 0x01;
    return CX_OK;
}

// AES CBC without padding: complements the input
static cx_err_t fake_aes(const cx_aes_key_t *key,
                         uint32_t mode,
                         const uint8_t *in,
                         size_t in_len,
                         uint8_t *out,
                         size_t *out_len,
                         int num_calls) {
    (void) key;
    (void) mode;
    (void) num_calls;
    TEST_ASSERT_TRUE(in_len <= *out_len);
    memmove(out, in, in_len);
    for (size_t i = 0; i < in_len; i++) {
        out[i] ^= 0xFF;
    }
    *out_len = in_len;
    return CX_OK;
}

/* ----------------------------------------------------------------------- */
/* User Interaction Flag                                                   */
/* ----------------------------------------------------------------------- */

static void test_uif_sign(void) {
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.UIF[0] = 1;

    // Confirmed on the device first, which then replays the command
    ui_menu_uifconfirm_display_Expect(0);
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_RESPONSE, pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));

    G_gpg_vstate.UIF_flags = 1;
    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
    // Valid for one operation
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.UIF_flags);
}

static void test_uif_decipher(void) {
    const uint8_t data[] = {PAD_AES, 0x00};

    G_gpg_vstate.kslot->dec.UIF[0] = 1;
    ui_menu_uifconfirm_display_Expect(0);
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_RESPONSE, pso(PSO_DEC, data, sizeof(data)));
}

static void test_uif_authenticate(void) {
    G_gpg_vstate.kslot->aut.UIF[0] = 1;
    command(0x0000, DIGEST_INFO, sizeof(DIGEST_INFO));

    ui_menu_uifconfirm_display_Expect(0);
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_RESPONSE, gpg_apdu_internal_authenticate());
}

/* ----------------------------------------------------------------------- */
/* PSO:COMPUTE DIGITAL SIGNATURE                                           */
/* ----------------------------------------------------------------------- */

static void test_sign_rsa(void) {
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig_count = 41;

    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
    assert_response_length(RSA2048_LEN);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xAB, G_gpg_vstate.work.io_buffer, RSA2048_LEN);
    TEST_ASSERT_EQUAL_UINT(42, G_gpg_vstate.kslot->sig_count);
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_sign_single_use_pw1(void) {
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    N_gpg_pstate->PW_status[0] = 0;

    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

// RSA private operation on any DigestInfo
static cx_err_t fake_rsa_sign_any(const cx_rsa_private_key_t *key,
                                  uint32_t mode,
                                  cx_md_t hashID,
                                  const uint8_t *mesg,
                                  size_t mesg_len,
                                  uint8_t *dec,
                                  size_t *dec_len,
                                  int num_calls) {
    (void) key;
    (void) mode;
    (void) hashID;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(RSA2048_LEN, mesg_len);
    TEST_ASSERT_EQUAL_HEX8(0x00, mesg[0]);
    TEST_ASSERT_EQUAL_HEX8(0x01, mesg[1]);
    memset(dec, 0xAB, RSA2048_LEN);
    *dec_len = RSA2048_LEN;
    return CX_OK;
}

static void test_sign_rsa_too_long(void) {
    // At most 40% of the modulus
    static uint8_t data[(RSA2048_LEN * 40 / 100) + 1];

    set_rsa2048(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_CDS, data, sizeof(data)));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.kslot->sig_count);

    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign_any);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, data, sizeof(data) - 1));
}

static void test_sign_rsa_no_key(void) {
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.priv_key.rsa2048.size = 0;
    N_gpg_pstate->PW_status[0] = 0;

    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED,
                            pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
    // The single-use PW1 is consumed by the attempt
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_sign_crypto_error(void) {
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig_count = 41;

    cx_rsa_decrypt_no_throw_ExpectAnyArgsAndReturn(CX_INTERNAL_ERROR);
    TEST_ASSERT_EQUAL_HEX32(CX_INTERNAL_ERROR, pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
    TEST_ASSERT_EQUAL_UINT(41, G_gpg_vstate.kslot->sig_count);
}

static void set_ecdsa_p256(gpg_key_t *key) {
    set_ecc(key, KEY_ID_ECDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1), CX_CURVE_SECP256R1);
}

static void test_sign_ecdsa_digest_length(void) {
    uint8_t digest[48] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    memset(ecdsa_r, 0x11, sizeof(ecdsa_r));
    memset(ecdsa_s, 0x22, sizeof(ecdsa_s));

    // A longer digest is truncated to the curve size
    cx_ecdsa_sign_no_throw_StubWithCallback(fake_ecdsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    TEST_ASSERT_EQUAL_UINT(ECC_LEN, ecdsa_hash_len);

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_CDS, digest, 0));
}

static void test_sign_ecdsa_short_digest(void) {
    // A shorter digest is left-padded with zeros
    uint8_t digest[28];
    uint8_t expected[ECC_LEN] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    memset(digest, 0xD1, sizeof(digest));
    memcpy(expected + ECC_LEN - sizeof(digest), digest, sizeof(digest));
    memset(ecdsa_r, 0x11, sizeof(ecdsa_r));
    memset(ecdsa_s, 0x22, sizeof(ecdsa_s));

    cx_ecdsa_sign_no_throw_StubWithCallback(fake_ecdsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    TEST_ASSERT_EQUAL_UINT(ECC_LEN, ecdsa_hash_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, ecdsa_hash, ECC_LEN);
}

static void check_ecdsa_signature(void) {
    // r || s, each on the curve size
    uint8_t expected[2 * ECC_LEN];

    memcpy(expected, ecdsa_r, ECC_LEN);
    memcpy(expected + ECC_LEN, ecdsa_s, ECC_LEN);
    assert_response_length(sizeof(expected));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.work.io_buffer, sizeof(expected));
}

static void test_sign_ecdsa(void) {
    uint8_t digest[ECC_LEN] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    cx_ecdsa_sign_no_throw_StubWithCallback(fake_ecdsa_sign);

    // r with its high bit set, s without
    memset(ecdsa_r, 0x81, sizeof(ecdsa_r));
    memset(ecdsa_s, 0x22, sizeof(ecdsa_s));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    check_ecdsa_signature();
}

static void test_sign_ecdsa_short_integers(void) {
    uint8_t digest[ECC_LEN] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    cx_ecdsa_sign_no_throw_StubWithCallback(fake_ecdsa_sign);

    // r shorter than the curve size
    memset(ecdsa_r, 0x33, sizeof(ecdsa_r));
    ecdsa_r[0] = 0x00;
    memset(ecdsa_s, 0x92, sizeof(ecdsa_s));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    check_ecdsa_signature();

    // s shorter than the curve size, with its high bit set after the leading zero
    memset(ecdsa_r, 0x33, sizeof(ecdsa_r));
    memset(ecdsa_s, 0x92, sizeof(ecdsa_s));
    ecdsa_s[0] = 0x00;
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    check_ecdsa_signature();

    // Both shorter, by several bytes
    memset(ecdsa_r, 0x33, sizeof(ecdsa_r));
    memset(ecdsa_r, 0x00, 3);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, digest, sizeof(digest)));
    check_ecdsa_signature();
}

static cx_err_t fake_ecdsa_bad_der(const cx_ecfp_private_key_t *pvkey,
                                   uint32_t mode,
                                   cx_md_t hashID,
                                   const uint8_t *hash,
                                   size_t hash_len,
                                   uint8_t *sig,
                                   size_t *sig_len,
                                   uint32_t *info,
                                   int num_calls) {
    // r on 33 significant bytes
    const uint8_t der[] = {0x30, 0x25, 0x02, 0x21, 0x01, 0x00};

    (void) pvkey;
    (void) mode;
    (void) hashID;
    (void) hash;
    (void) hash_len;
    (void) num_calls;
    memset(sig, 0x11, 64);
    memcpy(sig, der, sizeof(der));
    *sig_len = 2 + 0x25;
    *info = 0;
    return CX_OK;
}

static void test_sign_ecdsa_bad_signature(void) {
    uint8_t digest[ECC_LEN] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig_count = 7;
    cx_ecdsa_sign_no_throw_StubWithCallback(fake_ecdsa_bad_der);
    TEST_ASSERT_EQUAL_HEX32(CX_INTERNAL_ERROR, pso(PSO_CDS, digest, sizeof(digest)));
    TEST_ASSERT_EQUAL_UINT(7, G_gpg_vstate.kslot->sig_count);
}

static void test_sign_ecdsa_curve_mismatch(void) {
    uint8_t digest[ECC_LEN] = {0};

    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.priv_key.ecfp.curve = CX_CURVE_SECP256K1;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_CDS, digest, sizeof(digest)));

    // No key
    set_ecdsa_p256(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.priv_key.ecfp.d_len = 0;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_CDS, digest, sizeof(digest)));
}

static void test_sign_eddsa(void) {
    const uint8_t message[] = {'m', 's', 'g'};

    set_ecc(&G_gpg_vstate.kslot->sig,
            KEY_ID_EDDSA,
            C_OID_Ed25519,
            sizeof(C_OID_Ed25519),
            CX_CURVE_Ed25519);

    cx_eddsa_sign_no_throw_StubWithCallback(fake_eddsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_CDS, message, sizeof(message)));
    assert_response_length(2 * ECC_LEN);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xED, G_gpg_vstate.work.io_buffer, 2 * ECC_LEN);
}

static void test_sign_eddsa_too_long(void) {
    static uint8_t message[GPG_IO_BUFFER_LENGTH - 255];

    set_ecc(&G_gpg_vstate.kslot->sig,
            KEY_ID_EDDSA,
            C_OID_Ed25519,
            sizeof(C_OID_Ed25519),
            CX_CURVE_Ed25519);
    // The message must not overlap the signature output area
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_CDS, message, sizeof(message)));
}

static void test_sign_unsupported_key(void) {
    G_gpg_vstate.kslot->sig.attributes.value[0] = KEY_ID_ECDH;
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND,
                            pso(PSO_CDS, DIGEST_INFO, sizeof(DIGEST_INFO)));
}

/* ----------------------------------------------------------------------- */
/* PSO:DECIPHER and PSO:ENCIPHER                                           */
/* ----------------------------------------------------------------------- */

static void test_decipher_empty(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_DEC, NULL, 0));
}

static void test_decipher_unknown_padding(void) {
    const uint8_t data[] = {0x01, 0x00};

    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, pso(PSO_DEC, data, sizeof(data)));
}

static void test_decipher_rsa(void) {
    static uint8_t data[1 + RSA2048_LEN] = {PAD_RSA};

    set_rsa2048(&G_gpg_vstate.kslot->dec);
    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_decrypt);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_DEC, data, sizeof(data)));
    assert_response_length(32);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x5E, G_gpg_vstate.work.io_buffer, 32);
}

static void test_decipher_rsa_wrong_key(void) {
    static uint8_t data[1 + RSA2048_LEN] = {PAD_RSA};

    // Not a RSA key
    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_cv25519,
            sizeof(C_OID_cv25519),
            CX_CURVE_Curve25519);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, data, sizeof(data)));

    // No key
    set_rsa2048(&G_gpg_vstate.kslot->dec);
    G_gpg_vstate.kslot->dec.priv_key.rsa2048.size = 0;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, data, sizeof(data)));
}

static void test_decipher_aes(void) {
    uint8_t data[1 + 32] = {PAD_AES};

    set_aes(&G_gpg_vstate.kslot->AES_dec, CX_AES_256_KEY_LEN);
    memset(data + 1, 0x0F, 32);
    cx_aes_no_throw_StubWithCallback(fake_aes);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_DEC, data, sizeof(data)));
    assert_response_length(32);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xF0, G_gpg_vstate.work.io_buffer, 32);
}

static void test_aes_key_sizes(void) {
    uint8_t data[1 + 16] = {PAD_AES};

    // DO D5 holds a 128 or 256 bits key
    set_aes(&G_gpg_vstate.kslot->AES_dec, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, data, sizeof(data)));
    set_aes(&G_gpg_vstate.kslot->AES_dec, 24);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, data, sizeof(data)));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_ENC, data + 1, 16));
}

static void test_encipher_aes(void) {
    uint8_t data[32];

    set_aes(&G_gpg_vstate.kslot->AES_dec, CX_AES_128_KEY_LEN);
    memset(data, 0x0F, sizeof(data));
    cx_aes_no_throw_StubWithCallback(fake_aes);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_ENC, data, sizeof(data)));

    // Padding indicator, then the cryptogram
    assert_response_length(1 + sizeof(data));
    TEST_ASSERT_EQUAL_HEX8(PAD_AES, G_gpg_vstate.work.io_buffer[0]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xF0, G_gpg_vstate.work.io_buffer + 1, sizeof(data));
}

static void test_pso_unknown(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, pso(0x9E9B, DIGEST_INFO, 4));
}

/* ----------------------------------------------------------------------- */
/* PSO:DECIPHER with ECDH                                                  */
/* ----------------------------------------------------------------------- */

// A6 { 7F49 { 86 <public key> } }
static size_t ecdh_command(uint8_t *buf, const uint8_t *public_key, size_t len) {
    size_t n = 0;

    buf[n++] = PAD_ECDH;
    buf[n++] = (uint8_t) (len + 5);
    buf[n++] = 0x7F;
    buf[n++] = 0x49;
    buf[n++] = (uint8_t) (len + 2);
    buf[n++] = 0x86;
    buf[n++] = (uint8_t) len;
    memcpy(buf + n, public_key, len);
    return n + len;
}

static void test_ecdh_p256(void) {
    uint8_t point[65];
    uint8_t buf[80];
    size_t len;

    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_SECP256R1,
            sizeof(C_OID_SECP256R1),
            CX_CURVE_SECP256R1);
    memset(point, 0x42, sizeof(point));
    point[0] = 0x04;
    len = ecdh_command(buf, point, sizeof(point));

    cx_ecdh_no_throw_StubWithCallback(fake_ecdh);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_DEC, buf, len));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(point, ecdh_point, sizeof(point));

    // The x coordinate of the shared point
    assert_response_length(ECC_LEN);
    TEST_ASSERT_EQUAL_HEX8(0x01, G_gpg_vstate.work.io_buffer[0]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEC, G_gpg_vstate.work.io_buffer + 1, ECC_LEN - 1);
}

static void test_ecdh_cv25519(void) {
    uint8_t public_key[32];
    uint8_t reversed[32];
    uint8_t buf[48];
    size_t len;

    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_cv25519,
            sizeof(C_OID_cv25519),
            CX_CURVE_Curve25519);
    for (size_t i = 0; i < sizeof(public_key); i++) {
        public_key[i] = (uint8_t) i;
        reversed[31 - i] = (uint8_t) i;
    }
    len = ecdh_command(buf, public_key, sizeof(public_key));

    cx_ecdh_no_throw_StubWithCallback(fake_ecdh);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, pso(PSO_DEC, buf, len));

    // Little-endian on the wire, big-endian x in the uncompressed point
    TEST_ASSERT_EQUAL_HEX8(0x04, ecdh_point[0]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(reversed, ecdh_point + 1, sizeof(reversed));

    // The shared secret is sent back little-endian
    assert_response_length(ECC_LEN);
    TEST_ASSERT_EQUAL_HEX8(0x01, G_gpg_vstate.work.io_buffer[ECC_LEN - 1]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xEC, G_gpg_vstate.work.io_buffer, ECC_LEN - 1);
}

static void test_ecdh_wrong_key(void) {
    uint8_t point[65] = {0x04};
    uint8_t buf[80];
    size_t len = ecdh_command(buf, point, sizeof(point));

    // Not an ECDH key
    set_rsa2048(&G_gpg_vstate.kslot->dec);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, buf, len));

    // A key for another curve than its attributes
    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_SECP256R1,
            sizeof(C_OID_SECP256R1),
            CX_CURVE_SECP256K1);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, pso(PSO_DEC, buf, len));
}

static void test_ecdh_malformed(void) {
    uint8_t point[65] = {0x04};
    uint8_t buf[80];
    size_t len;

    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_SECP256R1,
            sizeof(C_OID_SECP256R1),
            CX_CURVE_SECP256R1);

    // Not a public key DO
    len = ecdh_command(buf, point, sizeof(point));
    buf[3] = 0x4A;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, pso(PSO_DEC, buf, len));

    // Not an external public key
    len = ecdh_command(buf, point, sizeof(point));
    buf[5] = 0x87;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, pso(PSO_DEC, buf, len));

    // Public key longer than the data
    len = ecdh_command(buf, point, sizeof(point));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_DEC, buf, len - 1));

    // Truncated headers
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_DEC, buf, 2));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_DEC, buf, 5));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, pso(PSO_DEC, buf, 8));
}

static void test_ecdh_wrong_point_size(void) {
    uint8_t point[65] = {0x04};
    uint8_t buf[80];
    size_t len;

    // Uncompressed point for P-256
    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_SECP256R1,
            sizeof(C_OID_SECP256R1),
            CX_CURVE_SECP256R1);
    len = ecdh_command(buf, point, 33);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, pso(PSO_DEC, buf, len));

    // x coordinate only for Curve25519
    set_ecc(&G_gpg_vstate.kslot->dec,
            KEY_ID_ECDH,
            C_OID_cv25519,
            sizeof(C_OID_cv25519),
            CX_CURVE_Curve25519);
    len = ecdh_command(buf, point, 31);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, pso(PSO_DEC, buf, len));
}

/* ----------------------------------------------------------------------- */
/* INTERNAL AUTHENTICATE                                                   */
/* ----------------------------------------------------------------------- */

static void test_authenticate_rsa(void) {
    set_rsa2048(&G_gpg_vstate.kslot->aut);
    command(0x0000, DIGEST_INFO, sizeof(DIGEST_INFO));

    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_internal_authenticate());
    assert_response_length(RSA2048_LEN);
}

static void test_authenticate_rsa_too_long(void) {
    // At most 40% of the modulus
    static uint8_t data[(RSA2048_LEN * 40 / 100) + 1];

    set_rsa2048(&G_gpg_vstate.kslot->aut);
    command(0x0000, data, sizeof(data));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_apdu_internal_authenticate());

    cx_rsa_decrypt_no_throw_StubWithCallback(fake_rsa_sign_any);
    command(0x0000, data, sizeof(data) - 1);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_internal_authenticate());
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_uif_sign);
    RUN_TEST(test_uif_decipher);
    RUN_TEST(test_uif_authenticate);
    RUN_TEST(test_sign_rsa);
    RUN_TEST(test_sign_single_use_pw1);
    RUN_TEST(test_sign_rsa_too_long);
    RUN_TEST(test_sign_rsa_no_key);
    RUN_TEST(test_sign_crypto_error);
    RUN_TEST(test_sign_ecdsa_digest_length);
    RUN_TEST(test_sign_ecdsa_short_digest);
    RUN_TEST(test_sign_ecdsa);
    RUN_TEST(test_sign_ecdsa_short_integers);
    RUN_TEST(test_sign_ecdsa_bad_signature);
    RUN_TEST(test_sign_ecdsa_curve_mismatch);
    RUN_TEST(test_sign_eddsa);
    RUN_TEST(test_sign_eddsa_too_long);
    RUN_TEST(test_sign_unsupported_key);
    RUN_TEST(test_decipher_empty);
    RUN_TEST(test_decipher_unknown_padding);
    RUN_TEST(test_decipher_rsa);
    RUN_TEST(test_decipher_rsa_wrong_key);
    RUN_TEST(test_decipher_aes);
    RUN_TEST(test_aes_key_sizes);
    RUN_TEST(test_encipher_aes);
    RUN_TEST(test_pso_unknown);
    RUN_TEST(test_ecdh_p256);
    RUN_TEST(test_ecdh_cv25519);
    RUN_TEST(test_ecdh_wrong_key);
    RUN_TEST(test_ecdh_malformed);
    RUN_TEST(test_ecdh_wrong_point_size);
    RUN_TEST(test_authenticate_rsa);
    RUN_TEST(test_authenticate_rsa_too_long);
    return UNITY_END();
}
