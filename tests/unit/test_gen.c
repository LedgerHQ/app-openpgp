#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "fake_digest.h"
#include "Mockgpg_ux.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_math.h"
#include "Mocklcx_rsa.h"
#include "Mocklcx_sha256.h"
#include "Mocklcx_sha3.h"

#define RSA2048 (2048 / 8)
#define ECC_LEN 32

static const uint8_t ATTR_RSA2048[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};
static const uint8_t EXPONENT[] = {0x00, 0x01, 0x00, 0x01};

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    memcpy((void *) N_gpg_pstate->default_RSA_exponent, EXPONENT, sizeof(EXPONENT));

    Mockgpg_ux_Init();
    Mocklcx_ecfp_Init();
    Mocklcx_hash_Init();
    Mocklcx_math_Init();
    Mocklcx_rsa_Init();
    Mocklcx_sha256_Init();
    Mocklcx_sha3_Init();
    fake_digest_install();

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(0));
}

void tearDown(void) {
    Mockgpg_ux_Verify();
    Mocklcx_ecfp_Verify();
    Mocklcx_math_Verify();
    Mocklcx_rsa_Verify();
    Mockgpg_ux_Destroy();
    Mocklcx_ecfp_Destroy();
    Mocklcx_hash_Destroy();
    Mocklcx_math_Destroy();
    Mocklcx_rsa_Destroy();
    Mocklcx_sha256_Destroy();
    Mocklcx_sha3_Destroy();
}

/* ----------------------------------------------------------------------- */
/* Keys and commands                                                       */
/* ----------------------------------------------------------------------- */

static void set_attributes(gpg_key_t *key, const uint8_t *attr, size_t len) {
    memcpy((void *) key->attributes.value, attr, len);
    key->attributes.length = len;
}

static void set_ecc_attributes(gpg_key_t *key, uint8_t algo, const uint8_t *oid, size_t oid_len) {
    key->attributes.value[0] = algo;
    memcpy((void *) (key->attributes.value + 1), oid, oid_len);
    key->attributes.length = 1 + oid_len;
}

static void set_ecc_public(gpg_key_t *key, cx_curve_t curve, const uint8_t *W, size_t len) {
    key->pub_key.ecfp.curve = curve;
    key->pub_key.ecfp.W_len = len;
    memcpy((void *) key->pub_key.ecfp.W, W, len);
}

// GENERATE ASYMMETRIC KEY PAIR, with the CRT of the key in the data
static int gen(unsigned int p1p2, uint8_t crt) {
    const uint8_t data[] = {crt, 0x00};

    G_gpg_vstate.io_p1p2 = p1p2;
    G_gpg_vstate.io_p1 = p1p2 >> 8;
    G_gpg_vstate.io_p2 = p1p2 & 0xFF;
    gpg_io_discard(1);
    gpg_io_insert(data, sizeof(data));
    gpg_io_set_offset(0);
    return gpg_apdu_gen();
}

// Check the 7F49 template of the response, and return the offset of its first DO
static size_t check_template(void) {
    unsigned int t = 0;
    unsigned int l = 0;

    gpg_io_set_offset(0);
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x7F49, t);
    TEST_ASSERT_EQUAL_UINT(G_gpg_vstate.io_length - G_gpg_vstate.io_offset, l);
    return G_gpg_vstate.io_offset;
}

static void fetch_do(unsigned int tag, size_t len) {
    unsigned int t = 0;
    unsigned int l = 0;

    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(tag, t);
    TEST_ASSERT_EQUAL_UINT(len, l);
}

/* ----------------------------------------------------------------------- */
/* Command checks                                                          */
/* ----------------------------------------------------------------------- */

static void test_gen_parameters(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, gen(0x8003, KEY_SIG));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, gen(0x8200, KEY_SIG));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(READ_ASYM_KEY, 0xB7));

    // Control Reference Template on exactly 2 bytes
    G_gpg_vstate.io_p1p2 = READ_ASYM_KEY;
    gpg_io_discard(1);
    gpg_io_insert_u8(KEY_SIG);
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_apdu_gen());
    gpg_io_insert_u16(0);
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_apdu_gen());
}

/* ----------------------------------------------------------------------- */
/* Public key read                                                         */
/* ----------------------------------------------------------------------- */

static void test_read_rsa(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->sig;
    size_t n;

    set_attributes(key, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    key->priv_key.rsa2048.size = RSA2048;
    memset((void *) key->priv_key.rsa2048.n, 0xA7, RSA2048);
    memcpy((void *) key->pub_key.rsa, EXPONENT, sizeof(EXPONENT));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(READ_ASYM_KEY, KEY_SIG));
    n = check_template();
    fetch_do(0x81, RSA2048);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xA7, G_gpg_vstate.work.io_buffer + n + 4, RSA2048);
    G_gpg_vstate.io_offset += RSA2048;
    fetch_do(0x82, 4);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPONENT,
                                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                 sizeof(EXPONENT));
}

static void test_read_rsa_no_key(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, gen(READ_ASYM_KEY, KEY_SIG));
}

static void test_read_p256(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->aut;
    uint8_t W[65];
    size_t n;

    memset(W, 0x3C, sizeof(W));
    W[0] = 0x04;
    set_ecc_attributes(key, KEY_ID_ECDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1));
    set_ecc_public(key, CX_CURVE_SECP256R1, W, sizeof(W));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(READ_ASYM_KEY, KEY_AUT));
    n = check_template();
    fetch_do(0x86, sizeof(W));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(W, G_gpg_vstate.work.io_buffer + n + 2, sizeof(W));
}

// Edwards point compression: 02 || x, as the SDK writes it in place
static cx_err_t fake_compress(cx_curve_t curve, uint8_t *p, size_t p_len, int num_calls) {
    (void) num_calls;
    TEST_ASSERT_EQUAL_INT(CX_CURVE_Ed25519, curve);
    TEST_ASSERT_EQUAL_UINT(65, p_len);
    TEST_ASSERT_EQUAL_HEX8(0x04, p[0]);
    p[0] = 0x02;
    return CX_OK;
}

static void test_read_ed25519(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->sig;
    uint8_t W[65];
    size_t n;

    memset(W, 0xED, sizeof(W));
    W[0] = 0x04;
    set_ecc_attributes(key, KEY_ID_EDDSA, C_OID_Ed25519, sizeof(C_OID_Ed25519));
    set_ecc_public(key, CX_CURVE_Ed25519, W, sizeof(W));

    cx_edwards_compress_point_no_throw_StubWithCallback(fake_compress);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(READ_ASYM_KEY, KEY_SIG));
    n = check_template();
    fetch_do(0x86, ECC_LEN);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xED, G_gpg_vstate.work.io_buffer + n + 2, ECC_LEN);

    // Only an uncompressed point can be compressed
    W[0] = 0x02;
    set_ecc_public(key, CX_CURVE_Ed25519, W, sizeof(W));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(READ_ASYM_KEY, KEY_SIG));
    set_ecc_public(key, CX_CURVE_Ed25519, W, 33);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(READ_ASYM_KEY, KEY_SIG));
}

static void check_cv25519_read(const uint8_t *W, size_t len, const uint8_t *x) {
    gpg_key_t *key = &G_gpg_vstate.kslot->dec;
    size_t n;

    set_ecc_public(key, CX_CURVE_Curve25519, W, len);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(READ_ASYM_KEY, KEY_DEC));
    n = check_template();
    fetch_do(0x86, ECC_LEN);
    // Little-endian x
    for (size_t i = 0; i < ECC_LEN; i++) {
        TEST_ASSERT_EQUAL_HEX8(x[ECC_LEN - 1 - i], G_gpg_vstate.work.io_buffer[n + 2 + i]);
    }
}

static void test_read_cv25519(void) {
    uint8_t W[65];

    set_ecc_attributes(&G_gpg_vstate.kslot->dec, KEY_ID_ECDH, C_OID_cv25519, sizeof(C_OID_cv25519));
    W[0] = 0x04;
    for (size_t i = 1; i < sizeof(W); i++) {
        W[i] = (uint8_t) i;
    }
    // Uncompressed point, x with its prefix, or x alone
    check_cv25519_read(W, 65, W + 1);
    check_cv25519_read(W, 33, W + 1);
    check_cv25519_read(W + 1, 32, W + 1);

    set_ecc_public(&G_gpg_vstate.kslot->dec, CX_CURVE_Curve25519, W + 1, 33);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(READ_ASYM_KEY, KEY_DEC));
}

static void test_read_ecc_invalid(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->aut;
    uint8_t W[65] = {0x04};

    set_ecc_attributes(key, KEY_ID_ECDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1));

    // No key
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, gen(READ_ASYM_KEY, KEY_AUT));

    // A key on another curve than its attributes
    set_ecc_public(key, CX_CURVE_SECP256K1, W, sizeof(W));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, gen(READ_ASYM_KEY, KEY_AUT));

    // A point length beyond the stored point
    set_ecc_public(key, CX_CURVE_SECP256R1, W, sizeof(W));
    key->pub_key.ecfp.W_len = sizeof(key->pub_key.ecfp640.W) + 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(READ_ASYM_KEY, KEY_AUT));
}

/* ----------------------------------------------------------------------- */
/* RSA generation                                                          */
/* ----------------------------------------------------------------------- */

static const uint8_t *rsa_pq;
static uint8_t rsa_p_first;
static uint8_t rsa_q_first;

static cx_err_t fake_rsa_generate(size_t modulus_len,
                                  cx_rsa_public_key_t *public_key,
                                  cx_rsa_private_key_t *private_key,
                                  const uint8_t *pub_exponent,
                                  size_t exponent_len,
                                  const uint8_t *externalPQ,
                                  int num_calls) {
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(RSA2048, modulus_len);
    TEST_ASSERT_EQUAL_UINT(4, exponent_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPONENT, pub_exponent, sizeof(EXPONENT));
    rsa_pq = externalPQ;
    if (externalPQ != NULL) {
        rsa_p_first = externalPQ[0];
        rsa_q_first = externalPQ[RSA2048 / 2];
    }
    private_key->size = RSA2048;
    memset(((cx_rsa_2048_private_key_t *) private_key)->n, 0x4E, RSA2048);
    memcpy(public_key->e, pub_exponent, 4);
    return CX_OK;
}

static void test_gen_rsa_random(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->sig;

    set_attributes(key, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.kslot->sig_count = 9;

    cx_rsa_generate_pair_no_throw_StubWithCallback(fake_rsa_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY, KEY_SIG));
    TEST_ASSERT_NULL(rsa_pq);
    TEST_ASSERT_EQUAL_UINT(RSA2048, key->priv_key.rsa2048.size);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPONENT, key->pub_key.rsa, sizeof(EXPONENT));
    // A new signature key restarts the counter
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.kslot->sig_count);

    // The response is the new public key
    check_template();
    fetch_do(0x81, RSA2048);
}

static void test_gen_rsa_other_key_keeps_counter(void) {
    set_attributes(&G_gpg_vstate.kslot->dec, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.kslot->sig_count = 9;

    cx_rsa_generate_pair_no_throw_StubWithCallback(fake_rsa_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY, KEY_DEC));
    TEST_ASSERT_EQUAL_UINT(9, G_gpg_vstate.kslot->sig_count);
}

static void test_gen_rsa_invalid(void) {
    const uint8_t rsa1024[] = {KEY_ID_RSA, 0x04, 0x00, 0x00, 0x20, 0x00};
    const uint8_t even[] = {0x00, 0x01, 0x00, 0x00};

    set_attributes(&G_gpg_vstate.kslot->sig, rsa1024, sizeof(rsa1024));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gen(GEN_ASYM_KEY, KEY_SIG));

    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    memcpy((void *) N_gpg_pstate->default_RSA_exponent, even, sizeof(even));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, gen(GEN_ASYM_KEY, KEY_SIG));
}

static unsigned int prime_calls;

static cx_err_t fake_next_prime(uint8_t *r, uint32_t len, int num_calls) {
    (void) r;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(RSA2048 / 2, len);
    prime_calls++;
    return CX_OK;
}

static void test_gen_rsa_seed_v2(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));

    // Primes searched from the seed, with the two top bits set for a full-size modulus
    prime_calls = 0;
    cx_math_next_prime_no_throw_StubWithCallback(fake_next_prime);
    cx_rsa_generate_pair_no_throw_StubWithCallback(fake_rsa_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY_SEED_V2, KEY_SIG));
    TEST_ASSERT_EQUAL_UINT(2, prime_calls);
    TEST_ASSERT_NOT_NULL(rsa_pq);
    TEST_ASSERT_EQUAL_HEX8(0xC0, rsa_p_first & 0xC0);
    TEST_ASSERT_EQUAL_HEX8(0xC0, rsa_q_first & 0xC0);
    // Derived on the full prime length
    TEST_ASSERT_EQUAL_UINT((RSA2048 / 2) * 8, fake_shake_bits);
}

static void test_gen_seed_mode(void) {
    // The default mode follows the Seed mode setting
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.seed_mode = 1;

    cx_math_next_prime_no_throw_IgnoreAndReturn(CX_OK);
    cx_rsa_generate_pair_no_throw_StubWithCallback(fake_rsa_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY, KEY_SIG));
    TEST_ASSERT_NOT_NULL(rsa_pq);
}

static void test_gen_rsa_error_clears_ram(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    memset(&G_gpg_vstate.work, 0x77, sizeof(G_gpg_vstate.work));

    cx_math_next_prime_no_throw_ExpectAnyArgsAndReturn(CX_INTERNAL_ERROR);
    TEST_ASSERT_EQUAL_HEX32(CX_INTERNAL_ERROR, gen(GEN_ASYM_KEY_SEED_V2, KEY_SIG));
    TEST_ASSERT_EACH_EQUAL_HEX8(0, (const uint8_t *) &G_gpg_vstate.work, sizeof(G_gpg_vstate.work));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.kslot->sig.priv_key.rsa2048.size);
}

/* ----------------------------------------------------------------------- */
/* ECC generation                                                          */
/* ----------------------------------------------------------------------- */

static uint8_t ecc_d[ECC_LEN];
static bool ecc_keepprivate;

static cx_err_t fake_init_private(cx_curve_t curve,
                                  const uint8_t *rawkey,
                                  size_t key_len,
                                  cx_ecfp_private_key_t *pvkey,
                                  int num_calls) {
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(ECC_LEN, key_len);
    memcpy(ecc_d, rawkey, key_len);
    pvkey->curve = curve;
    pvkey->d_len = key_len;
    memcpy(pvkey->d, rawkey, key_len);
    return CX_OK;
}

static cx_err_t fake_ecc_generate(cx_curve_t curve,
                                  cx_ecfp_public_key_t *pubkey,
                                  cx_ecfp_private_key_t *privkey,
                                  bool keepprivate,
                                  int num_calls) {
    (void) num_calls;
    ecc_keepprivate = keepprivate;
    if (!keepprivate) {
        privkey->curve = curve;
        privkey->d_len = ECC_LEN;
        memset(privkey->d, 0xD0, ECC_LEN);
    }
    pubkey->curve = curve;
    pubkey->W_len = 65;
    memset(pubkey->W, 0x50, 65);
    pubkey->W[0] = 0x04;
    return CX_OK;
}

static void test_gen_ecc_random(void) {
    gpg_key_t *key = &G_gpg_vstate.kslot->aut;

    set_ecc_attributes(key, KEY_ID_ECDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1));
    cx_ecfp_generate_pair_no_throw_StubWithCallback(fake_ecc_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY, KEY_AUT));
    TEST_ASSERT_FALSE(ecc_keepprivate);
    TEST_ASSERT_EQUAL_UINT(ECC_LEN, key->priv_key.ecfp.d_len);
    TEST_ASSERT_EQUAL_UINT(65, key->pub_key.ecfp.W_len);

    check_template();
    fetch_do(0x86, 65);
}

static unsigned int modm_calls;

static cx_err_t fake_modm(uint8_t *v, size_t len_v, const uint8_t *m, size_t len_m, int num_calls) {
    (void) v;
    (void) m;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(2 * ECC_LEN, len_v);
    TEST_ASSERT_EQUAL_UINT(ECC_LEN, len_m);
    modm_calls++;
    return CX_OK;
}

static void test_gen_ecc_seed_v2(void) {
    set_ecc_attributes(&G_gpg_vstate.kslot->dec, KEY_ID_ECDH, C_OID_cv25519, sizeof(C_OID_cv25519));

    // Derived on twice the curve size, then reduced modulo the order
    modm_calls = 0;
    cx_math_modm_no_throw_StubWithCallback(fake_modm);
    cx_ecfp_init_private_key_no_throw_StubWithCallback(fake_init_private);
    cx_ecfp_generate_pair_no_throw_StubWithCallback(fake_ecc_generate);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY_SEED_V2, KEY_DEC));
    TEST_ASSERT_TRUE(ecc_keepprivate);
    TEST_ASSERT_EQUAL_UINT(1, modm_calls);
    TEST_ASSERT_EQUAL_UINT(2 * ECC_LEN * 8, fake_shake_bits);

    // Clamped as a X25519 scalar, big-endian
    TEST_ASSERT_EQUAL_HEX8(0x00, ecc_d[ECC_LEN - 1] & 0x07);
    TEST_ASSERT_EQUAL_HEX8(0x40, ecc_d[0] & 0xC0);
}

static void test_gen_ecc_seed_is_deterministic(void) {
    uint8_t first[ECC_LEN];

    set_ecc_attributes(&G_gpg_vstate.kslot->sig,
                       KEY_ID_EDDSA,
                       C_OID_Ed25519,
                       sizeof(C_OID_Ed25519));
    cx_math_modm_no_throw_IgnoreAndReturn(CX_OK);
    cx_ecfp_init_private_key_no_throw_StubWithCallback(fake_init_private);
    cx_ecfp_generate_pair_no_throw_StubWithCallback(fake_ecc_generate);
    cx_edwards_compress_point_no_throw_StubWithCallback(fake_compress);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY_SEED_V2, KEY_SIG));
    memcpy(first, ecc_d, sizeof(first));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY_SEED_V2, KEY_SIG));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first, ecc_d, sizeof(first));

    // Another slot gives another key
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(1));
    set_ecc_attributes(&G_gpg_vstate.kslot->sig,
                       KEY_ID_EDDSA,
                       C_OID_Ed25519,
                       sizeof(C_OID_Ed25519));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gen(GEN_ASYM_KEY_SEED_V2, KEY_SIG));
    TEST_ASSERT_FALSE(memcmp(first, ecc_d, sizeof(first)) == 0);
}

static void test_gen_ecc_unsupported_curve(void) {
    // brainpoolP256r1
    const uint8_t oid[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};

    set_ecc_attributes(&G_gpg_vstate.kslot->aut, KEY_ID_ECDSA, oid, sizeof(oid));
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, gen(GEN_ASYM_KEY, KEY_AUT));
}

static void test_gen_wrong_mode(void) {
    set_ecc_attributes(&G_gpg_vstate.kslot->aut,
                       KEY_ID_ECDSA,
                       C_OID_SECP256R1,
                       sizeof(C_OID_SECP256R1));
    G_gpg_vstate.io_p2 = 0x03;
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, gen(GEN_ASYM_KEY | 0x03, KEY_AUT));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_gen_parameters);
    RUN_TEST(test_read_rsa);
    RUN_TEST(test_read_rsa_no_key);
    RUN_TEST(test_read_p256);
    RUN_TEST(test_read_ed25519);
    RUN_TEST(test_read_cv25519);
    RUN_TEST(test_read_ecc_invalid);
    RUN_TEST(test_gen_rsa_random);
    RUN_TEST(test_gen_rsa_other_key_keeps_counter);
    RUN_TEST(test_gen_rsa_invalid);
    RUN_TEST(test_gen_rsa_seed_v2);
    RUN_TEST(test_gen_seed_mode);
    RUN_TEST(test_gen_rsa_error_clears_ram);
    RUN_TEST(test_gen_ecc_random);
    RUN_TEST(test_gen_ecc_seed_v2);
    RUN_TEST(test_gen_ecc_seed_is_deterministic);
    RUN_TEST(test_gen_ecc_unsupported_curve);
    RUN_TEST(test_gen_wrong_mode);
    return UNITY_END();
}
