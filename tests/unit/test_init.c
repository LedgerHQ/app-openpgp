#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "Mocklcx_rng.h"

// SHA-256 of "123456" and "12345678"
static const uint8_t SHA256_123456[] = {
    0x8d, 0x96, 0x9e, 0xef, 0x6e, 0xca, 0xd3, 0xc2, 0x9a, 0x3a, 0x62, 0x92, 0x80, 0xe6, 0x86, 0xcf,
    0x0c, 0x3f, 0x5d, 0x5a, 0x86, 0xaf, 0xf3, 0xca, 0x12, 0x02, 0x0c, 0x92, 0x3a, 0xdc, 0x6c, 0x92};
static const uint8_t SHA256_12345678[] = {
    0xef, 0x79, 0x7c, 0x81, 0x18, 0xf0, 0x2d, 0xfb, 0x64, 0x96, 0x07, 0xdd, 0x5d, 0x3f, 0x8c, 0x76,
    0x23, 0x04, 0x8c, 0x9c, 0x06, 0x3d, 0x53, 0x2c, 0xc9, 0x5c, 0x5e, 0xd7, 0xa8, 0x98, 0xa6, 0x4f};
static const uint8_t ATTR_RSA2048[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x01};
// RID, OpenPGP application, version 3.3, Ledger manufacturer, then the serial bytes
static const uint8_t DEFAULT_AID[AID_LENGTH] = {0xD2,
                                                0x76,
                                                0x00,
                                                0x01,
                                                0x24,
                                                0x01,
                                                0x03,
                                                0x03,
                                                0x2C,
                                                0x97,
                                                0x00,
                                                0x00,
                                                0x00,
                                                0x00,
                                                0x00,
                                                0x00};
static const uint8_t MAGIC[] = {'G', 'P', 'G', 'C', 'A', 'R', 'D', '3'};

static unsigned int rng_calls;

static void fake_rng(uint8_t *buffer, size_t len, int num_calls) {
    (void) num_calls;
    memset(buffer, 0x40 + rng_calls++, len);
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0xA5, sizeof(gpg_nv_state_t));
    rng_calls = 0;
    Mocklcx_rng_Init();
    cx_rng_no_throw_StubWithCallback(fake_rng);
}

void tearDown(void) {
    Mocklcx_rng_Destroy();
}

/* ----------------------------------------------------------------------- */
/* Curves and OIDs                                                         */
/* ----------------------------------------------------------------------- */

static void test_oid_curve(void) {
    static const struct {
        const uint8_t *oid;
        size_t len;
        unsigned int curve;
    } curves[] = {
        {C_OID_SECP256R1, sizeof(C_OID_SECP256R1), CX_CURVE_SECP256R1},
        {C_OID_SECP256K1, sizeof(C_OID_SECP256K1), CX_CURVE_SECP256K1},
        {C_OID_Ed25519, sizeof(C_OID_Ed25519), CX_CURVE_Ed25519},
        {C_OID_cv25519, sizeof(C_OID_cv25519), CX_CURVE_Curve25519},
    };

    for (size_t i = 0; i < sizeof(curves) / sizeof(curves[0]); i++) {
        unsigned int len = 0;

        TEST_ASSERT_EQUAL_UINT(curves[i].curve,
                               gpg_oid2curve((unsigned char *) curves[i].oid, curves[i].len));
        TEST_ASSERT_EQUAL_PTR(curves[i].oid, gpg_curve2oid(curves[i].curve, &len));
        TEST_ASSERT_EQUAL_UINT(curves[i].len, len);
        TEST_ASSERT_EQUAL_UINT(32, gpg_curve2domainlen(curves[i].curve));
        // A truncated OID is unknown
        TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE,
                               gpg_oid2curve((unsigned char *) curves[i].oid, curves[i].len - 1));
    }
}

static void test_oid_unsupported(void) {
    // brainpoolP256r1 and secp384r1
    uint8_t brainpool[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
    uint8_t p384[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
    unsigned int len = 0xFF;

    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE, gpg_oid2curve(brainpool, sizeof(brainpool)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE, gpg_oid2curve(p384, sizeof(p384)));
    TEST_ASSERT_NULL(gpg_curve2oid(CX_CURVE_SECP384R1, &len));
    TEST_ASSERT_EQUAL_UINT(0, len);
    TEST_ASSERT_EQUAL_UINT(0, gpg_curve2domainlen(CX_CURVE_SECP384R1));
}

static unsigned int attributes_curve(uint8_t algo, const uint8_t *oid, size_t oid_len) {
    uint8_t attr[GPG_KEY_ATTRIBUTES_LENGTH];

    attr[0] = algo;
    memcpy(attr + 1, oid, oid_len);
    return gpg_attributes2curve(attr, 1 + oid_len);
}

static void test_attributes_curve(void) {
    // Each curve with the algorithms it supports
    TEST_ASSERT_EQUAL_UINT(
        CX_CURVE_SECP256R1,
        attributes_curve(KEY_ID_ECDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_SECP256R1,
                           attributes_curve(KEY_ID_ECDH, C_OID_SECP256R1, sizeof(C_OID_SECP256R1)));
    TEST_ASSERT_EQUAL_UINT(
        CX_CURVE_SECP256K1,
        attributes_curve(KEY_ID_ECDSA, C_OID_SECP256K1, sizeof(C_OID_SECP256K1)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_Ed25519,
                           attributes_curve(KEY_ID_EDDSA, C_OID_Ed25519, sizeof(C_OID_Ed25519)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_Curve25519,
                           attributes_curve(KEY_ID_ECDH, C_OID_cv25519, sizeof(C_OID_cv25519)));

    TEST_ASSERT_EQUAL_UINT(
        CX_CURVE_NONE,
        attributes_curve(KEY_ID_EDDSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE,
                           attributes_curve(KEY_ID_ECDSA, C_OID_Ed25519, sizeof(C_OID_Ed25519)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE,
                           attributes_curve(KEY_ID_ECDSA, C_OID_cv25519, sizeof(C_OID_cv25519)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE,
                           attributes_curve(KEY_ID_RSA, C_OID_SECP256R1, sizeof(C_OID_SECP256R1)));
    TEST_ASSERT_EQUAL_UINT(CX_CURVE_NONE, gpg_attributes2curve(ATTR_RSA2048, 0));
}

static void test_key_curve_matches_attributes(void) {
    gpg_key_t key;

    memset(&key, 0, sizeof(key));
    key.attributes.value[0] = KEY_ID_EDDSA;
    memcpy(key.attributes.value + 1, C_OID_Ed25519, sizeof(C_OID_Ed25519));
    key.attributes.length = 1 + sizeof(C_OID_Ed25519);

    TEST_ASSERT_TRUE(gpg_key_curve_matches_attributes(&key, CX_CURVE_Ed25519));
    TEST_ASSERT_FALSE(gpg_key_curve_matches_attributes(&key, CX_CURVE_Curve25519));
    TEST_ASSERT_FALSE(gpg_key_curve_matches_attributes(&key, CX_CURVE_NONE));

    key.attributes.length = 0;
    TEST_ASSERT_FALSE(gpg_key_curve_matches_attributes(&key, CX_CURVE_Ed25519));
}

/* ----------------------------------------------------------------------- */
/* Installation and session                                                */
/* ----------------------------------------------------------------------- */

static void check_slot(unsigned int s) {
    const gpg_key_slot_t *slot = (const gpg_key_slot_t *) &N_gpg_pstate->keys[s];
    const gpg_key_t *keys[] = {&slot->sig, &slot->dec, &slot->aut};

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        TEST_ASSERT_EQUAL_UINT(sizeof(ATTR_RSA2048), keys[i]->attributes.length);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048, keys[i]->attributes.value, sizeof(ATTR_RSA2048));
        TEST_ASSERT_EQUAL_HEX8(0x00, keys[i]->UIF[0]);
        TEST_ASSERT_EQUAL_HEX8(C_gen_feature, keys[i]->UIF[1]);
        TEST_ASSERT_EACH_EQUAL_HEX8(0,
                                    (const uint8_t *) &keys[i]->priv_key,
                                    sizeof(keys[i]->priv_key));
        TEST_ASSERT_EACH_EQUAL_HEX8(0, keys[i]->fingerprints, sizeof(keys[i]->fingerprints));
    }
    TEST_ASSERT_EQUAL_UINT(0, slot->sig_count);
}

static void test_install(void) {
    const uint8_t pw_status[] = {0x01, GPG_MAX_PW_LENGTH, GPG_MAX_PW_LENGTH, GPG_MAX_PW_LENGTH};
    const uint8_t config_slot[] = {GPG_KEYS_SLOTS, 0x00, 0x03};
    const uint8_t exponent[] = {0x00, 0x01, 0x00, 0x01};

    gpg_install(STATE_ACTIVATE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(MAGIC, N_gpg_pstate->magic, sizeof(MAGIC));
    TEST_ASSERT_EQUAL_HEX8(STATE_ACTIVATE, N_gpg_pstate->histo[HISTO_OFFSET_STATE]);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DEFAULT_AID, N_gpg_pstate->AID, AID_LENGTH);

    // Default PINs, the Resetting Code is not set
    TEST_ASSERT_EQUAL_UINT(GPG_MIN_PW1_LENGTH, N_gpg_pstate->PW1.length);
    TEST_ASSERT_EQUAL_UINT(3, N_gpg_pstate->PW1.counter);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(SHA256_123456, N_gpg_pstate->PW1.value, 32);
    TEST_ASSERT_EQUAL_UINT(GPG_MIN_PW3_LENGTH, N_gpg_pstate->PW3.length);
    TEST_ASSERT_EQUAL_UINT(3, N_gpg_pstate->PW3.counter);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(SHA256_12345678, N_gpg_pstate->PW3.value, 32);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->RC.length);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->RC.counter);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(pw_status, N_gpg_pstate->PW_status, sizeof(pw_status));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(config_slot, N_gpg_pstate->config_slot, sizeof(config_slot));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(exponent, N_gpg_pstate->default_RSA_exponent, sizeof(exponent));
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_CONFIRM, N_gpg_pstate->config_pin);
    TEST_ASSERT_TRUE(N_gpg_pstate->keypad_shuffle);
    TEST_ASSERT_EQUAL_HEX8('9', N_gpg_pstate->salutation[0]);

    // Data from a previous installation are erased
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->name.length);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->private_DO1.length);
    for (unsigned int s = 0; s < GPG_KEYS_SLOTS; s++) {
        check_slot(s);
    }
}

static void test_install_serials(void) {
    // Each slot gets its own random serial
    gpg_install(STATE_ACTIVATE);
    TEST_ASSERT_EQUAL_UINT(GPG_KEYS_SLOTS, rng_calls);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x40, N_gpg_pstate->keys[0].serial, 4);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x41, N_gpg_pstate->keys[1].serial, 4);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x42, N_gpg_pstate->keys[2].serial, 4);
}

static void test_install_terminated(void) {
    gpg_install(STATE_TERMINATE);

    // Everything is erased, without default PINs nor keys
    TEST_ASSERT_EQUAL_HEX8_ARRAY(MAGIC, N_gpg_pstate->magic, sizeof(MAGIC));
    TEST_ASSERT_EQUAL_HEX8(STATE_TERMINATE, N_gpg_pstate->histo[HISTO_OFFSET_STATE]);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->PW1.counter);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->PW3.counter);
    TEST_ASSERT_EQUAL_UINT(0, N_gpg_pstate->keys[0].sig.attributes.length);
    TEST_ASSERT_EQUAL_UINT(0, rng_calls);
}

static void test_init_first_start(void) {
    // Without the magic, the first start installs the application
    gpg_init();
    TEST_ASSERT_EQUAL_HEX8_ARRAY(MAGIC, N_gpg_pstate->magic, sizeof(MAGIC));
    TEST_ASSERT_EQUAL_HEX8(STATE_ACTIVATE, N_gpg_pstate->histo[HISTO_OFFSET_STATE]);
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->keys[0], G_gpg_vstate.kslot);
}

static void test_init_next_start(void) {
    gpg_install(STATE_ACTIVATE);
    N_gpg_pstate->name.length = 3;
    N_gpg_pstate->config_slot[1] = 2;
    N_gpg_pstate->config_pin = PIN_MODE_TRUST;
    gpg_pin_set_verified(PIN_ID_PW3, 1);
    rng_calls = 0;

    // The persistent data are kept, the session starts from them
    gpg_init();
    TEST_ASSERT_EQUAL_UINT(0, rng_calls);
    TEST_ASSERT_EQUAL_UINT(3, N_gpg_pstate->name.length);
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.slot);
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->keys[2], G_gpg_vstate.kslot);
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->keys[2].aut, G_gpg_vstate.mse_aut);
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->keys[2].dec, G_gpg_vstate.mse_dec);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_TRUST, G_gpg_vstate.pinmode);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.seed_mode);
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));
}

static void test_init_session(void) {
    gpg_install(STATE_ACTIVATE);
    gpg_pin_set_verified(PIN_ID_PW1, 1);
    gpg_pin_set_verified(PIN_ID_PW2, 1);
    gpg_pin_set_verified(PIN_ID_PW3, 1);
    G_gpg_vstate.mse_dec = NULL;

    gpg_init_session();
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->dec, G_gpg_vstate.mse_dec);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_oid_curve);
    RUN_TEST(test_oid_unsupported);
    RUN_TEST(test_attributes_curve);
    RUN_TEST(test_key_curve_matches_attributes);
    RUN_TEST(test_install);
    RUN_TEST(test_install_serials);
    RUN_TEST(test_install_terminated);
    RUN_TEST(test_init_first_start);
    RUN_TEST(test_init_next_start);
    RUN_TEST(test_init_session);
    return UNITY_END();
}
