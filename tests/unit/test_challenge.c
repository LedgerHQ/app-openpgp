#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "fake_digest.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_math.h"
#include "Mocklcx_rng.h"
#include "Mocklcx_sha256.h"
#include "Mocklcx_sha3.h"

static void fake_rng(uint8_t *buffer, size_t len, int num_calls) {
    (void) num_calls;
    memset(buffer, 0x5C, len);
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    Mocklcx_hash_Init();
    Mocklcx_math_Init();
    Mocklcx_rng_Init();
    Mocklcx_sha256_Init();
    Mocklcx_sha3_Init();
    fake_digest_install();
    cx_rng_no_throw_StubWithCallback(fake_rng);
    cx_sha3_xof_init_no_throw_IgnoreAndReturn(CX_OK);
}

void tearDown(void) {
    Mocklcx_math_Verify();
    Mocklcx_hash_Destroy();
    Mocklcx_math_Destroy();
    Mocklcx_rng_Destroy();
    Mocklcx_sha256_Destroy();
    Mocklcx_sha3_Destroy();
}

static int challenge(unsigned char p1,
                     unsigned char p2,
                     unsigned char le,
                     const uint8_t *data,
                     size_t len) {
    G_gpg_vstate.io_p1 = p1;
    G_gpg_vstate.io_p2 = p2;
    G_gpg_vstate.io_le = le;
    gpg_io_discard(1);
    if (len != 0) {
        gpg_io_insert(data, len);
        gpg_io_set_offset(0);
    }
    return gpg_apdu_get_challenge();
}

static void test_challenge(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, challenge(CHALLENGE_NOMINAL, 0x00, 32, NULL, 0));
    TEST_ASSERT_EQUAL_UINT(32, G_gpg_vstate.io_length);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x5C, G_gpg_vstate.work.io_buffer, 32);
}

static void test_challenge_length(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            challenge(CHALLENGE_NOMINAL, 0x00, GPG_EXT_CHALLENGE_LENTH, NULL, 0));
    TEST_ASSERT_EQUAL_UINT(GPG_EXT_CHALLENGE_LENTH, G_gpg_vstate.io_length);

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, challenge(CHALLENGE_NOMINAL, 0x00, 0, NULL, 0));
    TEST_ASSERT_EQUAL_HEX16(
        SWO_WRONG_LENGTH,
        challenge(CHALLENGE_NOMINAL, 0x00, GPG_EXT_CHALLENGE_LENTH + 1, NULL, 0));
}

static void test_challenge_parameters(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, challenge(0x03, 0x00, 32, NULL, 0));
}

static void test_challenge_prime(void) {
    cx_math_next_prime_no_throw_ExpectAndReturn(G_gpg_vstate.work.io_buffer, 64, CX_OK);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, challenge(PRIME_MODE, 0x00, 64, NULL, 0));
    TEST_ASSERT_EQUAL_UINT(64, G_gpg_vstate.io_length);
}

static void test_challenge_seeded(void) {
    // Derived from the seed and the command data: the length is in P2
    const uint8_t data[] = {'s', 'a', 'l', 't'};
    uint8_t first[48];

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            challenge(SEEDED_MODE, sizeof(first), 0, data, sizeof(data)));
    TEST_ASSERT_EQUAL_UINT(sizeof(first), G_gpg_vstate.io_length);
    memcpy(first, G_gpg_vstate.work.io_buffer, sizeof(first));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            challenge(SEEDED_MODE, sizeof(first), 0, data, sizeof(data)));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first, G_gpg_vstate.work.io_buffer, sizeof(first));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, challenge(SEEDED_MODE, sizeof(first), 0, data, 3));
    TEST_ASSERT_FALSE(memcmp(first, G_gpg_vstate.work.io_buffer, sizeof(first)) == 0);

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, challenge(SEEDED_MODE, 0, 32, data, sizeof(data)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_challenge);
    RUN_TEST(test_challenge_length);
    RUN_TEST(test_challenge_parameters);
    RUN_TEST(test_challenge_prime);
    RUN_TEST(test_challenge_seeded);
    return UNITY_END();
}
