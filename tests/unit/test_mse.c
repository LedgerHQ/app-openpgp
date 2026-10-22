#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[0];
    gpg_mse_reset();
}

void tearDown(void) {
}

static int mse(unsigned char p1, unsigned char p2, const uint8_t *data, size_t len) {
    G_gpg_vstate.io_p1 = p1;
    G_gpg_vstate.io_p2 = p2;
    gpg_io_discard(1);
    if (len != 0) {
        gpg_io_insert(data, len);
        gpg_io_set_offset(0);
    }
    return gpg_apdu_mse();
}

static void test_mse_reset(void) {
    // Authentication with the AUT key, decryption with the DEC key
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->aut, G_gpg_vstate.mse_aut);
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->dec, G_gpg_vstate.mse_dec);
}

static void test_mse_swap(void) {
    const uint8_t use_dec[] = {0x83, 0x01, 0x02};
    const uint8_t use_aut[] = {0x83, 0x01, 0x03};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, mse(MSE_SET, KEY_AUT, use_dec, sizeof(use_dec)));
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->dec, G_gpg_vstate.mse_aut);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, mse(MSE_SET, KEY_DEC, use_aut, sizeof(use_aut)));
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->aut, G_gpg_vstate.mse_dec);

    gpg_mse_reset();
    test_mse_reset();
}

static void test_mse_parameters(void) {
    const uint8_t use_dec[] = {0x83, 0x01, 0x02};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, mse(0x81, KEY_AUT, use_dec, sizeof(use_dec)));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, mse(MSE_SET, KEY_SIG, use_dec, sizeof(use_dec)));
    test_mse_reset();
}

static void test_mse_data(void) {
    const uint8_t bad_tag[] = {0x84, 0x01, 0x02};
    const uint8_t bad_ref[] = {0x83, 0x01, 0x01};
    const uint8_t use_dec[] = {0x83, 0x01, 0x02};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, mse(MSE_SET, KEY_AUT, use_dec, 2));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, mse(MSE_SET, KEY_AUT, NULL, 0));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, mse(MSE_SET, KEY_AUT, bad_tag, sizeof(bad_tag)));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, mse(MSE_SET, KEY_AUT, bad_ref, sizeof(bad_ref)));
    test_mse_reset();
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_mse_reset);
    RUN_TEST(test_mse_swap);
    RUN_TEST(test_mse_parameters);
    RUN_TEST(test_mse_data);
    return UNITY_END();
}
