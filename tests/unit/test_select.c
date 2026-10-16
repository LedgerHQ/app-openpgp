#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"

static const uint8_t AID[AID_LENGTH] = {0xD2,
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

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    memcpy((void *) N_gpg_pstate->AID, AID, sizeof(AID));
    N_gpg_pstate->histo[HISTO_OFFSET_STATE] = STATE_ACTIVATE;
    G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[0];
}

void tearDown(void) {
}

static int select_file(const uint8_t *data, size_t len) {
    gpg_io_discard(1);
    gpg_io_insert(data, len);
    gpg_io_set_offset(0);
    return gpg_apdu_select();
}

static void test_select_app(void) {
    G_gpg_vstate.DO_current = 0x7F21;
    G_gpg_vstate.DO_reccord = 2;

    // The RID and application number of the AID
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_file(AID, 6));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.DO_current);
    TEST_ASSERT_EQUAL_INT(0, G_gpg_vstate.DO_reccord);
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->aut, G_gpg_vstate.mse_aut);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_select_resets_pins(void) {
    gpg_pin_set_verified(PIN_ID_PW1, 1);
    gpg_pin_set_verified(PIN_ID_PW2, 1);
    gpg_pin_set_verified(PIN_ID_PW3, 1);
    G_gpg_vstate.mse_aut = &G_gpg_vstate.kslot->dec;

    // Every SELECT of the application starts a new session
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_file(AID, 6));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));
    TEST_ASSERT_EQUAL_PTR(&G_gpg_vstate.kslot->aut, G_gpg_vstate.mse_aut);
}

static void test_select_terminated(void) {
    N_gpg_pstate->histo[HISTO_OFFSET_STATE] = STATE_TERMINATE;
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_INPUT_DATA_AVAILABLE, select_file(AID, 6));
}

static void test_select_files(void) {
    const uint8_t mf[] = {0x3F, 0x00};
    const uint8_t ef_atr[] = {0x2F, 0x02};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_file(mf, sizeof(mf)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_file(ef_atr, sizeof(ef_atr)));
}

static void test_select_not_found(void) {
    const uint8_t other[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10};
    const uint8_t ef[] = {0x2F, 0x03};

    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, select_file(other, sizeof(other)));
    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, select_file(ef, sizeof(ef)));
    // Only the first 6 bytes of the AID are selected
    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, select_file(AID, 5));
    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, select_file(AID, 7));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_select_app);
    RUN_TEST(test_select_resets_pins);
    RUN_TEST(test_select_terminated);
    RUN_TEST(test_select_files);
    RUN_TEST(test_select_not_found);
    return UNITY_END();
}
