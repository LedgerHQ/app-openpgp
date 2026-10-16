#include <string.h>

#include "unity.h"

// The dispatcher is built here, under another name than its mock from gpg_api.h
#define gpg_dispatch gpg_dispatch_under_test
#include "gpg_dispatch.c"
#undef gpg_dispatch

#include "Mockgpg_api.h"
#include "Mockgpg_ux.h"
#include "Mockmain_std_app.h"

// Verification status of PW1, PW2, PW3 and RC, by PIN reference
static int verified[PIN_ID_RC + 1];

static int fake_is_verified(int pinID, int num_calls) {
    (void) num_calls;
    TEST_ASSERT_TRUE((pinID >= PIN_ID_PW1) && (pinID <= PIN_ID_RC));
    return verified[pinID];
}

static void fake_set_verified(int pinID, int value, int num_calls) {
    (void) num_calls;
    TEST_ASSERT_TRUE((pinID >= PIN_ID_PW1) && (pinID <= PIN_ID_RC));
    verified[pinID] = value;
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    memset(verified, 0, sizeof(verified));
    N_gpg_pstate->histo[HISTO_OFFSET_STATE] = STATE_ACTIVATE;

    Mockgpg_api_Init();
    Mockgpg_ux_Init();
    Mockmain_std_app_Init();
    gpg_pin_is_verified_StubWithCallback(fake_is_verified);
    gpg_pin_set_verified_StubWithCallback(fake_set_verified);
    gpg_io_discard_Ignore();
}

void tearDown(void) {
    Mockgpg_api_Verify();
    Mockgpg_ux_Verify();
    Mockmain_std_app_Verify();
    Mockgpg_api_Destroy();
    Mockgpg_ux_Destroy();
    Mockmain_std_app_Destroy();
}

static void command(unsigned char ins, unsigned char p1, unsigned char p2) {
    G_gpg_vstate.io_cla = CLA_APP_DEF;
    G_gpg_vstate.io_ins = ins;
    G_gpg_vstate.io_p1 = p1;
    G_gpg_vstate.io_p2 = p2;
    G_gpg_vstate.io_p1p2 = (p1 << 8) | p2;
}

static int dispatch(unsigned char ins, unsigned char p1, unsigned char p2) {
    command(ins, p1, p2);
    return gpg_dispatch_under_test();
}

/* ----------------------------------------------------------------------- */
/* Command filtering                                                       */
/* ----------------------------------------------------------------------- */

static void test_ui_pending(void) {
    G_gpg_vstate.ui_pending = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_SELECT, 0x04, 0x00));
}

static void test_class(void) {
    static const unsigned char classes[] = {CLA_APP_SM, CLA_APP_CHAIN, CLA_APP_CHAIN_SM, 0x80};

    for (size_t i = 0; i < sizeof(classes); i++) {
        command(INS_GET_DATA, 0x00, 0x6E);
        G_gpg_vstate.io_cla = classes[i];
        TEST_ASSERT_EQUAL_HEX16(SWO_INVALID_CLA, gpg_dispatch_under_test());
    }

    // The class of the on-device PIN entry
    command(INS_VERIFY, 0x00, PIN_ID_PW1);
    G_gpg_vstate.io_cla = CLA_APP_APDU_PIN;
    gpg_apdu_verify_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_dispatch_under_test());
}

static void test_unknown_instruction(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_INVALID_INS, dispatch(0x00, 0x00, 0x00));
    // GET LOG only exists in GPG_LOG builds
    TEST_ASSERT_EQUAL_HEX16(SWO_INVALID_INS, dispatch(0x04, 0x00, 0x00));
}

/* ----------------------------------------------------------------------- */
/* Life cycle                                                              */
/* ----------------------------------------------------------------------- */

static void test_select(void) {
    gpg_apdu_select_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_SELECT, 0x04, 0x00));
}

static void test_terminated(void) {
    N_gpg_pstate->histo[HISTO_OFFSET_STATE] = STATE_TERMINATE;
    verified[PIN_ID_PW3] = 1;

    // Only SELECT, ACTIVATE FILE and TERMINATE DF are processed
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_INPUT_DATA_AVAILABLE, dispatch(INS_GET_DATA, 0x00, 0x6E));
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_INPUT_DATA_AVAILABLE, dispatch(INS_VERIFY, 0x00, PIN_ID_PW3));
    gpg_apdu_select_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_SELECT, 0x04, 0x00));
}

static void test_activate(void) {
    // No effect on an active application
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_ACTIVATE_FILE, 0x00, 0x00));

    N_gpg_pstate->histo[HISTO_OFFSET_STATE] = STATE_TERMINATE;
    gpg_install_Expect(STATE_ACTIVATE);
    gpg_init_session_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_ACTIVATE_FILE, 0x00, 0x00));
}

static gpg_pin_t pw3;

static void test_terminate(void) {
    // PW3 neither verified nor blocked
    gpg_pin_get_pin_ExpectAndReturn(PIN_ID_PW3, &pw3);
    gpg_pin_is_blocked_ExpectAndReturn(&pw3, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_TERMINATE_DF, 0x00, 0x00));

    verified[PIN_ID_PW3] = 1;
    gpg_install_Expect(STATE_TERMINATE);
    gpg_init_session_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_TERMINATE_DF, 0x00, 0x00));
}

static void test_terminate_pw3_blocked(void) {
    // Confirmed on the device, which then sends the status word
    gpg_pin_get_pin_ExpectAndReturn(PIN_ID_PW3, &pw3);
    gpg_pin_is_blocked_ExpectAndReturn(&pw3, 1);
    ui_menu_terminate_display_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_NO_RESPONSE, dispatch(INS_TERMINATE_DF, 0x00, 0x00));
}

/* ----------------------------------------------------------------------- */
/* PIN commands                                                            */
/* ----------------------------------------------------------------------- */

static void test_verify(void) {
    static const unsigned char refs[] = {PIN_ID_PW1, PIN_ID_PW2, PIN_ID_PW3};

    for (size_t i = 0; i < sizeof(refs); i++) {
        gpg_apdu_verify_ExpectAndReturn(SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_VERIFY, 0x00, refs[i]));
    }
    // The Resetting Code is not verified on its own
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, dispatch(INS_VERIFY, 0x00, PIN_ID_RC));
}

static void test_change_reference_data(void) {
    gpg_apdu_change_ref_data_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_CHANGE_REFERENCE_DATA, 0x00, PIN_ID_PW1));
    gpg_apdu_change_ref_data_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_CHANGE_REFERENCE_DATA, 0x00, PIN_ID_PW3));

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, dispatch(INS_CHANGE_REFERENCE_DATA, 0x00, PIN_ID_PW2));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, dispatch(INS_CHANGE_REFERENCE_DATA, 0x00, PIN_ID_RC));
}

static void test_reset_retry_counter(void) {
    // With the Resetting Code in the data, checked by the command itself
    gpg_apdu_reset_retry_counter_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            dispatch(INS_RESET_RETRY_COUNTER, RESET_RETRY_WITH_CODE, PIN_ID_PW1));

    // With PW3
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_RESET_RETRY_COUNTER, RESET_RETRY_WITH_PW3, PIN_ID_PW1));
    verified[PIN_ID_PW3] = 1;
    gpg_apdu_reset_retry_counter_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            dispatch(INS_RESET_RETRY_COUNTER, RESET_RETRY_WITH_PW3, PIN_ID_PW1));

    // Only PW1 can be reset
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2,
                            dispatch(INS_RESET_RETRY_COUNTER, RESET_RETRY_WITH_PW3, PIN_ID_PW3));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, dispatch(INS_RESET_RETRY_COUNTER, 0x01, PIN_ID_PW1));
}

/* ----------------------------------------------------------------------- */
/* Key commands                                                            */
/* ----------------------------------------------------------------------- */

static void test_generate_key(void) {
    // Reading a public key is always allowed
    gpg_apdu_gen_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GEN_ASYM_KEYPAIR, READ_ASYM_KEY >> 8, 0x00));

    // Generating one requires PW3
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_GEN_ASYM_KEYPAIR, GEN_ASYM_KEY >> 8, 0x00));
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_GEN_ASYM_KEYPAIR, GEN_ASYM_KEY >> 8, 0x00));
    verified[PIN_ID_PW3] = 1;
    gpg_apdu_gen_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GEN_ASYM_KEYPAIR, GEN_ASYM_KEY >> 8, 0x00));
}

static void test_sign(void) {
    // PSO:CDS requires PW1, not PW2 or PW3
    verified[PIN_ID_PW2] = 1;
    verified[PIN_ID_PW3] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_PSO, PSO_CDS >> 8, PSO_CDS & 0xFF));

    verified[PIN_ID_PW1] = 1;
    N_gpg_pstate->PW_status[0] = 1;
    gpg_apdu_pso_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PSO, PSO_CDS >> 8, PSO_CDS & 0xFF));
    // Valid for several signatures
    TEST_ASSERT_TRUE(verified[PIN_ID_PW1]);
}

static void test_sign_single(void) {
    // PW1 is only valid for one signature
    verified[PIN_ID_PW1] = 1;
    N_gpg_pstate->PW_status[0] = 0;
    gpg_apdu_pso_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PSO, PSO_CDS >> 8, PSO_CDS & 0xFF));
    TEST_ASSERT_FALSE(verified[PIN_ID_PW1]);

    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_PSO, PSO_CDS >> 8, PSO_CDS & 0xFF));
}

static void test_decipher_encipher(void) {
    static const unsigned int p1p2[] = {PSO_DEC, PSO_ENC};

    for (size_t i = 0; i < sizeof(p1p2) / sizeof(p1p2[0]); i++) {
        // PW2 is required, PW1 is not enough
        verified[PIN_ID_PW2] = 0;
        verified[PIN_ID_PW1] = 1;
        verified[PIN_ID_PW3] = 1;
        TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                                dispatch(INS_PSO, p1p2[i] >> 8, p1p2[i] & 0xFF));
        verified[PIN_ID_PW2] = 1;
        gpg_apdu_pso_ExpectAndReturn(SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PSO, p1p2[i] >> 8, p1p2[i] & 0xFF));
    }
}

static void test_pso_unknown(void) {
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    verified[PIN_ID_PW3] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, dispatch(INS_PSO, 0x9E, 0x9B));
}

static void test_internal_authenticate(void) {
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW3] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_INTERNAL_AUTHENTICATE, 0x00, 0x00));
    verified[PIN_ID_PW2] = 1;
    gpg_apdu_internal_authenticate_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_INTERNAL_AUTHENTICATE, 0x00, 0x00));
}

static void test_always_allowed(void) {
    gpg_apdu_mse_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_MSE, 0x41, KEY_DEC));
    gpg_apdu_get_challenge_ExpectAndReturn(SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_CHALLENGE, 0x00, 0x00));
}

static void test_exit(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, dispatch(INS_EXIT, 0x00, 0x00));

    verified[PIN_ID_PW2] = 1;
    app_exit_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_EXIT, 0x00, 0x00));
}

/* ----------------------------------------------------------------------- */
/* Data objects                                                            */
/* ----------------------------------------------------------------------- */

static void test_get_data_always(void) {
    static const unsigned int refs[] = {0x0101,
                                        0x0102,
                                        0x006E,
                                        0x0065,
                                        0x007A,
                                        0x004F,
                                        0x005E,
                                        0x5F50,
                                        0x5F52,
                                        0x7F21,
                                        0x00C4,
                                        0x7F74};

    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        gpg_apdu_get_data_ExpectAndReturn(refs[i], SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_DATA, refs[i] >> 8, refs[i] & 0xFF));
    }
}

static void test_get_data_protected(void) {
    // 0103 after PW2, 0104 after PW3
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW3] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_GET_DATA, 0x01, 0x03));
    verified[PIN_ID_PW2] = 1;
    gpg_apdu_get_data_ExpectAndReturn(0x0103, SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_DATA, 0x01, 0x03));

    verified[PIN_ID_PW3] = 0;
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_GET_DATA, 0x01, 0x04));
    verified[PIN_ID_PW3] = 1;
    gpg_apdu_get_data_ExpectAndReturn(0x0104, SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_DATA, 0x01, 0x04));
}

static void test_get_key_backup(void) {
    static const unsigned int refs[] = {KEY_SIG, KEY_DEC, KEY_AUT};

    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        verified[PIN_ID_PW3] = 0;
        TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                                dispatch(INS_GET_DATA, 0x00, refs[i]));
        verified[PIN_ID_PW3] = 1;
        gpg_apdu_get_key_data_ExpectAndReturn(refs[i], SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_DATA, 0x00, refs[i]));
    }
}

static void test_get_data_unknown(void) {
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    verified[PIN_ID_PW3] = 1;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_GET_DATA, 0x12, 0x34));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_GET_NEXT_DATA, 0x12, 0x34));
}

static void test_get_next_data(void) {
    gpg_apdu_get_next_data_ExpectAndReturn(0x7F21, SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_GET_NEXT_DATA, 0x7F, 0x21));
}

static void test_put_data_pw2(void) {
    static const unsigned int refs[] = {0x0101, 0x0103, 0x01F2};

    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW3] = 1;
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        verified[PIN_ID_PW2] = 0;
        TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                                dispatch(INS_PUT_DATA, refs[i] >> 8, refs[i] & 0xFF));
        verified[PIN_ID_PW2] = 1;
        gpg_apdu_put_data_ExpectAndReturn(refs[i], SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PUT_DATA, refs[i] >> 8, refs[i] & 0xFF));
    }
}

static void test_put_data_pw3(void) {
    static const unsigned int refs[] = {0x0102,
                                        0x0104,
                                        0x01F1,
                                        0x01F8,
                                        0x004F,
                                        0x005B,
                                        0x005E,
                                        0x5F2D,
                                        0x5F35,
                                        0x5F50,
                                        0x7F21,
                                        0x00C1,
                                        0x00C4,
                                        0x00C7,
                                        0x00CE,
                                        0x00D3,
                                        0x00D5,
                                        0x00D6};

    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        verified[PIN_ID_PW3] = 0;
        TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                                dispatch(INS_PUT_DATA, refs[i] >> 8, refs[i] & 0xFF));
        verified[PIN_ID_PW3] = 1;
        gpg_apdu_put_data_ExpectAndReturn(refs[i], SWO_SUCCESS);
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PUT_DATA, refs[i] >> 8, refs[i] & 0xFF));
    }
}

static void test_put_key(void) {
    // Key import with PUT DATA odd, and key restore
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            dispatch(INS_PUT_DATA_ODD, 0x3F, 0xFF));
    verified[PIN_ID_PW3] = 1;
    gpg_apdu_put_data_ExpectAndReturn(0x3FFF, SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PUT_DATA_ODD, 0x3F, 0xFF));

    gpg_apdu_put_key_data_ExpectAndReturn(KEY_AUT, SWO_SUCCESS);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, dispatch(INS_PUT_DATA, 0x00, KEY_AUT));
}

static void test_put_data_unknown(void) {
    verified[PIN_ID_PW1] = 1;
    verified[PIN_ID_PW2] = 1;
    verified[PIN_ID_PW3] = 1;
    // Including the read-only DOs
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_PUT_DATA, 0x00, 0x6E));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_PUT_DATA, 0x00, 0x7A));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, dispatch(INS_PUT_DATA, 0x12, 0x34));
}

/* ----------------------------------------------------------------------- */
/* SELECT DATA                                                             */
/* ----------------------------------------------------------------------- */

static int select_data(unsigned char p1, const unsigned char *data, unsigned int len) {
    command(INS_SELECT_DATA, p1, SELECT_SKIP);
    memcpy(G_gpg_vstate.work.io_buffer, data, len);
    G_gpg_vstate.io_length = len;
    return gpg_dispatch_under_test();
}

static void test_select_data(void) {
    const unsigned char tag1[] = {0x60, 0x03, 0x5C, 0x01, 0x6E};
    const unsigned char tag2[] = {0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21};

    gpg_apdu_select_data_Expect(0x6E, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_data(0, tag1, sizeof(tag1)));
    gpg_apdu_select_data_Expect(0x7F21, SELECT_MAX_INSTANCE);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, select_data(SELECT_MAX_INSTANCE, tag2, sizeof(tag2)));
}

static void test_select_data_parameters(void) {
    const unsigned char tag2[] = {0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2,
                            select_data(SELECT_MAX_INSTANCE + 1, tag2, sizeof(tag2)));
    command(INS_SELECT_DATA, 0x00, 0x00);
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_P1_P2, gpg_dispatch_under_test());
}

static void test_select_data_malformed(void) {
    const unsigned char bad_template[] = {0x61, 0x04, 0x5C, 0x02, 0x7F, 0x21};
    const unsigned char bad_outer_len[] = {0x60, 0x05, 0x5C, 0x02, 0x7F, 0x21};
    const unsigned char bad_tag_list[] = {0x60, 0x04, 0x5D, 0x02, 0x7F, 0x21};
    const unsigned char bad_inner_len[] = {0x60, 0x04, 0x5C, 0x01, 0x7F, 0x21};
    const unsigned char too_short[] = {0x60, 0x02, 0x5C, 0x00};
    const unsigned char too_long[] = {0x60, 0x05, 0x5C, 0x03, 0x00, 0x7F, 0x21};

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, bad_template, 6));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, bad_outer_len, 6));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, bad_tag_list, 6));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, bad_inner_len, 6));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, too_short, sizeof(too_short)));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, select_data(0, too_long, sizeof(too_long)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ui_pending);
    RUN_TEST(test_class);
    RUN_TEST(test_unknown_instruction);
    RUN_TEST(test_select);
    RUN_TEST(test_terminated);
    RUN_TEST(test_activate);
    RUN_TEST(test_terminate);
    RUN_TEST(test_terminate_pw3_blocked);
    RUN_TEST(test_verify);
    RUN_TEST(test_change_reference_data);
    RUN_TEST(test_reset_retry_counter);
    RUN_TEST(test_generate_key);
    RUN_TEST(test_sign);
    RUN_TEST(test_sign_single);
    RUN_TEST(test_decipher_encipher);
    RUN_TEST(test_pso_unknown);
    RUN_TEST(test_internal_authenticate);
    RUN_TEST(test_always_allowed);
    RUN_TEST(test_exit);
    RUN_TEST(test_get_data_always);
    RUN_TEST(test_get_data_protected);
    RUN_TEST(test_get_key_backup);
    RUN_TEST(test_get_data_unknown);
    RUN_TEST(test_get_next_data);
    RUN_TEST(test_put_data_pw2);
    RUN_TEST(test_put_data_pw3);
    RUN_TEST(test_put_key);
    RUN_TEST(test_put_data_unknown);
    RUN_TEST(test_select_data);
    RUN_TEST(test_select_data_parameters);
    RUN_TEST(test_select_data_malformed);
    return UNITY_END();
}
