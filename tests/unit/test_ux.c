#include <stdint.h>
#include <string.h>

#include "unity.h"

// The UI is built here, so that the tests reach its static callbacks
#include "gpg_ux_nbgl.c"

#include "Mockgpg_api.h"
#include "Mocknbgl_layout.h"
#include "Mocknbgl_use_case.h"
#include "Mockmain_std_app.h"

const nbgl_icon_details_t C_gpg_14px;
const nbgl_icon_details_t C_gpg_48px;
const nbgl_icon_details_t C_gpg_64px;

// Verification status of PW1, PW2, PW3 and RC, by PIN reference
static int verified[PIN_ID_RC + 1];
static gpg_pin_t pins[PIN_ID_RC + 1];

static int fake_is_verified(int pinID, int num_calls) {
    (void) num_calls;
    return verified[pinID];
}

static void fake_set_verified(int pinID, int value, int num_calls) {
    (void) num_calls;
    verified[pinID] = value;
}

static gpg_pin_t *fake_get_pin(int id, int num_calls) {
    (void) num_calls;
    return &pins[id];
}

// Status words sent back to the host by the callbacks
static unsigned int sent_sw;
static unsigned int sent_count;

static void fake_insert_u16(unsigned int v16, int num_calls) {
    (void) num_calls;
    sent_sw = v16;
}

static unsigned int fake_io_do(unsigned int io_flags, int num_calls) {
    (void) num_calls;
    TEST_ASSERT_EQUAL_HEX(IO_RETURN_AFTER_TX, io_flags);
    sent_count++;
    return SWO_SUCCESS;
}

// The keypad shown by the last PIN entry
static nbgl_pinValidCallback_t keypad_validate;
static nbgl_callback_t keypad_back;

static void fake_keypad(const char *title,
                        uint8_t minDigits,
                        uint8_t maxDigits,
                        bool shuffled,
                        bool hidden,
                        nbgl_pinValidCallback_t validatePinCallback,
                        nbgl_callback_t backCallback,
                        int num_calls) {
    (void) title;
    (void) minDigits;
    (void) maxDigits;
    (void) shuffled;
    (void) hidden;
    (void) num_calls;
    keypad_validate = validatePinCallback;
    keypad_back = backCallback;
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    memset(verified, 0, sizeof(verified));
    memset(pins, 0, sizeof(pins));
    G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[0];
    sent_sw = 0;
    sent_count = 0;
    keypad_validate = NULL;
    keypad_back = NULL;

    Mockgpg_api_Init();
    Mocknbgl_layout_Init();
    Mocknbgl_use_case_Init();
    Mockmain_std_app_Init();
    gpg_pin_is_verified_StubWithCallback(fake_is_verified);
    gpg_pin_set_verified_StubWithCallback(fake_set_verified);
    gpg_pin_get_pin_StubWithCallback(fake_get_pin);
    gpg_io_insert_u16_StubWithCallback(fake_insert_u16);
    gpg_io_do_StubWithCallback(fake_io_do);
    gpg_io_discard_Ignore();
    gpg_io_insert_u8_Ignore();
    gpg_io_insert_Ignore();
    nbgl_useCaseHomeAndSettings_Ignore();
    nbgl_useCaseStatus_Ignore();
    nbgl_useCaseChoice_Ignore();
    nbgl_useCaseGenericConfiguration_Ignore();
    nbgl_useCaseKeypad_StubWithCallback(fake_keypad);
    nbgl_layoutGet_IgnoreAndReturn(NULL);
    nbgl_layoutAddHeader_IgnoreAndReturn(0);
    nbgl_layoutAddSeparationLine_IgnoreAndReturn(0);
    nbgl_layoutAddRadioChoice_IgnoreAndReturn(0);
    nbgl_layoutAddButton_IgnoreAndReturn(0);
    nbgl_layoutDraw_IgnoreAndReturn(0);
}

void tearDown(void) {
    Mockgpg_api_Verify();
    Mockgpg_api_Destroy();
    Mocknbgl_layout_Destroy();
    Mocknbgl_use_case_Destroy();
    Mockmain_std_app_Destroy();
}

/* ----------------------------------------------------------------------- */
/* PIN confirmation                                                        */
/* ----------------------------------------------------------------------- */

static void test_pin_confirm(void) {
    G_gpg_vstate.io_p2 = PIN_ID_PW1;
    ui_menu_pinconfirm_display(PIN_ID_PW1);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ui_pending);

    // The PIN of the prompt, whatever the host sent meanwhile
    G_gpg_vstate.ux_pinconfirm_p2 = PIN_ID_PW2;
    pin_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ui_pending);
    TEST_ASSERT_TRUE(verified[PIN_ID_PW2]);
    TEST_ASSERT_FALSE(verified[PIN_ID_PW3]);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, sent_sw);
    TEST_ASSERT_EQUAL_UINT(1, sent_count);
}

static void test_pin_confirm_refused(void) {
    verified[PIN_ID_PW1] = 1;
    G_gpg_vstate.ux_pinconfirm_p2 = PIN_ID_PW1;

    pin_confirm_cb(false);
    TEST_ASSERT_FALSE(verified[PIN_ID_PW1]);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, sent_sw);
}

/* ----------------------------------------------------------------------- */
/* PIN entry on the device                                                 */
/* ----------------------------------------------------------------------- */

static const uint8_t PIN_OLD[] = {'1', '2', '3', '4', '5', '6'};
static const uint8_t PIN_NEW[] = {'6', '5', '4', '3', '2', '1', '0'};

static void start_entry(unsigned char ins, unsigned char p2) {
    G_gpg_vstate.io_ins = ins;
    G_gpg_vstate.ux_pinconfirm_p2 = p2;
    ui_menu_pinentry_display(0);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ui_pending);
    TEST_ASSERT_NOT_NULL(keypad_validate);
}

static void test_pinentry_verify(void) {
    start_entry(INS_VERIFY, PIN_ID_PW3);

    gpg_pin_check_ExpectAndReturn(&pins[PIN_ID_PW3],
                                  PIN_ID_PW3,
                                  PIN_OLD,
                                  sizeof(PIN_OLD),
                                  SWO_SUCCESS);
    keypad_validate(PIN_OLD, sizeof(PIN_OLD));
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ui_pending);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, sent_sw);
}

static void test_pinentry_verify_wrong(void) {
    start_entry(INS_VERIFY, PIN_ID_PW1);

    // A wrong PIN gives another try, without answering the host
    gpg_pin_check_ExpectAnyArgsAndReturn(SWO_SECURITY_CONDITION_NOT_SATISFIED);
    keypad_validate(PIN_OLD, sizeof(PIN_OLD));
    TEST_ASSERT_EQUAL_UINT(0, sent_count);
}

static void test_pinentry_verify_blocked(void) {
    start_entry(INS_VERIFY, PIN_ID_PW1);

    gpg_pin_check_ExpectAnyArgsAndReturn(SWO_AUTH_METHOD_BLOCKED);
    keypad_validate(PIN_OLD, sizeof(PIN_OLD));
    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, sent_sw);
}

// Change flow: current PIN, new PIN, then its confirmation
static uint8_t new_pin[GPG_MAX_PW_LENGTH + 1];
static size_t new_pin_len;

static void fake_io_insert_u8(unsigned int v8, int num_calls) {
    (void) num_calls;
    new_pin_len = v8;
}

static void fake_io_insert(const unsigned char *buff, unsigned int len, int num_calls) {
    (void) num_calls;
    G_gpg_vstate.work.io_buffer[0] = (unsigned char) new_pin_len;
    memcpy(G_gpg_vstate.work.io_buffer + 1, buff, len);
    memcpy(new_pin, buff, len);
}

static void enter_current_and_new(unsigned char p2) {
    gpg_io_insert_u8_StubWithCallback(fake_io_insert_u8);
    gpg_io_insert_StubWithCallback(fake_io_insert);
    start_entry(INS_CHANGE_REFERENCE_DATA, p2);

    // The current PIN is checked without opening a session
    gpg_pin_check_value_ExpectAndReturn(&pins[p2], PIN_OLD, sizeof(PIN_OLD), SWO_SUCCESS);
    keypad_validate(PIN_OLD, sizeof(PIN_OLD));
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ux_step);
    TEST_ASSERT_FALSE(verified[p2]);

    keypad_validate(PIN_NEW, sizeof(PIN_NEW));
    TEST_ASSERT_EQUAL_UINT8(2, G_gpg_vstate.ux_step);
    TEST_ASSERT_EQUAL_UINT(0, sent_count);
}

static void test_pinentry_change(void) {
    enter_current_and_new(PIN_ID_PW1);

    gpg_pin_set_ExpectAndReturn(&pins[PIN_ID_PW1],
                                G_gpg_vstate.work.io_buffer + 1,
                                sizeof(PIN_NEW),
                                SWO_SUCCESS);
    keypad_validate(PIN_NEW, sizeof(PIN_NEW));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, sent_sw);
    TEST_ASSERT_EQUAL_UINT(1, sent_count);
}

static void test_pinentry_change_differs(void) {
    const uint8_t other[] = {'6', '5', '4', '3', '2', '1', '9'};

    enter_current_and_new(PIN_ID_PW3);

    // A different confirmation sets nothing, and starts the new PIN again
    keypad_validate(other, sizeof(other));
    TEST_ASSERT_EQUAL_UINT(0, sent_count);
    keypad_validate(PIN_NEW, sizeof(PIN_NEW) - 1);
    TEST_ASSERT_EQUAL_UINT(0, sent_count);
}

static void test_pinentry_change_wrong_current(void) {
    start_entry(INS_CHANGE_REFERENCE_DATA, PIN_ID_PW1);

    gpg_pin_check_value_ExpectAnyArgsAndReturn(SWO_SECURITY_CONDITION_NOT_SATISFIED);
    keypad_validate(PIN_OLD, sizeof(PIN_OLD));
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ux_step);
    TEST_ASSERT_EQUAL_UINT(0, sent_count);
}

static void test_pinentry_back(void) {
    enter_current_and_new(PIN_ID_PW1);

    // Leaving the entry refuses the command
    keypad_back();
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ui_pending);
    TEST_ASSERT_FALSE(verified[PIN_ID_PW1]);
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, sent_sw);
}

/* ----------------------------------------------------------------------- */
/* TERMINATE DF confirmation                                               */
/* ----------------------------------------------------------------------- */

static void test_terminate_confirmed(void) {
    ui_menu_terminate_display();
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ui_pending);

    gpg_install_Expect(STATE_TERMINATE);
    gpg_init_session_Expect();
    terminate_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ui_pending);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, sent_sw);
}

static void test_terminate_refused(void) {
    ui_menu_terminate_display();
    terminate_confirm_cb(false);
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, sent_sw);
}

/* ----------------------------------------------------------------------- */
/* UIF confirmation                                                        */
/* ----------------------------------------------------------------------- */

static const uint8_t DIGEST_A[] = {0xAA, 0xAA, 0xAA, 0xAA};

static int check_shown_pso(int num_calls) {
    (void) num_calls;
    // The operation is the one shown to the user
    TEST_ASSERT_EQUAL_HEX8(INS_PSO, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_HEX16(PSO_CDS, G_gpg_vstate.io_p1p2);
    TEST_ASSERT_EQUAL_UINT(sizeof(DIGEST_A), G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(DIGEST_A, G_gpg_vstate.work.io_buffer, sizeof(DIGEST_A));
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.UIF_flags);
    return SWO_SUCCESS;
}

static void show_uif_for_digest_a(void) {
    G_gpg_vstate.io_ins = INS_PSO;
    G_gpg_vstate.io_p1p2 = PSO_CDS;
    G_gpg_vstate.io_length = sizeof(DIGEST_A);
    memcpy(G_gpg_vstate.work.io_buffer, DIGEST_A, sizeof(DIGEST_A));
    ui_menu_uifconfirm_display(0);
}

static void test_uif_confirmed(void) {
    show_uif_for_digest_a();

    gpg_apdu_pso_StubWithCallback(check_shown_pso);
    uif_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.UIF_flags);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, sent_sw);
}

static void test_uif_refused(void) {
    show_uif_for_digest_a();
    uif_confirm_cb(false);
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_ISSUE, sent_sw);
}

static void test_uif_blocks_commands(void) {
    // No other command can run, nor replace the operation, while the prompt is shown
    show_uif_for_digest_a();
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ui_pending);

    gpg_apdu_pso_StubWithCallback(check_shown_pso);
    uif_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.ui_pending);
}

/* ----------------------------------------------------------------------- */
/* PIN mode settings                                                       */
/* ----------------------------------------------------------------------- */

static void test_pin_mode_trust_requires_pw3(void) {
    G_gpg_vstate.pinmode = PIN_MODE_CONFIRM;

    pin_cb(TOKEN_PIN_SET, PIN_CHOICE_TRUST);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_CONFIRM, G_gpg_vstate.pinmode);

    // With PW3, the Trust mode is only selected after a confirmation
    verified[PIN_ID_PW3] = 1;
    pin_cb(TOKEN_PIN_SET, PIN_CHOICE_TRUST);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_CONFIRM, G_gpg_vstate.pinmode);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_TRUST, G_gpg_vstate.pinmode_req);
    trust_cb(true);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_TRUST, G_gpg_vstate.pinmode);
}

static void test_pin_mode_screen_requires_pw1(void) {
    G_gpg_vstate.pinmode = PIN_MODE_CONFIRM;

    pin_cb(TOKEN_PIN_SET, PIN_CHOICE_SCREEN);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_CONFIRM, G_gpg_vstate.pinmode);

    verified[PIN_ID_PW2] = 1;
    G_gpg_vstate.keypad_shuffle = true;
    pin_cb(TOKEN_PIN_SET, PIN_CHOICE_SCREEN);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_SCREEN, G_gpg_vstate.pinmode);
    TEST_ASSERT_FALSE(G_gpg_vstate.keypad_shuffle);
}

static void test_pin_mode_default(void) {
    // The Trust mode is never the default one
    G_gpg_vstate.pinmode = PIN_MODE_TRUST;
    N_gpg_pstate->config_pin = PIN_MODE_CONFIRM;
    pin_cb(TOKEN_PIN_DEF, 0);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_CONFIRM, N_gpg_pstate->config_pin);

    G_gpg_vstate.pinmode = PIN_MODE_SCREEN;
    G_gpg_vstate.keypad_shuffle = false;
    N_gpg_pstate->keypad_shuffle = true;
    pin_cb(TOKEN_PIN_DEF, 0);
    TEST_ASSERT_EQUAL_HEX8(PIN_MODE_SCREEN, N_gpg_pstate->config_pin);
    TEST_ASSERT_FALSE(N_gpg_pstate->keypad_shuffle);
}

/* ----------------------------------------------------------------------- */
/* Key template change                                                     */
/* ----------------------------------------------------------------------- */

static void test_template_change_other_slot(void) {
    // A change confirmed after the slot was switched does not apply to the new slot
    G_template_pending.slot = 1;
    G_template_pending.key = TOKEN_TEMPLATE_SIG;
    G_gpg_vstate.slot = 0;

    template_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_template_pending.key);
}

static void test_template_change(void) {
    const uint8_t attr[] = {KEY_ID_RSA, 0x0C, 0x00, 0x00, 0x20, 0x00};

    G_template_pending.slot = 0;
    G_template_pending.key = TOKEN_TEMPLATE_DEC;
    G_template_pending.attributes.length = sizeof(attr);
    memcpy(G_template_pending.attributes.value, attr, sizeof(attr));

    gpg_key_erase_Expect(&G_gpg_vstate.kslot->dec);
    template_confirm_cb(true);
    TEST_ASSERT_EQUAL_UINT(sizeof(attr), G_gpg_vstate.kslot->dec.attributes.length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(attr, G_gpg_vstate.kslot->dec.attributes.value, sizeof(attr));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_pin_confirm);
    RUN_TEST(test_pin_confirm_refused);
    RUN_TEST(test_pinentry_verify);
    RUN_TEST(test_pinentry_verify_wrong);
    RUN_TEST(test_pinentry_verify_blocked);
    RUN_TEST(test_pinentry_change);
    RUN_TEST(test_pinentry_change_differs);
    RUN_TEST(test_pinentry_change_wrong_current);
    RUN_TEST(test_pinentry_back);
    RUN_TEST(test_terminate_confirmed);
    RUN_TEST(test_terminate_refused);
    RUN_TEST(test_uif_confirmed);
    RUN_TEST(test_uif_refused);
    RUN_TEST(test_uif_blocks_commands);
    RUN_TEST(test_pin_mode_trust_requires_pw3);
    RUN_TEST(test_pin_mode_screen_requires_pw1);
    RUN_TEST(test_pin_mode_default);
    RUN_TEST(test_template_change_other_slot);
    RUN_TEST(test_template_change);
    return UNITY_END();
}
