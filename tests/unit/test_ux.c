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

// The callbacks of the last confirmation, settings page and radio page shown
static nbgl_choiceCallback_t choice_cb;
static const nbgl_genericContents_t *config_contents;
static const char *config_title;
static nbgl_layoutTouchCallback_t radio_cb;
static nbgl_callback_t status_cb;

static void fake_status(const char *message,
                        bool isSuccess,
                        nbgl_callback_t quitCallback,
                        int num_calls) {
    (void) message;
    (void) isSuccess;
    (void) num_calls;
    status_cb = quitCallback;
}

static void fake_choice(const nbgl_icon_details_t *icon,
                        const char *message,
                        const char *subMessage,
                        const char *confirmText,
                        const char *rejectString,
                        nbgl_choiceCallback_t callback,
                        int num_calls) {
    (void) icon;
    (void) message;
    (void) subMessage;
    (void) confirmText;
    (void) rejectString;
    (void) num_calls;
    choice_cb = callback;
}

static void fake_configuration(const char *title,
                               uint8_t initPage,
                               const nbgl_genericContents_t *contents,
                               nbgl_callback_t quitCallback,
                               int num_calls) {
    (void) initPage;
    (void) quitCallback;
    (void) num_calls;
    config_title = title;
    config_contents = contents;
}

static nbgl_layout_t *fake_layout_get(const nbgl_layoutDescription_t *description, int num_calls) {
    (void) num_calls;
    radio_cb = description->onActionCallback;
    return NULL;
}

static nbgl_contentActionCallback_t config_action(void) {
    TEST_ASSERT_NOT_NULL(config_contents);
    return config_contents->contentsList[0].contentActionCallback;
}

// OIDs returned by the curve lookup, told apart by their single byte
static unsigned char OID_SECP256K1[] = {0x01};
static unsigned char OID_SECP256R1[] = {0x02};
static unsigned char OID_ED25519[] = {0x03};
static unsigned char OID_CV25519[] = {0x04};

static unsigned char *fake_curve2oid(unsigned int cv, unsigned int *len, int num_calls) {
    (void) num_calls;
    *len = 1;
    switch (cv) {
        case CX_CURVE_SECP256K1:
            return OID_SECP256K1;
        case CX_CURVE_SECP256R1:
            return OID_SECP256R1;
        case CX_CURVE_Ed25519:
            return OID_ED25519;
        case CX_CURVE_Curve25519:
            return OID_CV25519;
        default:
            TEST_FAIL_MESSAGE("unexpected curve");
            return NULL;
    }
}

static void set_attributes(gpg_key_t *key, const uint8_t *attr, unsigned int len) {
    key->attributes.length = len;
    memcpy(key->attributes.value, attr, len);
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
    choice_cb = NULL;
    config_contents = NULL;
    config_title = NULL;
    radio_cb = NULL;
    status_cb = NULL;

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
    nbgl_useCaseStatus_StubWithCallback(fake_status);
    nbgl_useCaseChoice_StubWithCallback(fake_choice);
    nbgl_useCaseGenericConfiguration_StubWithCallback(fake_configuration);
    nbgl_useCaseGetNbChoicesInPage_IgnoreAndReturn(4);
    gpg_curve2oid_StubWithCallback(fake_curve2oid);
    gpg_oid2curve_IgnoreAndReturn(0);
    nbgl_useCaseKeypad_StubWithCallback(fake_keypad);
    nbgl_layoutGet_StubWithCallback(fake_layout_get);
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

    TEST_ASSERT_NOT_NULL(status_cb);
    keypad_validate = NULL;
    status_cb();
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ui_pending);
    TEST_ASSERT_NOT_NULL(keypad_validate);
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
    TEST_ASSERT_NOT_NULL(status_cb);
    status_cb();
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.ux_step);
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

/* ----------------------------------------------------------------------- */
/* Key template selection                                                  */
/* ----------------------------------------------------------------------- */

static const uint8_t ATTR_RSA2048[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x01};
static const uint8_t ATTR_RSA3072[] = {KEY_ID_RSA, 0x0C, 0x00, 0x00, 0x20, 0x01};

static void test_template_select_without_key(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.ux_key = TOKEN_TEMPLATE_SIG;

    // Without a key to delete, the template applies at once
    gpg_key_is_present_ExpectAndReturn(&G_gpg_vstate.kslot->sig, false);
    gpg_key_erase_Expect(&G_gpg_vstate.kslot->sig);
    template_key_cb(TOKEN_TEMPLATE_SIG, TOKEN_TYPE_RSA3072 - FIRST_USER_TOKEN, 0);
    TEST_ASSERT_NULL(choice_cb);
    TEST_ASSERT_EQUAL_UINT(sizeof(ATTR_RSA3072), G_gpg_vstate.kslot->sig.attributes.length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA3072,
                                 G_gpg_vstate.kslot->sig.attributes.value,
                                 sizeof(ATTR_RSA3072));
}

static void test_template_select_same(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.ux_key = TOKEN_TEMPLATE_SIG;

    // The template in use changes nothing, and does not delete the key
    template_key_cb(TOKEN_TEMPLATE_SIG, TOKEN_TYPE_RSA2048 - FIRST_USER_TOKEN, 0);
    TEST_ASSERT_NULL(choice_cb);
    TEST_ASSERT_EQUAL_UINT8(0, G_template_pending.key);
}

static void test_template_select_with_key(void) {
    const uint8_t attr_cv25519[] = {KEY_ID_ECDH, 0x04};

    set_attributes(&G_gpg_vstate.kslot->dec, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.ux_key = TOKEN_TEMPLATE_DEC;

    // Deleting the key needs a confirmation
    gpg_key_is_present_ExpectAndReturn(&G_gpg_vstate.kslot->dec, true);
    template_key_cb(TOKEN_TEMPLATE_DEC, TOKEN_TYPE_Ed25519 - FIRST_USER_TOKEN, 0);
    TEST_ASSERT_NOT_NULL(choice_cb);
    choice_cb(false);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048,
                                 G_gpg_vstate.kslot->dec.attributes.value,
                                 sizeof(ATTR_RSA2048));
    TEST_ASSERT_EQUAL_UINT8(0, G_template_pending.key);

    // The decryption key takes Curve25519 for the Ed25519 entry
    gpg_key_is_present_ExpectAndReturn(&G_gpg_vstate.kslot->dec, true);
    template_key_cb(TOKEN_TEMPLATE_DEC, TOKEN_TYPE_Ed25519 - FIRST_USER_TOKEN, 0);
    gpg_key_erase_Expect(&G_gpg_vstate.kslot->dec);
    choice_cb(true);
    TEST_ASSERT_EQUAL_UINT(sizeof(attr_cv25519), G_gpg_vstate.kslot->dec.attributes.length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(attr_cv25519,
                                 G_gpg_vstate.kslot->dec.attributes.value,
                                 sizeof(attr_cv25519));
}

static void test_template_select_on_second_page(void) {
    const uint8_t attr_ed25519[] = {KEY_ID_EDDSA, 0x03};

    // The choice index is relative to its page
    template_cb(TOKEN_TEMPLATE_AUT, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(TOKEN_TEMPLATE_AUT, G_gpg_vstate.ux_key);
    TEST_ASSERT_EQUAL_STRING(LABEL_AUT, config_title);

    gpg_key_is_present_ExpectAndReturn(&G_gpg_vstate.kslot->aut, false);
    gpg_key_erase_Expect(&G_gpg_vstate.kslot->aut);
    config_action()(TOKEN_TEMPLATE_AUT, TOKEN_TYPE_Ed25519 - FIRST_USER_TOKEN - 4, 1);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(attr_ed25519,
                                 G_gpg_vstate.kslot->aut.attributes.value,
                                 sizeof(attr_ed25519));
}

static void test_template_select_back(void) {
    set_attributes(&G_gpg_vstate.kslot->sig, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.ux_key = TOKEN_TEMPLATE_SIG;

    template_key_cb(TOKEN_TYPE_BACK, TOKEN_TYPE_RSA3072 - FIRST_USER_TOKEN, 0);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048,
                                 G_gpg_vstate.kslot->sig.attributes.value,
                                 sizeof(ATTR_RSA2048));
}

/* ----------------------------------------------------------------------- */
/* Slot selection                                                          */
/* ----------------------------------------------------------------------- */

static void test_slot_select_disabled(void) {
    // DO 01F1 does not allow the slot selection on the screen
    N_gpg_pstate->config_slot[1] = 0;
    N_gpg_pstate->config_slot[2] = 0;
    G_gpg_vstate.slot = 1;

    slot_cb(TOKEN_SLOT_SELECT, 2);
    slot_cb(TOKEN_SLOT_DEF, 0);
    TEST_ASSERT_EQUAL_UINT8(0, N_gpg_pstate->config_slot[1]);
}

static void test_slot_select(void) {
    N_gpg_pstate->config_slot[2] = SLOT_SELECT_SCREEN;
    G_gpg_vstate.slot = 0;

    // The slot in use is not selected again
    slot_cb(TOKEN_SLOT_SELECT, 0);

    gpg_select_slot_ExpectAndReturn(2, SWO_SUCCESS);
    slot_cb(TOKEN_SLOT_SELECT, 2);
}

static void test_slot_default(void) {
    N_gpg_pstate->config_slot[1] = 0;
    N_gpg_pstate->config_slot[2] = SLOT_SELECT_SCREEN;
    G_gpg_vstate.slot = 2;

    ui_menu_slot_action();
    TEST_ASSERT_NOT_NULL(radio_cb);
    radio_cb(TOKEN_SLOT_DEF, 0);
    TEST_ASSERT_EQUAL_UINT8(2, N_gpg_pstate->config_slot[1]);
}

/* ----------------------------------------------------------------------- */
/* Seed mode setting                                                       */
/* ----------------------------------------------------------------------- */

static void test_seed_mode_disable(void) {
    G_gpg_vstate.seed_mode = 1;
    ui_settings_seed();

    // Disabling the seed mode needs a confirmation
    config_action()(TOKEN_SEED, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.seed_mode);
    TEST_ASSERT_NOT_NULL(choice_cb);
    choice_cb(false);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.seed_mode);

    config_action()(TOKEN_SEED, 0, 0);
    choice_cb(true);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.seed_mode);
}

static void test_seed_mode_enable(void) {
    G_gpg_vstate.seed_mode = 0;
    ui_settings_seed();

    config_action()(TOKEN_SEED, 1, 0);
    TEST_ASSERT_NULL(choice_cb);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.seed_mode);
}

/* ----------------------------------------------------------------------- */
/* UIF setting                                                             */
/* ----------------------------------------------------------------------- */

static void test_uif_setting(void) {
    ui_settings_uif(0);

    config_action()(TOKEN_UIF_DEC, 1, 0);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.kslot->sig.UIF[0]);
    TEST_ASSERT_EQUAL_UINT8(1, G_gpg_vstate.kslot->dec.UIF[0]);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.kslot->aut.UIF[0]);

    config_action()(TOKEN_UIF_DEC, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(0, G_gpg_vstate.kslot->dec.UIF[0]);
}

static void test_uif_setting_locked(void) {
    // A UIF set permanently by the host cannot be changed on the device
    N_gpg_pstate->keys[0].aut.UIF[0] = 2;
    ui_settings_uif(0);

    config_action()(TOKEN_UIF_AUT, 0, 0);
    TEST_ASSERT_EQUAL_UINT8(2, G_gpg_vstate.kslot->aut.UIF[0]);
}

/* ----------------------------------------------------------------------- */
/* Settings menu and factory reset                                         */
/* ----------------------------------------------------------------------- */

static void test_settings_menu(void) {
    controlsCallback(TOKEN_SETTINGS_TEMPLATE, 0, 1);
    TEST_ASSERT_EQUAL_UINT8(1, setting_initPage);
    TEST_ASSERT_EQUAL_STRING("Keys Templates", config_title);
    TEST_ASSERT_EQUAL_PTR(template_cb, config_action());

    controlsCallback(TOKEN_SETTINGS_SEED, 0, 1);
    TEST_ASSERT_EQUAL_PTR(seed_cb, config_action());

    controlsCallback(TOKEN_SETTINGS_UIF, 0, 1);
    TEST_ASSERT_EQUAL_PTR(uif_cb, config_action());

    controlsCallback(TOKEN_SETTINGS_PIN, 0, 1);
    TEST_ASSERT_EQUAL_PTR(pin_cb, radio_cb);
}

static void test_reset(void) {
    memset((void *) N_gpg_pstate->magic, 0xAA, MAGIC_LENGTH);
    controlsCallback(TOKEN_SETTINGS_RESET, 0, 0);
    TEST_ASSERT_NOT_NULL(choice_cb);

    choice_cb(false);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xAA, N_gpg_pstate->magic, MAGIC_LENGTH);

    gpg_init_Expect();
    choice_cb(true);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x00, N_gpg_pstate->magic, MAGIC_LENGTH);
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
    RUN_TEST(test_template_select_without_key);
    RUN_TEST(test_template_select_same);
    RUN_TEST(test_template_select_with_key);
    RUN_TEST(test_template_select_on_second_page);
    RUN_TEST(test_template_select_back);
    RUN_TEST(test_slot_select_disabled);
    RUN_TEST(test_slot_select);
    RUN_TEST(test_slot_default);
    RUN_TEST(test_seed_mode_disable);
    RUN_TEST(test_seed_mode_enable);
    RUN_TEST(test_uif_setting);
    RUN_TEST(test_uif_setting_locked);
    RUN_TEST(test_settings_menu);
    RUN_TEST(test_reset);
    return UNITY_END();
}
