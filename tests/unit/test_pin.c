#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "Mockgpg_ux.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_sha256.h"
#include "Mockos_utils.h"

#define PW1_DEFAULT "123456"
#define PW3_DEFAULT "12345678"
#define RC_DEFAULT  "abcdefgh"

// Injective stand-in for SHA-256 on PINs: the PIN, then its length
static cx_err_t fake_sha256(cx_hash_t *hash,
                            uint32_t mode,
                            const uint8_t *in,
                            size_t len,
                            uint8_t *out,
                            size_t out_len,
                            int num_calls) {
    (void) hash;
    (void) mode;
    (void) num_calls;
    TEST_ASSERT_TRUE(len < 32);
    TEST_ASSERT_EQUAL_UINT(32, out_len);
    memset(out, 0, out_len);
    memcpy(out, in, len);
    out[31] = (uint8_t) len;
    return CX_OK;
}

static char fake_secure_memcmp(const void *src1, const void *src2, size_t length, int num_calls) {
    (void) num_calls;
    return (char) (memcmp(src1, src2, length) != 0);
}

static void store_pin(gpg_pin_t *pin, const char *value) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_pin_set(pin, (unsigned char *) value, strlen(value)));
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    Mockgpg_ux_Init();
    Mocklcx_hash_Init();
    Mocklcx_sha256_Init();
    Mockos_utils_Init();
    os_secure_memcmp_StubWithCallback(fake_secure_memcmp);
    cx_sha256_init_no_throw_IgnoreAndReturn(CX_OK);
    cx_hash_no_throw_StubWithCallback(fake_sha256);

    store_pin(gpg_pin_get_pin(PIN_ID_PW1), PW1_DEFAULT);
    store_pin(gpg_pin_get_pin(PIN_ID_PW3), PW3_DEFAULT);
}

void tearDown(void) {
    Mockgpg_ux_Verify();
    Mockgpg_ux_Destroy();
    Mocklcx_hash_Destroy();
    Mocklcx_sha256_Destroy();
    Mockos_utils_Destroy();
}

// Load a received command, as left by gpg_io_do()
static void command(unsigned char cla, unsigned char p1, unsigned char p2, const char *data) {
    gpg_io_discard(1);
    G_gpg_vstate.io_cla = cla;
    G_gpg_vstate.io_p1 = p1;
    G_gpg_vstate.io_p2 = p2;
    if ((data != NULL) && (data[0] != '\0')) {
        gpg_io_insert((const unsigned char *) data, strlen(data));
        gpg_io_set_offset(0);
    }
}

static int verify(unsigned char p2, const char *pin) {
    command(CLA_APP_DEF, PIN_VERIFY, p2, pin);
    return gpg_apdu_verify();
}

static int change(unsigned char p2, const char *old_and_new) {
    command(CLA_APP_DEF, 0x00, p2, old_and_new);
    return gpg_apdu_change_ref_data();
}

static int reset_with_code(const char *rc_and_new) {
    command(CLA_APP_DEF, RESET_RETRY_WITH_CODE, PIN_ID_PW1, rc_and_new);
    return gpg_apdu_reset_retry_counter();
}

static int reset_with_pw3(const char *new_pw1) {
    command(CLA_APP_DEF, RESET_RETRY_WITH_PW3, PIN_ID_PW1, new_pw1);
    return gpg_apdu_reset_retry_counter();
}

static unsigned int counter(unsigned int ref) {
    return gpg_pin_get_pin(ref)->counter;
}

/* ----------------------------------------------------------------------- */
/* PIN references                                                          */
/* ----------------------------------------------------------------------- */

static void test_pin_references(void) {
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->PW1, gpg_pin_get_pin(PIN_ID_PW1));
    // PW2 is the PW1 value, with its own verification status
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->PW1, gpg_pin_get_pin(PIN_ID_PW2));
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->PW3, gpg_pin_get_pin(PIN_ID_PW3));
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->RC, gpg_pin_get_pin(PIN_ID_RC));
    TEST_ASSERT_NULL(gpg_pin_get_pin(0x80));
    TEST_ASSERT_NULL(gpg_pin_get_pin(0x85));
}

static void test_pin_set(void) {
    gpg_pin_t *pw1 = gpg_pin_get_pin(PIN_ID_PW1);

    TEST_ASSERT_EQUAL_UINT(strlen(PW1_DEFAULT), pw1->length);
    TEST_ASSERT_EQUAL_UINT(3, pw1->counter);
}

static void test_pin_set_unknown(void) {
    gpg_pin_t other = {0};

    // Only the PIN locations of the persistent state can be set, and nothing is written
    TEST_ASSERT_LEDGER_ASSERT(gpg_pin_set(&other, (unsigned char *) PW1_DEFAULT, 6));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, (const uint8_t *) &other, sizeof(other));
}

static void test_verified_status(void) {
    gpg_pin_set_verified(PIN_ID_PW1, 1);
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));

    // Unknown references are never verified
    gpg_pin_set_verified(0x85, 1);
    TEST_ASSERT_FALSE(gpg_pin_is_verified(0x85));
}

/* ----------------------------------------------------------------------- */
/* VERIFY                                                                  */
/* ----------------------------------------------------------------------- */

static void test_verify(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    TEST_ASSERT_EQUAL_UINT(3, counter(PIN_ID_PW1));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW2, PW1_DEFAULT));
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW2));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, PW3_DEFAULT));
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW3));

    // The PIN is not left in the IO buffer
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
}

static void test_verify_wrong_pin(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, "654321"));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_EQUAL_UINT(2, counter(PIN_ID_PW1));

    // A prefix or an extension of the PIN is wrong too
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, "12345"));
    TEST_ASSERT_EQUAL_UINT(1, counter(PIN_ID_PW1));

    // The right PIN restores the counter
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_UINT(3, counter(PIN_ID_PW1));
}

static unsigned int counter_when_hashed;

static cx_err_t spy_sha256(cx_hash_t *hash,
                           uint32_t mode,
                           const uint8_t *in,
                           size_t len,
                           uint8_t *out,
                           size_t out_len,
                           int num_calls) {
    counter_when_hashed = gpg_pin_get_pin(PIN_ID_PW1)->counter;
    return fake_sha256(hash, mode, in, len, out, out_len, num_calls);
}

static void test_verify_consumes_try_first(void) {
    // The try is already counted in NVRAM when the PIN is checked
    cx_hash_no_throw_StubWithCallback(spy_sha256);

    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, "000000"));
    TEST_ASSERT_EQUAL_UINT(2, counter_when_hashed);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_UINT(1, counter_when_hashed);
    TEST_ASSERT_EQUAL_UINT(3, counter(PIN_ID_PW1));
}

static void test_verify_secure_compare(void) {
    // The PIN hash is compared with the constant-time comparison of the SDK
    os_secure_memcmp_StubWithCallback(NULL);
    os_secure_memcmp_ExpectAnyArgsAndReturn(1);

    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_hash_error(void) {
    // A failed check still costs the try
    cx_hash_no_throw_StubWithCallback(NULL);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_INTERNAL_ERROR);

    TEST_ASSERT_EQUAL_HEX32(CX_INTERNAL_ERROR, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_UINT(2, counter(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_blocked(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW3, "00000000"));
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW3, "00000000"));
    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, verify(PIN_ID_PW3, "00000000"));
    TEST_ASSERT_EQUAL_UINT(0, counter(PIN_ID_PW3));

    // Even the right PIN is refused once blocked
    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, verify(PIN_ID_PW3, PW3_DEFAULT));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));
    TEST_ASSERT_EQUAL_UINT(0, counter(PIN_ID_PW3));
}

static void test_verify_wrong_pin_clears_status(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, "000000"));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_status_request(void) {
    // Not verified: 63Cx with the remaining tries
    TEST_ASSERT_EQUAL_HEX16(SWO_VERIFY_FAILED | 3, verify(PIN_ID_PW1, NULL));
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, "000000"));
    TEST_ASSERT_EQUAL_HEX16(SWO_VERIFY_FAILED | 2, verify(PIN_ID_PW1, NULL));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, NULL));
}

static void test_verify_reset_request(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));

    command(CLA_APP_DEF, PIN_NOT_VERIFIED, PIN_ID_PW1, NULL);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_verify());
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_reset_with_data(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));

    // The reset request has no data
    command(CLA_APP_DEF, PIN_NOT_VERIFIED, PIN_ID_PW1, PW1_DEFAULT);
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_apdu_verify());
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
}

static void test_verify_bad_parameters(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, verify(0x85, PW1_DEFAULT));

    command(CLA_APP_DEF, 0x01, PIN_ID_PW1, NULL);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gpg_apdu_verify());
    command(CLA_APP_DEF, 0x01, PIN_ID_PW1, PW1_DEFAULT);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gpg_apdu_verify());
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

/* ----------------------------------------------------------------------- */
/* VERIFY with the on-device PIN entry                                     */
/* ----------------------------------------------------------------------- */

static void test_verify_pinpad_screen(void) {
    G_gpg_vstate.pinmode = PIN_MODE_SCREEN;
    command(CLA_APP_APDU_PIN, PIN_VERIFY, PIN_ID_PW1, NULL);

    ui_menu_pinentry_display_Expect(0);
    TEST_ASSERT_EQUAL_HEX16(0, gpg_apdu_verify());
    TEST_ASSERT_EQUAL_HEX8(PIN_ID_PW1, G_gpg_vstate.ux_pinconfirm_p2);
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_pinpad_confirm(void) {
    G_gpg_vstate.pinmode = PIN_MODE_CONFIRM;
    command(CLA_APP_APDU_PIN, PIN_VERIFY, PIN_ID_PW3, NULL);

    ui_menu_pinconfirm_display_Expect(PIN_ID_PW3);
    TEST_ASSERT_EQUAL_HEX16(0, gpg_apdu_verify());
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));
}

static void test_verify_pinpad_trust(void) {
    G_gpg_vstate.pinmode = PIN_MODE_TRUST;
    command(CLA_APP_APDU_PIN, PIN_VERIFY, PIN_ID_PW2, NULL);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_verify());
    TEST_ASSERT_TRUE(gpg_pin_is_verified(PIN_ID_PW2));
}

static void test_verify_pinpad_blocked(void) {
    gpg_pin_get_pin(PIN_ID_PW1)->counter = 0;
    G_gpg_vstate.pinmode = PIN_MODE_TRUST;
    command(CLA_APP_APDU_PIN, PIN_VERIFY, PIN_ID_PW1, NULL);

    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, gpg_apdu_verify());
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

static void test_verify_pinpad_bad_mode(void) {
    G_gpg_vstate.pinmode = PIN_MODE_MAX;
    command(CLA_APP_APDU_PIN, PIN_VERIFY, PIN_ID_PW1, NULL);

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, gpg_apdu_verify());
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
}

/* ----------------------------------------------------------------------- */
/* CHANGE REFERENCE DATA                                                   */
/* ----------------------------------------------------------------------- */

static void test_change_pw1(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW2, PW1_DEFAULT));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, change(PIN_ID_PW1, PW1_DEFAULT "1111111"));
    TEST_ASSERT_EQUAL_UINT(7, gpg_pin_get_pin(PIN_ID_PW1)->length);
    // The PW2 session was opened with the previous value
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);

    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, verify(PIN_ID_PW1, PW1_DEFAULT));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, "1111111"));
}

static void test_change_pw3(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, change(PIN_ID_PW3, PW3_DEFAULT "87654321"));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, "87654321"));
}

static void test_change_wrong_pin(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            change(PIN_ID_PW1,
                                   "000000"
                                   "1111111"));
    TEST_ASSERT_EQUAL_UINT(2, counter(PIN_ID_PW1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
}

static void test_change_new_pin_length(void) {
    // PW1: 6 to 12 digits, PW3: 8 to 12 digits
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, change(PIN_ID_PW1, PW1_DEFAULT "11111"));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, change(PIN_ID_PW1, PW1_DEFAULT "1111111111111"));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, change(PIN_ID_PW3, PW3_DEFAULT "1111111"));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, change(PIN_ID_PW1, PW1_DEFAULT "111111111111"));

    // The rejected values were not stored
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, PW3_DEFAULT));
}

static void test_change_blocked(void) {
    gpg_pin_get_pin(PIN_ID_PW3)->counter = 0;
    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, change(PIN_ID_PW3, PW3_DEFAULT "87654321"));
}

static void test_change_on_device(void) {
    // Without data, the old and new PINs are entered on the device
    ui_menu_pinentry_display_Expect(0);
    TEST_ASSERT_EQUAL_HEX16(0, change(PIN_ID_PW1, NULL));
    TEST_ASSERT_EQUAL_HEX8(PIN_ID_PW1, G_gpg_vstate.ux_pinconfirm_p2);
}

static void test_change_leaves_pin_not_verified(void) {
    // Checking the current PIN does not open a session, whatever the result
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, PW3_DEFAULT));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, change(PIN_ID_PW3, PW3_DEFAULT "87654321"));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW3));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, change(PIN_ID_PW1, PW1_DEFAULT "11111"));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, change(PIN_ID_PW1, PW1_DEFAULT "1111111"));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
}

static void test_check_value(void) {
    gpg_pin_t *pw1 = gpg_pin_get_pin(PIN_ID_PW1);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            gpg_pin_check_value(pw1, (const unsigned char *) PW1_DEFAULT, 6));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            gpg_pin_check_value(pw1, (const unsigned char *) "000000", 6));
    TEST_ASSERT_EQUAL_UINT(2, counter(PIN_ID_PW1));
}

static void test_change_bad_reference(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, change(0x85, PW1_DEFAULT "1111111"));
}

/* ----------------------------------------------------------------------- */
/* RESET RETRY COUNTER                                                     */
/* ----------------------------------------------------------------------- */

static void block_pw1(void) {
    gpg_pin_get_pin(PIN_ID_PW1)->counter = 0;
}

static void test_reset_with_code(void) {
    store_pin(gpg_pin_get_pin(PIN_ID_RC), RC_DEFAULT);
    block_pw1();
    gpg_pin_set_verified(PIN_ID_PW2, 1);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, reset_with_code(RC_DEFAULT "2222222"));
    TEST_ASSERT_EQUAL_UINT(3, counter(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW1));
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_PW2));
    // The Resetting Code is only checked for this command
    TEST_ASSERT_FALSE(gpg_pin_is_verified(PIN_ID_RC));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, "2222222"));
}

static void test_reset_wrong_code(void) {
    store_pin(gpg_pin_get_pin(PIN_ID_RC), RC_DEFAULT);

    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED,
                            reset_with_code("00000000"
                                            "2222222"));
    TEST_ASSERT_EQUAL_UINT(2, counter(PIN_ID_RC));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
}

static void test_reset_without_code(void) {
    // No Resetting Code defined
    TEST_ASSERT_EQUAL_HEX16(SWO_AUTH_METHOD_BLOCKED, reset_with_code(RC_DEFAULT "2222222"));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
}

static void test_reset_with_pw3(void) {
    block_pw1();
    TEST_ASSERT_EQUAL_HEX16(SWO_SECURITY_CONDITION_NOT_SATISFIED, reset_with_pw3("2222222"));
    TEST_ASSERT_EQUAL_UINT(0, counter(PIN_ID_PW1));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, PW3_DEFAULT));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, reset_with_pw3("2222222"));
    TEST_ASSERT_EQUAL_UINT(3, counter(PIN_ID_PW1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, "2222222"));
}

static void test_reset_new_pin_length(void) {
    store_pin(gpg_pin_get_pin(PIN_ID_RC), RC_DEFAULT);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW3, PW3_DEFAULT));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, reset_with_code(RC_DEFAULT "22222"));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, reset_with_code(RC_DEFAULT "2222222222222"));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, reset_with_pw3("22222"));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, reset_with_pw3("2222222222222"));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, verify(PIN_ID_PW1, PW1_DEFAULT));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_pin_references);
    RUN_TEST(test_pin_set);
    RUN_TEST(test_pin_set_unknown);
    RUN_TEST(test_verified_status);
    RUN_TEST(test_verify);
    RUN_TEST(test_verify_wrong_pin);
    RUN_TEST(test_verify_consumes_try_first);
    RUN_TEST(test_verify_secure_compare);
    RUN_TEST(test_verify_hash_error);
    RUN_TEST(test_verify_blocked);
    RUN_TEST(test_verify_wrong_pin_clears_status);
    RUN_TEST(test_verify_status_request);
    RUN_TEST(test_verify_reset_request);
    RUN_TEST(test_verify_reset_with_data);
    RUN_TEST(test_verify_bad_parameters);
    RUN_TEST(test_verify_pinpad_screen);
    RUN_TEST(test_verify_pinpad_confirm);
    RUN_TEST(test_verify_pinpad_trust);
    RUN_TEST(test_verify_pinpad_blocked);
    RUN_TEST(test_verify_pinpad_bad_mode);
    RUN_TEST(test_change_pw1);
    RUN_TEST(test_change_pw3);
    RUN_TEST(test_change_wrong_pin);
    RUN_TEST(test_change_new_pin_length);
    RUN_TEST(test_change_blocked);
    RUN_TEST(test_change_on_device);
    RUN_TEST(test_change_leaves_pin_not_verified);
    RUN_TEST(test_check_value);
    RUN_TEST(test_change_bad_reference);
    RUN_TEST(test_reset_with_code);
    RUN_TEST(test_reset_wrong_code);
    RUN_TEST(test_reset_without_code);
    RUN_TEST(test_reset_with_pw3);
    RUN_TEST(test_reset_new_pin_length);
    return UNITY_END();
}
