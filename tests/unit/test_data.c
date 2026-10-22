#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "Mockgpg_ux.h"
#include "Mocklcx_aes.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_rsa.h"

static const uint8_t ATTR_RSA2048[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};

static size_t ed25519_attributes(uint8_t *attr) {
    attr[0] = KEY_ID_EDDSA;
    memcpy(attr + 1, C_OID_Ed25519, sizeof(C_OID_Ed25519));
    return 1 + sizeof(C_OID_Ed25519);
}

static void mocks_reset(void) {
    Mockgpg_ux_Destroy();
    Mocklcx_aes_Destroy();
    Mocklcx_ecfp_Destroy();
    Mocklcx_rsa_Destroy();
    Mockgpg_ux_Init();
    Mocklcx_aes_Init();
    Mocklcx_ecfp_Init();
    Mocklcx_rsa_Init();
}

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    mocks_reset();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(0));
}

void tearDown(void) {
    Mockgpg_ux_Verify();
    Mocklcx_aes_Verify();
    Mocklcx_ecfp_Verify();
    Mocklcx_rsa_Verify();
}

// Run PUT DATA on a received command data field, as left by gpg_io_do()
static int put_data(unsigned int ref, const uint8_t *data, size_t len) {
    gpg_io_discard(1);
    if (len != 0) {
        gpg_io_insert(data, len);
        gpg_io_set_offset(0);
    }
    return gpg_apdu_put_data(ref);
}

static void assert_response(const void *expected, size_t len) {
    TEST_ASSERT_EQUAL_UINT(len, G_gpg_vstate.io_length);
    if (len != 0) {
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.work.io_buffer, len);
    }
}

/* ----------------------------------------------------------------------- */
/* Variable length DOs                                                     */
/* ----------------------------------------------------------------------- */

static void test_private_do(void) {
    static const unsigned int refs[] = {0x0101, 0x0102, 0x0103, 0x0104};

    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        uint8_t value[] = {'D', 'O', (uint8_t) ('1' + i)};

        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(refs[i], value, sizeof(value)));
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(refs[i]));
        assert_response(value, sizeof(value));
    }
}

static void test_private_do_max_length(void) {
    static uint8_t value[GPG_EXT_PRIVATE_DO_LENGTH + 1];
    const uint8_t previous[] = {'o', 'l', 'd'};

    memset(value, 'A', sizeof(value));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x0101, value, GPG_EXT_PRIVATE_DO_LENGTH));
    TEST_ASSERT_EQUAL_UINT(GPG_EXT_PRIVATE_DO_LENGTH, N_gpg_pstate->private_DO1.length);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x0101, previous, sizeof(previous)));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x0101, value, sizeof(value)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x0101));
    assert_response(previous, sizeof(previous));
}

static void test_private_do_empty(void) {
    const uint8_t value[] = {'D', 'O'};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x0101, value, sizeof(value)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x0101, NULL, 0));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x0101));
    assert_response(NULL, 0);
}

static void test_login_and_url(void) {
    const uint8_t login[] = "alice";
    const uint8_t url[] = "https://example.com/key.asc";

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5E, login, sizeof(login) - 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5F50, url, sizeof(url) - 1));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x005E));
    assert_response(login, sizeof(login) - 1);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x5F50));
    assert_response(url, sizeof(url) - 1);
}

static void test_url_per_slot(void) {
    const uint8_t url[] = "https://example.com/slot0";

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5F50, url, sizeof(url) - 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x5F50));
    assert_response(NULL, 0);
}

static void test_login_url_max_length(void) {
    static uint8_t value[GPG_EXT_PRIVATE_DO_LENGTH + 1];

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5E, value, sizeof(value)));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5F50, value, sizeof(value)));
}

static void test_do_length(void) {
    const uint8_t value[] = {'B', 'o', 'b'};
    static const unsigned int refs[] = {0x5B, 0x5E, 0x5F2D, 0x5F50, 0x7F21};
    volatile unsigned int *lengths[] = {
        &N_gpg_pstate->name.length,
        &N_gpg_pstate->login.length,
        &N_gpg_pstate->lang.length,
        &N_gpg_pstate->keys[0].url.length,
        &N_gpg_pstate->keys[0].aut.CA.length,
    };

    // The stored length does not depend on the current offset in the IO buffer
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        gpg_io_discard(1);
        gpg_io_insert(value, sizeof(value));
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_put_data(refs[i]));
        TEST_ASSERT_EQUAL_UINT(sizeof(value), *lengths[i]);
    }
}

static void test_cardholder_data(void) {
    const uint8_t name[] = "Doe<<John";
    const uint8_t lang[] = "fren";
    const uint8_t salutation[] = {'1'};
    // clang-format off
    const uint8_t expected[] = {
        0x5B, 0x09, 'D', 'o', 'e', '<', '<', 'J', 'o', 'h', 'n',
        0x5F, 0x2D, 0x04, 'f', 'r', 'e', 'n',
        0x5F, 0x35, 0x01, '1',
    };
    // clang-format on

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5B, name, sizeof(name) - 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5F2D, lang, sizeof(lang) - 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5F35, salutation, sizeof(salutation)));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x65));
    assert_response(expected, sizeof(expected));
}

static void test_cardholder_data_lengths(void) {
    static uint8_t value[GPG_NAME_LENGTH + 1];

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5B, value, GPG_NAME_LENGTH));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5B, value, GPG_NAME_LENGTH + 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x5F2D, value, GPG_LANG_LENGTH));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5F2D, value, GPG_LANG_LENGTH + 1));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5F35, value, 0));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x5F35, value, 2));
}

/* ----------------------------------------------------------------------- */
/* Fixed length DOs                                                        */
/* ----------------------------------------------------------------------- */

static void test_serial(void) {
    const uint8_t serial[] = {0x12, 0x34, 0x56, 0x78, 0x9A};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x4F, serial, 4));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x4F, serial, 3));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x4F, serial, 5));

    // Full AID: 10 bytes of RID and version, the serial, then 0000
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x004F));
    TEST_ASSERT_EQUAL_UINT(16, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(serial, G_gpg_vstate.work.io_buffer + 10, 4);
}

static void test_fingerprints(void) {
    static const unsigned int refs[] = {0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC};
    uint8_t fingerprint[21];

    memset(fingerprint, 0xF0, sizeof(fingerprint));
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(refs[i], fingerprint, 20));
        TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(refs[i], fingerprint, 19));
        TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(refs[i], fingerprint, 21));
    }
    TEST_ASSERT_EACH_EQUAL_HEX8(0xF0, G_gpg_vstate.kslot->sig.fingerprints, 20);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xF0, G_gpg_vstate.kslot->aut.CA_fingerprints, 20);
}

static void test_dates(void) {
    static const unsigned int refs[] = {0xCE, 0xCF, 0xD0};
    const uint8_t date[] = {0x65, 0x00, 0x00, 0x01, 0x02};

    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++) {
        TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(refs[i], date, 4));
        TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(refs[i], date, 5));
    }
    TEST_ASSERT_EQUAL_HEX8_ARRAY(date, G_gpg_vstate.kslot->dec.date, 4);
}

static void test_uif(void) {
    const uint8_t enabled[] = {0x01, 0x20};
    const uint8_t permanent[] = {0x02, 0x20};
    const uint8_t disabled[] = {0x00, 0x20};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xD6, enabled, sizeof(enabled)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x00D6));
    assert_response(enabled, sizeof(enabled));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xD6, enabled, 1));

    // A permanent UIF can no longer be changed
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xD7, permanent, sizeof(permanent)));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED,
                            put_data(0xD7, disabled, sizeof(disabled)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xD7, permanent, sizeof(permanent)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x00D7));
    assert_response(permanent, sizeof(permanent));
}

static void test_pw_status(void) {
    const uint8_t status[] = {0x01};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xC4, status, 0));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xC4, status, sizeof(status)));
    TEST_ASSERT_EQUAL_HEX8(0x01, N_gpg_pstate->PW_status[0]);
}

static void test_unknown_do(void) {
    const uint8_t value[] = {0x00};

    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x0105, value, sizeof(value)));
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, gpg_apdu_get_data(0x0105));
}

/* ----------------------------------------------------------------------- */
/* Slots and RSA exponent configuration                                    */
/* ----------------------------------------------------------------------- */

static void test_config_slot(void) {
    const uint8_t config[] = {GPG_KEYS_SLOTS, 0x01, SLOT_SELECT_APDU};
    const uint8_t bad_count[] = {GPG_KEYS_SLOTS + 1, 0x01, 0x00};
    const uint8_t bad_default[] = {GPG_KEYS_SLOTS, GPG_KEYS_SLOTS, 0x00};
    const uint8_t bad_flags[] = {GPG_KEYS_SLOTS, 0x00, 0x04};

    ui_init_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x01F1, config, sizeof(config)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x01F1));
    assert_response(config, sizeof(config));

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x01F1, config, 2));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F1, bad_count, 3));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F1, bad_default, 3));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F1, bad_flags, 3));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(config, N_gpg_pstate->config_slot, sizeof(config));
}

static void test_select_slot(void) {
    const uint8_t config[] = {GPG_KEYS_SLOTS, 0x00, SLOT_SELECT_APDU};
    const uint8_t slot[] = {0x02};
    const uint8_t bad_slot[] = {GPG_KEYS_SLOTS};

    // Disabled until allowed by the slot configuration
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, put_data(0x01F2, slot, sizeof(slot)));

    ui_init_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x01F1, config, sizeof(config)));

    ui_init_Expect();
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x01F2, slot, sizeof(slot)));
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.slot);
    TEST_ASSERT_EQUAL_PTR(&N_gpg_pstate->keys[2], G_gpg_vstate.kslot);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x01F2));
    assert_response(slot, sizeof(slot));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F2, bad_slot, sizeof(bad_slot)));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F2, slot, 0));
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.slot);
}

static void test_rsa_exponent(void) {
    // Written little-endian, read back big-endian
    const uint8_t written[] = {0x01, 0x00, 0x01, 0x00};
    const uint8_t read[] = {0x00, 0x01, 0x00, 0x01};
    const uint8_t even[] = {0x00, 0x00, 0x01, 0x00};
    const uint8_t one[] = {0x01, 0x00, 0x00, 0x00};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x01F8, written, sizeof(written)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x01F8));
    assert_response(read, sizeof(read));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F8, even, sizeof(even)));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x01F8, one, sizeof(one)));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x01F8, written, 3));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x01F8));
    assert_response(read, sizeof(read));
}

/* ----------------------------------------------------------------------- */
/* Key attributes                                                          */
/* ----------------------------------------------------------------------- */

static void test_attributes_rsa(void) {
    const uint8_t rsa1024[] = {KEY_ID_RSA, 0x04, 0x00, 0x00, 0x20, 0x00};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xC1, ATTR_RSA2048, sizeof(ATTR_RSA2048)));
    TEST_ASSERT_EQUAL_UINT(sizeof(ATTR_RSA2048), G_gpg_vstate.kslot->sig.attributes.length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048,
                                 G_gpg_vstate.kslot->sig.attributes.value,
                                 sizeof(ATTR_RSA2048));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xC1, rsa1024, sizeof(rsa1024)));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xC1, ATTR_RSA2048, 2));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048,
                                 G_gpg_vstate.kslot->sig.attributes.value,
                                 sizeof(ATTR_RSA2048));
}

static void test_attributes_ecc(void) {
    uint8_t attr[GPG_KEY_ATTRIBUTES_LENGTH];
    size_t len = ed25519_attributes(attr);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xC3, attr, len));
    TEST_ASSERT_EQUAL_UINT(len, G_gpg_vstate.kslot->aut.attributes.length);

    // Ed25519 is only usable for EdDSA
    attr[0] = KEY_ID_ECDSA;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xC3, attr, len));
    // Truncated OID
    attr[0] = KEY_ID_EDDSA;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xC3, attr, len - 1));
}

static void test_attributes_lengths(void) {
    uint8_t attr[GPG_KEY_ATTRIBUTES_LENGTH + 1] = {KEY_ID_RSA, 0x08, 0x00};
    const uint8_t unknown[] = {0x42, 0x08, 0x00};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xC2, attr, 0));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xC2, attr, sizeof(attr)));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xC2, unknown, sizeof(unknown)));
}

static void test_attributes_erase_key(void) {
    const uint8_t uif[] = {0x01, 0x20};

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xD6, uif, sizeof(uif)));
    memset((void *) &G_gpg_vstate.kslot->sig.priv_key,
           0xA5,
           sizeof(G_gpg_vstate.kslot->sig.priv_key));
    memset((void *) G_gpg_vstate.kslot->sig.fingerprints, 0xF0, 20);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xC1, ATTR_RSA2048, sizeof(ATTR_RSA2048)));
    TEST_ASSERT_EACH_EQUAL_HEX8(0,
                                (const uint8_t *) &G_gpg_vstate.kslot->sig.priv_key,
                                sizeof(G_gpg_vstate.kslot->sig.priv_key));
    TEST_ASSERT_EACH_EQUAL_HEX8(0, G_gpg_vstate.kslot->sig.fingerprints, 20);
    // The User Interaction Flag is kept
    TEST_ASSERT_EQUAL_HEX8_ARRAY(uif, G_gpg_vstate.kslot->sig.UIF, sizeof(uif));
}

static void test_attributes_rejected_keep_key(void) {
    const uint8_t rsa1024[] = {KEY_ID_RSA, 0x04, 0x00, 0x00, 0x20, 0x00};

    memset((void *) &G_gpg_vstate.kslot->sig.priv_key,
           0xA5,
           sizeof(G_gpg_vstate.kslot->sig.priv_key));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xC1, rsa1024, sizeof(rsa1024)));
    TEST_ASSERT_EACH_EQUAL_HEX8(0xA5,
                                (const uint8_t *) &G_gpg_vstate.kslot->sig.priv_key,
                                sizeof(G_gpg_vstate.kslot->sig.priv_key));
}

/* ----------------------------------------------------------------------- */
/* Cardholder certificates                                                 */
/* ----------------------------------------------------------------------- */

static void test_certificates(void) {
    const uint8_t cert_aut[] = "AUT";
    const uint8_t cert_dec[] = "DEC";
    const uint8_t cert_sig[] = "SIG";

    // Records are selected with SELECT DATA: 0 for AUT, 1 for DEC, 2 for SIG
    gpg_apdu_select_data(0x7F21, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x7F21, cert_aut, 3));
    gpg_apdu_select_data(0x7F21, 1);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x7F21, cert_dec, 3));
    gpg_apdu_select_data(0x7F21, 2);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x7F21, cert_sig, 3));

    gpg_apdu_select_data(0x7F21, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x7F21));
    assert_response(cert_aut, 3);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_next_data(0x7F21));
    assert_response(cert_dec, 3);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_next_data(0x7F21));
    assert_response(cert_sig, 3);

    // No fourth record: stay on the last one
    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, gpg_apdu_get_next_data(0x7F21));
    TEST_ASSERT_EQUAL_INT(2, G_gpg_vstate.DO_reccord);
}

static void test_certificate_bad_record(void) {
    const uint8_t cert[] = "CERT";

    gpg_apdu_select_data(0x7F21, 3);
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x7F21, cert, 4));
    TEST_ASSERT_EQUAL_HEX16(SWO_FILE_NOT_FOUND, gpg_apdu_get_data(0x7F21));
}

static void test_certificate_max_length(void) {
    static uint8_t cert[GPG_IO_BUFFER_LENGTH];

    memset(cert, 'C', sizeof(cert));
    gpg_apdu_select_data(0x7F21, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x7F21, cert, GPG_IO_BUFFER_LENGTH - 2));
    // Must stay readable with its status word in the IO buffer
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x7F21, cert, GPG_IO_BUFFER_LENGTH - 1));
    TEST_ASSERT_EQUAL_UINT(GPG_IO_BUFFER_LENGTH - 2, G_gpg_vstate.kslot->aut.CA.length);
}

static void test_get_next_data_other_do(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, gpg_apdu_get_next_data(0x0101));
    // Not after a GET DATA of a certificate
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x0101));
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, gpg_apdu_get_next_data(0x7F21));
}

/* ----------------------------------------------------------------------- */
/* Read only DOs                                                           */
/* ----------------------------------------------------------------------- */

static void test_application_related_data(void) {
    const uint8_t serial[] = {0x12, 0x34, 0x56, 0x78};
    uint8_t aid[AID_LENGTH];
    unsigned int t = 0;
    unsigned int l = 0;

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x4F, serial, sizeof(serial)));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x004F));
    memcpy(aid, G_gpg_vstate.work.io_buffer, sizeof(aid));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xC1, ATTR_RSA2048, sizeof(ATTR_RSA2048)));
    memset((void *) N_gpg_pstate->histo, 0xA5, HISTO_LENGTH);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x6E));

    // AID, the same as DO 4F, historical bytes, extended length information,
    // then the discretionary data objects
    gpg_io_set_offset(0);
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x4F, t);
    TEST_ASSERT_EQUAL_UINT(AID_LENGTH, l);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(aid,
                                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                 AID_LENGTH);
    TEST_ASSERT_TRUE(gpg_io_skip(l));
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x5F52, t);
    TEST_ASSERT_EQUAL_UINT(HISTO_LENGTH, l);
    TEST_ASSERT_EACH_EQUAL_HEX8(0xA5, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, l);
    TEST_ASSERT_TRUE(gpg_io_skip(l));
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x7F66, t);
    TEST_ASSERT_TRUE(gpg_io_skip(l));
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x73, t);
    TEST_ASSERT_EQUAL_UINT(G_gpg_vstate.io_length - G_gpg_vstate.io_offset, l);

    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0xC0, t);
    TEST_ASSERT_TRUE(gpg_io_skip(l));
    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0xC1, t);
    TEST_ASSERT_EQUAL_UINT(sizeof(ATTR_RSA2048), l);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(ATTR_RSA2048,
                                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                 sizeof(ATTR_RSA2048));
}

static void test_pw_status_bytes(void) {
    N_gpg_pstate->PW1.counter = 3;
    N_gpg_pstate->RC.counter = 0;
    N_gpg_pstate->PW3.counter = 2;

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x00C4));
    TEST_ASSERT_EQUAL_UINT(7, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8(3, G_gpg_vstate.work.io_buffer[4]);
    TEST_ASSERT_EQUAL_HEX8(0, G_gpg_vstate.work.io_buffer[5]);
    TEST_ASSERT_EQUAL_HEX8(2, G_gpg_vstate.work.io_buffer[6]);
}

static void test_signature_counter(void) {
    const uint8_t expected[] = {0x93, 0x03, 0x01, 0x02, 0x03};

    G_gpg_vstate.kslot->sig_count = 0x010203;
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_apdu_get_data(0x7A));
    assert_response(expected, sizeof(expected));
}

/* ----------------------------------------------------------------------- */
/* Key import: extended header list                                        */
/* ----------------------------------------------------------------------- */

// Build an extended header list for an ECC private key, then a 5F48 of key_len bytes
static size_t ecc_key_import(uint8_t *buf, unsigned int crt, size_t key_len) {
    size_t n = 0;

    buf[n++] = 0x4D;
    buf[n++] = (uint8_t) (2 + 5 + 3 + key_len);
    buf[n++] = (uint8_t) crt;
    buf[n++] = 0x00;
    buf[n++] = 0x7F;
    buf[n++] = 0x48;
    buf[n++] = 0x02;
    buf[n++] = 0x92;
    buf[n++] = (uint8_t) key_len;
    buf[n++] = 0x5F;
    buf[n++] = 0x48;
    buf[n++] = (uint8_t) key_len;
    for (size_t i = 0; i < key_len; i++) {
        buf[n++] = (uint8_t) (i + 1);
    }
    return n;
}

static void set_ed25519_attributes(gpg_key_t *key) {
    uint8_t attr[GPG_KEY_ATTRIBUTES_LENGTH];
    size_t len = ed25519_attributes(attr);

    memcpy((void *) key->attributes.value, attr, len);
    key->attributes.length = len;
}

static void test_import_ecc(void) {
    uint8_t buf[64];
    size_t len = ecc_key_import(buf, KEY_SIG, 32);

    set_ed25519_attributes(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig_count = 5;

    cx_ecfp_generate_pair_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x3FFF, buf, len));
    TEST_ASSERT_EQUAL_UINT(32, G_gpg_vstate.kslot->sig.priv_key.ecfp.d_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(buf + len - 32, G_gpg_vstate.kslot->sig.priv_key.ecfp.d, 32);
    // Importing the signature key resets the signature counter
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.kslot->sig_count);
}

static void test_import_ecc_short_key(void) {
    uint8_t buf[64];
    uint8_t expected[32] = {0};
    size_t len = ecc_key_import(buf, KEY_AUT, 31);

    set_ed25519_attributes(&G_gpg_vstate.kslot->aut);
    memcpy(expected + 1, buf + len - 31, 31);

    // Restored with its leading zero byte
    cx_ecfp_generate_pair_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x3FFF, buf, len));
    TEST_ASSERT_EQUAL_UINT(32, G_gpg_vstate.kslot->aut.priv_key.ecfp.d_len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.kslot->aut.priv_key.ecfp.d, 32);
}

static void test_import_ecc_wrong_length(void) {
    uint8_t buf[64];
    size_t len;

    set_ed25519_attributes(&G_gpg_vstate.kslot->aut);
    memset((void *) &G_gpg_vstate.kslot->aut.priv_key,
           0xA5,
           sizeof(G_gpg_vstate.kslot->aut.priv_key));

    len = ecc_key_import(buf, KEY_AUT, 33);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));
    len = ecc_key_import(buf, KEY_AUT, 0);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));

    // The previous key is kept
    TEST_ASSERT_EACH_EQUAL_HEX8(0xA5,
                                (const uint8_t *) &G_gpg_vstate.kslot->aut.priv_key,
                                sizeof(G_gpg_vstate.kslot->aut.priv_key));
}

static void test_import_truncated(void) {
    uint8_t buf[64];
    size_t len = ecc_key_import(buf, KEY_AUT, 32);
    int sw;

    set_ed25519_attributes(&G_gpg_vstate.kslot->aut);
    memset((void *) &G_gpg_vstate.kslot->aut.priv_key,
           0xA5,
           sizeof(G_gpg_vstate.kslot->aut.priv_key));

    // Cut inside the 4D, CRT or 7F48 headers
    for (size_t n = 0; n < 7; n++) {
        TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x3FFF, buf, n));
    }
    // Cut anywhere else
    for (size_t n = 7; n < len; n++) {
        sw = put_data(0x3FFF, buf, n);
        TEST_ASSERT_TRUE((sw == SWO_WRONG_LENGTH) || (sw == SWO_INCORRECT_DATA));
    }

    // The previous key is kept
    TEST_ASSERT_EACH_EQUAL_HEX8(0xA5,
                                (const uint8_t *) &G_gpg_vstate.kslot->aut.priv_key,
                                sizeof(G_gpg_vstate.kslot->aut.priv_key));
}

static void test_import_unsupported_length(void) {
    // 3-byte long form length
    const uint8_t buf[] = {0x4D, 0x83, 0x00, 0x00, 0x10};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0x3FFF, buf, sizeof(buf)));
}

static void test_import_no_attributes(void) {
    uint8_t buf[64];
    size_t len = ecc_key_import(buf, KEY_DEC, 32);

    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x3FFF, buf, len));
}

static void test_import_bad_headers(void) {
    uint8_t buf[64];
    size_t len;

    set_ed25519_attributes(&G_gpg_vstate.kslot->sig);

    // Not an extended header list
    len = ecc_key_import(buf, KEY_SIG, 32);
    buf[0] = 0x4E;
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x3FFF, buf, len));

    // Unknown control reference template
    len = ecc_key_import(buf, 0xB7, 32);
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x3FFF, buf, len));

    // Private key template longer than the data
    len = ecc_key_import(buf, KEY_SIG, 32);
    buf[6] = 0x7F;
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));

    // Unknown tag in the private key template
    len = ecc_key_import(buf, KEY_SIG, 32);
    buf[7] = 0x98;
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x3FFF, buf, len));

    // Key data other than 5F48
    len = ecc_key_import(buf, KEY_SIG, 32);
    buf[10] = 0x49;
    TEST_ASSERT_EQUAL_HEX16(SWO_REFERENCED_DATA_NOT_FOUND, put_data(0x3FFF, buf, len));

    // Key data longer than received
    len = ecc_key_import(buf, KEY_SIG, 32);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len - 1));
}

// Build an extended header list for a RSA private key with e, p and q
static size_t rsa_key_import(uint8_t *buf, size_t len_e, size_t len_p, size_t len_q) {
    size_t n = 0;
    size_t data_len = len_e + len_p + len_q;

    buf[n++] = 0x4D;
    buf[n++] = 0x82;
    n += 2;
    buf[n++] = KEY_SIG;
    buf[n++] = 0x00;
    buf[n++] = 0x7F;
    buf[n++] = 0x48;
    buf[n++] = 0x09;
    buf[n++] = 0x91;
    buf[n++] = (uint8_t) len_e;
    buf[n++] = 0x92;
    buf[n++] = 0x82;
    buf[n++] = (uint8_t) (len_p >> 8);
    buf[n++] = (uint8_t) len_p;
    buf[n++] = 0x93;
    buf[n++] = 0x81;
    buf[n++] = (uint8_t) len_q;
    buf[n++] = 0x5F;
    buf[n++] = 0x48;
    buf[n++] = 0x82;
    buf[n++] = (uint8_t) (data_len >> 8);
    buf[n++] = (uint8_t) data_len;
    memset(buf + n, 0x55, data_len);
    if (len_e != 0) {
        buf[n + len_e - 1] = 0x01;
    }
    n += data_len;
    buf[2] = (uint8_t) ((n - 4) >> 8);
    buf[3] = (uint8_t) (n - 4);
    return n;
}

static void test_import_rsa_bad_parts(void) {
    static uint8_t buf[600];
    size_t len;

    memcpy((void *) G_gpg_vstate.kslot->sig.attributes.value, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.kslot->sig.attributes.length = sizeof(ATTR_RSA2048);

    // No public exponent
    len = rsa_key_import(buf, 0, 128, 128);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));

    // Prime longer than half the modulus
    len = rsa_key_import(buf, 3, 129, 128);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));
    len = rsa_key_import(buf, 3, 128, 129);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0x3FFF, buf, len));
}

static void test_import_rsa(void) {
    static uint8_t buf[600];
    size_t len = rsa_key_import(buf, 3, 128, 128);

    memcpy((void *) G_gpg_vstate.kslot->sig.attributes.value, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    G_gpg_vstate.kslot->sig.attributes.length = sizeof(ATTR_RSA2048);

    cx_rsa_generate_pair_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0x3FFF, buf, len));
}

/* ----------------------------------------------------------------------- */
/* AES keys and Resetting Code                                             */
/* ----------------------------------------------------------------------- */

static const unsigned int AES_KEY_REFS[] = {0xD1, 0xD2, 0xD5};

static void test_aes_key(void) {
    static const size_t lengths[] = {16, 24, 32};
    const uint8_t key[32] = {0};

    for (size_t i = 0; i < sizeof(AES_KEY_REFS) / sizeof(AES_KEY_REFS[0]); i++) {
        for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
            cx_aes_init_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
            TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(AES_KEY_REFS[i], key, lengths[j]));
        }
    }
}

static void test_aes_key_wrong_length(void) {
    static const size_t lengths[] = {0, 15, 17, 33};
    const uint8_t key[33] = {0};

    // Rejected before reaching the crypto library
    for (size_t i = 0; i < sizeof(AES_KEY_REFS) / sizeof(AES_KEY_REFS[0]); i++) {
        for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
            TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(AES_KEY_REFS[i], key, lengths[j]));
        }
    }
}

static void test_aes_key_crypto_error(void) {
    const uint8_t key[16] = {0};

    // The crypto library error is returned as is
    cx_aes_init_key_no_throw_ExpectAnyArgsAndReturn(CX_INTERNAL_ERROR);
    TEST_ASSERT_EQUAL_HEX32(CX_INTERNAL_ERROR, put_data(0xD5, key, sizeof(key)));
}

static void test_sm_keys(void) {
    const uint8_t keys[2 * CX_AES_128_KEY_LEN] = {0};

    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, put_data(0xF4, keys, CX_AES_128_KEY_LEN));
    cx_aes_init_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_aes_init_key_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xF4, keys, sizeof(keys)));
}

static void test_resetting_code_lengths(void) {
    const uint8_t rc[GPG_MAX_PW_LENGTH + 1] = {0};

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xD3, rc, 7));
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, put_data(0xD3, rc, sizeof(rc)));
}

static void test_resetting_code_clear(void) {
    gpg_pin_t *rc = gpg_pin_get_pin(PIN_ID_RC);

    memset(rc, 0xA5, sizeof(gpg_pin_t));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, put_data(0xD3, NULL, 0));
    TEST_ASSERT_EACH_EQUAL_HEX8(0, (const uint8_t *) rc, sizeof(gpg_pin_t));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_private_do);
    RUN_TEST(test_private_do_max_length);
    RUN_TEST(test_private_do_empty);
    RUN_TEST(test_login_and_url);
    RUN_TEST(test_url_per_slot);
    RUN_TEST(test_login_url_max_length);
    RUN_TEST(test_do_length);
    RUN_TEST(test_cardholder_data);
    RUN_TEST(test_cardholder_data_lengths);
    RUN_TEST(test_serial);
    RUN_TEST(test_fingerprints);
    RUN_TEST(test_dates);
    RUN_TEST(test_uif);
    RUN_TEST(test_pw_status);
    RUN_TEST(test_unknown_do);
    RUN_TEST(test_config_slot);
    RUN_TEST(test_select_slot);
    RUN_TEST(test_rsa_exponent);
    RUN_TEST(test_attributes_rsa);
    RUN_TEST(test_attributes_ecc);
    RUN_TEST(test_attributes_lengths);
    RUN_TEST(test_attributes_erase_key);
    RUN_TEST(test_attributes_rejected_keep_key);
    RUN_TEST(test_certificates);
    RUN_TEST(test_certificate_bad_record);
    RUN_TEST(test_certificate_max_length);
    RUN_TEST(test_get_next_data_other_do);
    RUN_TEST(test_application_related_data);
    RUN_TEST(test_pw_status_bytes);
    RUN_TEST(test_signature_counter);
    RUN_TEST(test_import_ecc);
    RUN_TEST(test_import_ecc_short_key);
    RUN_TEST(test_import_ecc_wrong_length);
    RUN_TEST(test_import_truncated);
    RUN_TEST(test_import_unsupported_length);
    RUN_TEST(test_import_no_attributes);
    RUN_TEST(test_import_bad_headers);
    RUN_TEST(test_import_rsa_bad_parts);
    RUN_TEST(test_import_rsa);
    RUN_TEST(test_aes_key);
    RUN_TEST(test_aes_key_wrong_length);
    RUN_TEST(test_aes_key_crypto_error);
    RUN_TEST(test_sm_keys);
    RUN_TEST(test_resetting_code_lengths);
    RUN_TEST(test_resetting_code_clear);
    return UNITY_END();
}
