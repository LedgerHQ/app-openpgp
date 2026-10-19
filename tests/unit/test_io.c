#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "offsets.h"
#include "gpg_vars.h"
#include "fake_assert.h"
#include "fake_io.h"

void setUp(void) {
    gpg_io_discard(1);
    fake_io_reset();
    G_gpg_vstate.io_cla = 0;
    G_gpg_vstate.io_ins = 0;
}

void tearDown(void) {
}

// Load the IO buffer with data_len bytes of response data followed by the 9000 status word
static void load_response(size_t data_len) {
    gpg_io_discard(1);
    for (size_t i = 0; i < data_len; i++) {
        gpg_io_insert_u8(i & 0xFF);
    }
    gpg_io_insert_u16(SWO_SUCCESS);
}

static void load_buffer(const uint8_t *data, size_t len) {
    gpg_io_insert(data, len);
    gpg_io_set_offset(0);
}

/* ----------------------------------------------------------------------- */
/* Buffer insertion                                                        */
/* ----------------------------------------------------------------------- */

static void test_io(void) {
    unsigned int v32 = 0x789ABCDE;
    unsigned int v24 = 0x456789;
    unsigned int v16 = 0x3456;
    unsigned int v8 = 0x12;
    unsigned int value = 0;

    gpg_io_insert_u8(v8);
    gpg_io_insert_u16(v16);
    gpg_io_insert_u24(v24);

    // Mark the current offset
    gpg_io_mark();

    gpg_io_insert_u32(v32);

    // rewind offset to the beginning to the buffer
    gpg_io_set_offset(0);

    TEST_ASSERT_TRUE(gpg_io_fetch_u8(&value));
    TEST_ASSERT_EQUAL_UINT(v8, value);
    TEST_ASSERT_TRUE(gpg_io_fetch_u16(&value));
    TEST_ASSERT_EQUAL_UINT(v16, value);
    TEST_ASSERT_TRUE(gpg_io_fetch_u24(&value));
    TEST_ASSERT_EQUAL_UINT(v24, value);
    TEST_ASSERT_TRUE(gpg_io_fetch_u32(&value));
    TEST_ASSERT_EQUAL_UINT(v32, value);

    // rewind offset to the mark
    gpg_io_set_offset(IO_OFFSET_MARK);

    TEST_ASSERT_TRUE(gpg_io_fetch_u32(&value));
    TEST_ASSERT_EQUAL_UINT(v32, value);
}

static void test_io_insert_in_middle(void) {
    const uint8_t expected[] = {0x01, 0x02, 0x03, 0x04};

    gpg_io_insert_u8(0x01);
    gpg_io_insert_u8(0x04);
    gpg_io_set_offset(1);
    gpg_io_insert_u16(0x0203);

    TEST_ASSERT_EQUAL_UINT(sizeof(expected), G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_offset);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.work.io_buffer, sizeof(expected));
}

static void test_io_insert_tl(void) {
    // clang-format off
    const uint8_t expected[] = {
        0x5E, 0x7F,              // 1-byte tag, short length
        0x5F, 0x50, 0x81, 0x80,  // 2-byte tag, 1-byte long length
        0x7F, 0x49, 0x81, 0xFF,  // largest 1-byte long length
        0x65, 0x82, 0x01, 0x00,  // 2-byte long length
    };
    // clang-format on

    gpg_io_insert_tl(0x5E, 0x7F);
    gpg_io_insert_tl(0x5F50, 0x80);
    gpg_io_insert_tl(0x7F49, 0xFF);
    gpg_io_insert_tl(0x65, 0x100);

    TEST_ASSERT_EQUAL_UINT(sizeof(expected), G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.work.io_buffer, sizeof(expected));
}

static void test_io_insert_tlv(void) {
    const uint8_t value[] = {'A', 'B', 'C'};
    const uint8_t expected[] = {0x5B, 0x03, 'A', 'B', 'C'};

    gpg_io_insert_tlv(0x5B, sizeof(value), value);

    TEST_ASSERT_EQUAL_UINT(sizeof(expected), G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, G_gpg_vstate.work.io_buffer, sizeof(expected));
}

static void test_io_insert_full_buffer(void) {
    static const uint8_t data[GPG_IO_BUFFER_LENGTH] = {0};

    gpg_io_insert(data, sizeof(data));
    TEST_ASSERT_EQUAL_UINT(GPG_IO_BUFFER_LENGTH, G_gpg_vstate.io_length);

    TEST_ASSERT_LEDGER_ASSERT(gpg_io_insert_u8(0));
}

static void test_io_insert_too_long(void) {
    static const uint8_t data[GPG_IO_BUFFER_LENGTH + 1] = {0};

    TEST_ASSERT_LEDGER_ASSERT(gpg_io_insert(data, sizeof(data)));
}

/* ----------------------------------------------------------------------- */
/* Buffer fetch                                                            */
/* ----------------------------------------------------------------------- */

static void test_io_fetch_past_end(void) {
    unsigned int value = 0;

    gpg_io_insert_u16(0x1234);
    gpg_io_set_offset(0);

    TEST_ASSERT_FALSE(gpg_io_fetch_u32(&value));
    TEST_ASSERT_FALSE(gpg_io_fetch_u24(&value));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);

    gpg_io_set_offset(1);
    TEST_ASSERT_FALSE(gpg_io_fetch_u16(&value));
    TEST_ASSERT_EQUAL_UINT(1, G_gpg_vstate.io_offset);

    gpg_io_set_offset(IO_OFFSET_END);
    TEST_ASSERT_FALSE(gpg_io_fetch_u8(&value));
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.io_offset);
}

static void test_io_fetch_t(void) {
    const uint8_t data[] = {0x5E, 0x5F, 0x50, 0x7F, 0x49};
    unsigned int t = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_TRUE(gpg_io_fetch_t(&t));
    TEST_ASSERT_EQUAL_HEX(0x5E, t);
    TEST_ASSERT_TRUE(gpg_io_fetch_t(&t));
    TEST_ASSERT_EQUAL_HEX(0x5F50, t);
    TEST_ASSERT_TRUE(gpg_io_fetch_t(&t));
    TEST_ASSERT_EQUAL_HEX(0x7F49, t);
    TEST_ASSERT_EQUAL_UINT(sizeof(data), G_gpg_vstate.io_offset);
}

static void test_io_fetch_t_truncated(void) {
    // 2-byte tag whose second byte is missing
    const uint8_t data[] = {0x5F};
    unsigned int t = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_FALSE(gpg_io_fetch_t(&t));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);
}

static void test_io_fetch_l(void) {
    const uint8_t data[] = {0x05, 0x81, 0x80, 0x82, 0x01, 0x00};
    unsigned int l = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_TRUE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(5, l);
    TEST_ASSERT_EQUAL_UINT(1, G_gpg_vstate.io_offset);
    TEST_ASSERT_TRUE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(0x80, l);
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_offset);
    TEST_ASSERT_TRUE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(0x100, l);
    TEST_ASSERT_EQUAL_UINT(6, G_gpg_vstate.io_offset);
}

static void test_io_fetch_l_unsupported(void) {
    // Indefinite form and 3-byte long form
    const uint8_t data[] = {0x80, 0x83, 0x01, 0x00, 0x00};
    unsigned int l = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_FALSE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);

    gpg_io_set_offset(1);
    TEST_ASSERT_FALSE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(1, G_gpg_vstate.io_offset);
}

static void test_io_fetch_l_truncated(void) {
    const uint8_t long1[] = {0x81};
    const uint8_t long2[] = {0x82, 0x01};
    unsigned int l = 0;

    load_buffer(long1, sizeof(long1));
    TEST_ASSERT_FALSE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);

    gpg_io_discard(1);
    load_buffer(long2, sizeof(long2));
    TEST_ASSERT_FALSE(gpg_io_fetch_l(&l));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);
}

static void test_io_fetch_tl(void) {
    const uint8_t data[] = {0x7F, 0x49, 0x81, 0x90};
    unsigned int t = 0;
    unsigned int l = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_TRUE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_HEX(0x7F49, t);
    TEST_ASSERT_EQUAL_UINT(0x90, l);
}

static void test_io_fetch_tl_truncated(void) {
    // Complete tag, truncated length: the tag is not consumed either
    const uint8_t data[] = {0x7F, 0x49, 0x82, 0x01};
    unsigned int t = 0;
    unsigned int l = 0;

    load_buffer(data, sizeof(data));

    TEST_ASSERT_FALSE(gpg_io_fetch_tl(&t, &l));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);
}

static void test_io_fetch(void) {
    const uint8_t data[] = {'A', 'B', 'C', 'D'};
    uint8_t out[3] = {0};

    load_buffer(data, sizeof(data));

    TEST_ASSERT_TRUE(gpg_io_fetch(out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY("ABC", out, sizeof(out));
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_offset);
}

static void test_io_skip(void) {
    const uint8_t data[] = {'A', 'B', 'C'};

    load_buffer(data, sizeof(data));

    TEST_ASSERT_TRUE(gpg_io_skip(2));
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.io_offset);
    TEST_ASSERT_FALSE(gpg_io_skip(2));
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.io_offset);
    TEST_ASSERT_TRUE(gpg_io_skip(1));
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_offset);
}

static void test_io_fetch_too_long(void) {
    const uint8_t data[] = {'A', 'B', 'C'};
    uint8_t out[4] = {0};

    load_buffer(data, sizeof(data));

    TEST_ASSERT_FALSE(gpg_io_fetch(out, sizeof(out)));
    TEST_ASSERT_FALSE(gpg_io_fetch_nv(out, sizeof(out)));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, out, sizeof(out));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);
}

static void test_io_fetch_huge_length(void) {
    const uint8_t data[] = {'A', 'B', 'C'};
    uint8_t out[3] = {0};

    load_buffer(data, sizeof(data));
    gpg_io_set_offset(1);

    TEST_ASSERT_FALSE(gpg_io_fetch(out, UINT32_MAX));
    TEST_ASSERT_FALSE(gpg_io_fetch_nv(out, UINT32_MAX));
    TEST_ASSERT_FALSE(gpg_io_skip(UINT32_MAX));
    TEST_ASSERT_EQUAL_UINT(1, G_gpg_vstate.io_offset);
}

static void test_nvm_write(void) {
    const unsigned char secret[] = "secret";
    unsigned char stored[sizeof(secret)] = {0};

    gpg_io_insert((unsigned char *) secret, sizeof(secret));
    gpg_io_set_offset(0);
    TEST_ASSERT_TRUE(gpg_io_fetch_nv(stored, sizeof(stored)));
    TEST_ASSERT_EQUAL_MEMORY(secret, stored, sizeof(secret));

    // A NULL source erases the destination
    nvm_write(stored, NULL, sizeof(stored));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, stored, sizeof(stored));
}

/* ----------------------------------------------------------------------- */
/* Offset and buffer state                                                 */
/* ----------------------------------------------------------------------- */

static void test_io_set_offset(void) {
    gpg_io_insert_u32(0x01020304);

    gpg_io_set_offset(2);
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.io_offset);
    gpg_io_mark();
    gpg_io_set_offset(IO_OFFSET_END);
    TEST_ASSERT_EQUAL_UINT(4, G_gpg_vstate.io_offset);
    gpg_io_set_offset(IO_OFFSET_MARK);
    TEST_ASSERT_EQUAL_UINT(2, G_gpg_vstate.io_offset);

    TEST_ASSERT_LEDGER_ASSERT(gpg_io_set_offset(4));
}

static void test_io_inserted(void) {
    gpg_io_insert_u8(0x01);
    gpg_io_inserted(3);

    TEST_ASSERT_EQUAL_UINT(4, G_gpg_vstate.io_offset);
    TEST_ASSERT_EQUAL_UINT(4, G_gpg_vstate.io_length);
}

static void test_io_discard(void) {
    gpg_io_insert_u32(0x01020304);
    gpg_io_mark();

    gpg_io_discard(0);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_offset);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_mark);
    TEST_ASSERT_EQUAL_HEX8(0x01, G_gpg_vstate.work.io_buffer[0]);

    gpg_io_discard(1);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
}

/* ----------------------------------------------------------------------- */
/* Command reception                                                       */
/* ----------------------------------------------------------------------- */

static void test_io_receive(void) {
    // GET DATA 6E, then PUT DATA 5B with "ABC"
    const uint8_t get_data[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};
    const uint8_t put_data[] = {0x00, 0xDA, 0x00, 0x5B, 0x03, 'A', 'B', 'C'};

    fake_io_push_rx(get_data, sizeof(get_data));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0xCA, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_HEX16(0x006E, G_gpg_vstate.io_p1p2);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);

    fake_io_push_rx(put_data, sizeof(put_data));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0xDA, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_MEMORY("ABC", G_gpg_vstate.work.io_buffer, 3);
}

static void test_io_receive_header_only(void) {
    // ACTIVATE FILE, case 1
    const uint8_t frame[] = {0x00, 0x44, 0x00, 0x00};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0x44, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_lc);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_le);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_receive_le_only(void) {
    // GENERATE ASYMMETRIC KEY PAIR, read the public key: case 2
    const uint8_t frame[] = {0x00, 0x47, 0x81, 0x00, 0x20};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0x81, G_gpg_vstate.io_p1);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_lc);
    TEST_ASSERT_EQUAL_UINT(0x20, G_gpg_vstate.io_le);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_receive_lc_and_le(void) {
    // PUT DATA, case 4
    const uint8_t frame[] = {0x00, 0xDA, 0x00, 0x5B, 0x03, 'A', 'B', 'C', 0x00};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_lc);
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_MEMORY("ABC", G_gpg_vstate.work.io_buffer, 3);
}

static void test_io_receive_get_challenge(void) {
    const uint8_t frame[] = {0x00, 0x84, 0x00, 0x00, 0x10};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0x10, G_gpg_vstate.io_le);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_receive_verify_status(void) {
    // VERIFY without PIN, with and without the Lc byte
    const uint8_t no_lc[] = {0x00, 0x20, 0x00, 0x81};
    const uint8_t empty_lc[] = {0x00, 0x20, 0x00, 0x81, 0x00};

    fake_io_push_rx(no_lc, sizeof(no_lc));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);

    fake_io_push_rx(empty_lc, sizeof(empty_lc));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_receive_verify_pin(void) {
    const uint8_t frame[] = {0x00, 0x20, 0x00, 0x81, 0x06, '1', '2', '3', '4', '5', '6'};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(6, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_MEMORY("123456", G_gpg_vstate.work.io_buffer, 6);
}

static void test_io_receive_verify_wrong_lc(void) {
    // Lc announces 6 PIN bytes, 3 are received
    const uint8_t frame[] = {0x00, 0x20, 0x00, 0x81, 0x06, '1', '2', '3'};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_truncated(void) {
    // Lc announces 5 bytes, 2 are received
    const uint8_t frame[] = {0x00, 0xDA, 0x00, 0x5B, 0x05, 'A', 'B'};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
}

static void test_io_too_long(void) {
    // Lc announces 1 byte, followed by 3 bytes
    const uint8_t frame[] = {0x00, 0xDA, 0x00, 0x5B, 0x01, 'A', 'B', 'C'};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_short_frame(void) {
    const uint8_t frame[] = {0x00, 0xDA, 0x00};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    // The rejected command is not left for the dispatcher
    TEST_ASSERT_EQUAL_HEX8(CLA_APP_DEF, G_gpg_vstate.io_cla);
    TEST_ASSERT_EQUAL_HEX8(0, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

/* ----------------------------------------------------------------------- */
/* Command chaining                                                        */
/* ----------------------------------------------------------------------- */

static void test_io_chaining(void) {
    const uint8_t first[] = {0x10, 0xDA, 0x00, 0x5B, 0x02, 'A', 'B'};
    const uint8_t last[] = {0x00, 0xDA, 0x00, 0x5B, 0x01, 'C'};

    fake_io_push_rx(first, sizeof(first));
    fake_io_push_rx(last, sizeof(last));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0x00, G_gpg_vstate.io_cla);
    TEST_ASSERT_EQUAL_UINT(3, G_gpg_vstate.io_length);
    TEST_ASSERT_EQUAL_MEMORY("ABC", G_gpg_vstate.work.io_buffer, 3);

    // The intermediate command is acknowledged with 9000
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx_count);
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx[1].len);
    TEST_ASSERT_EQUAL_HEX8(0x90, fake_io_tx[1].data[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, fake_io_tx[1].data[1]);
}

static void test_io_chaining_other_command(void) {
    const uint8_t first[] = {0x10, 0xDA, 0x00, 0x5B, 0x02, 'A', 'B'};
    const uint8_t other[] = {0x00, 0xDA, 0x00, 0x5E, 0x01, 'C'};

    fake_io_push_rx(first, sizeof(first));
    fake_io_push_rx(other, sizeof(other));
    TEST_ASSERT_EQUAL_HEX16(SWO_LAST_COMMAND_OF_CHAIN_EXPECTED, gpg_io_do(0));
    TEST_ASSERT_EQUAL_HEX8(0, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_chaining_short_frame(void) {
    const uint8_t first[] = {0x10, 0xDA, 0x00, 0x5B, 0x02, 'A', 'B'};
    const uint8_t last[] = {0x00, 0xDA, 0x00};

    fake_io_push_rx(first, sizeof(first));
    fake_io_push_rx(last, sizeof(last));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_chaining_wrong_lc(void) {
    const uint8_t first[] = {0x10, 0xDA, 0x00, 0x5B, 0x02, 'A', 'B'};
    const uint8_t last[] = {0x00, 0xDA, 0x00, 0x5B, 0x04, 'C'};

    fake_io_push_rx(first, sizeof(first));
    fake_io_push_rx(last, sizeof(last));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_chaining_overflow(void) {
    // 6 chained commands of 255 bytes exceed the IO buffer
    static uint8_t frame[OFFSET_CDATA + 255];
    const size_t chunks = (GPG_IO_BUFFER_LENGTH / 255) + 1;

    memset(frame, 'A', sizeof(frame));
    frame[OFFSET_CLA] = CLA_APP_CHAIN;
    frame[OFFSET_INS] = 0xDA;
    frame[OFFSET_P1] = 0x00;
    frame[OFFSET_P2] = 0x5B;
    frame[OFFSET_LC] = 255;
    for (size_t i = 0; i < chunks; i++) {
        fake_io_push_rx(frame, sizeof(frame));
    }
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

/* ----------------------------------------------------------------------- */
/* Response transmission                                                   */
/* ----------------------------------------------------------------------- */

static void test_io_transmit(void) {
    const uint8_t frame[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    gpg_io_insert_u16(0x9000);
    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(1, fake_io_tx_count);
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx[0].len);
    TEST_ASSERT_EQUAL_HEX8(0x90, fake_io_tx[0].data[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, fake_io_tx[0].data[1]);
}

static void test_io_transmit_largest_single(void) {
    // The largest response sent without 61xx
    const uint8_t next[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    load_response(GPG_APDU_LENGTH - 2);
    fake_io_push_rx(next, sizeof(next));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(1, fake_io_tx_count);
    TEST_ASSERT_EQUAL_UINT(GPG_APDU_LENGTH, fake_io_tx[0].len);
}

static void test_io_transmit_chained(void) {
    const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x30};
    const uint8_t next[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};
    const size_t first_len = GPG_APDU_LENGTH - 2;
    const size_t data_len = 300;

    load_response(data_len);
    fake_io_push_rx(get_response, sizeof(get_response));
    fake_io_push_rx(next, sizeof(next));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx_count);

    // First part, with 61xx announcing the remaining data
    TEST_ASSERT_EQUAL_UINT(first_len + 2, fake_io_tx[0].len);
    TEST_ASSERT_EQUAL_HEX8(0x00, fake_io_tx[0].data[0]);
    TEST_ASSERT_EQUAL_HEX8(first_len - 1, fake_io_tx[0].data[first_len - 1]);
    TEST_ASSERT_EQUAL_HEX8(0x61, fake_io_tx[0].data[first_len]);
    TEST_ASSERT_EQUAL_UINT(data_len - first_len, fake_io_tx[0].data[first_len + 1]);

    // Remaining data, then 9000
    TEST_ASSERT_EQUAL_UINT(data_len - first_len + 2, fake_io_tx[1].len);
    TEST_ASSERT_EQUAL_HEX8(first_len & 0xFF, fake_io_tx[1].data[0]);
    TEST_ASSERT_EQUAL_HEX8(0x90, fake_io_tx[1].data[data_len - first_len]);
    TEST_ASSERT_EQUAL_HEX8(0x00, fake_io_tx[1].data[data_len - first_len + 1]);

    // The command received after the response is ready to be dispatched
    TEST_ASSERT_EQUAL_HEX8(0xCA, G_gpg_vstate.io_ins);
}

static void test_io_transmit_chained_announce(void) {
    // Every 61xx announces the data actually sent in the next part
    const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
    const size_t first_len = GPG_APDU_LENGTH - 2;

    for (size_t remaining = 1; remaining <= GPG_APDU_LENGTH - 2; remaining++) {
        fake_io_reset();
        load_response(first_len + remaining);
        fake_io_push_rx(get_response, sizeof(get_response));
        gpg_io_do(IO_RETURN_AFTER_TX);

        TEST_ASSERT_EQUAL_UINT(2, fake_io_tx_count);
        TEST_ASSERT_EQUAL_UINT_MESSAGE(remaining + 2, fake_io_tx[1].len, "last part length");
        TEST_ASSERT_EQUAL_UINT_MESSAGE(remaining,
                                       fake_io_tx[0].data[first_len + 1],
                                       "61xx announced length");
    }
}

static void test_io_transmit_chain_dropped(void) {
    // Another command than GET RESPONSE drops the remaining data
    const uint8_t other[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    load_response(300);
    fake_io_push_rx(other, sizeof(other));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(1, fake_io_tx_count);
    TEST_ASSERT_EQUAL_HEX8(0xCA, G_gpg_vstate.io_ins);
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
}

static void test_io_return_after_tx(void) {
    gpg_io_insert_u16(0x9000);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(IO_RETURN_AFTER_TX));
    TEST_ASSERT_EQUAL_UINT(1, fake_io_tx_count);
    TEST_ASSERT_EQUAL_HEX8(CHANNEL_APDU | IO_RETURN_AFTER_TX, fake_io_tx[0].flags);
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx[0].len);
}

static void test_io_asynch_reply(void) {
    const uint8_t frame[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(IO_ASYNCH_REPLY));
    TEST_ASSERT_EQUAL_UINT(1, fake_io_tx_count);
    TEST_ASSERT_EQUAL_HEX8(CHANNEL_APDU | IO_ASYNCH_REPLY, fake_io_tx[0].flags);
    TEST_ASSERT_EQUAL_UINT(0, fake_io_tx[0].len);
    TEST_ASSERT_EQUAL_HEX8(0xCA, G_gpg_vstate.io_ins);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_io);
    RUN_TEST(test_io_insert_in_middle);
    RUN_TEST(test_io_insert_tl);
    RUN_TEST(test_io_insert_tlv);
    RUN_TEST(test_io_insert_full_buffer);
    RUN_TEST(test_io_insert_too_long);
    RUN_TEST(test_io_fetch_past_end);
    RUN_TEST(test_io_fetch_t);
    RUN_TEST(test_io_fetch_t_truncated);
    RUN_TEST(test_io_fetch_l);
    RUN_TEST(test_io_fetch_l_unsupported);
    RUN_TEST(test_io_fetch_l_truncated);
    RUN_TEST(test_io_fetch_tl);
    RUN_TEST(test_io_fetch_tl_truncated);
    RUN_TEST(test_io_fetch);
    RUN_TEST(test_io_skip);
    RUN_TEST(test_io_fetch_too_long);
    RUN_TEST(test_io_fetch_huge_length);
    RUN_TEST(test_nvm_write);
    RUN_TEST(test_io_set_offset);
    RUN_TEST(test_io_inserted);
    RUN_TEST(test_io_discard);
    RUN_TEST(test_io_receive);
    RUN_TEST(test_io_receive_header_only);
    RUN_TEST(test_io_receive_le_only);
    RUN_TEST(test_io_receive_lc_and_le);
    RUN_TEST(test_io_receive_get_challenge);
    RUN_TEST(test_io_receive_verify_status);
    RUN_TEST(test_io_receive_verify_pin);
    RUN_TEST(test_io_receive_verify_wrong_lc);
    RUN_TEST(test_io_truncated);
    RUN_TEST(test_io_too_long);
    RUN_TEST(test_io_short_frame);
    RUN_TEST(test_io_chaining);
    RUN_TEST(test_io_chaining_other_command);
    RUN_TEST(test_io_chaining_short_frame);
    RUN_TEST(test_io_chaining_wrong_lc);
    RUN_TEST(test_io_chaining_overflow);
    RUN_TEST(test_io_transmit);
    RUN_TEST(test_io_transmit_largest_single);
    RUN_TEST(test_io_transmit_chained);
    RUN_TEST(test_io_transmit_chained_announce);
    RUN_TEST(test_io_transmit_chain_dropped);
    RUN_TEST(test_io_return_after_tx);
    RUN_TEST(test_io_asynch_reply);
    return UNITY_END();
}
