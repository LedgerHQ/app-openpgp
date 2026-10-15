#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "fake_io.h"

void setUp(void) {
    gpg_io_discard(1);
    fake_io_reset();
}

void tearDown(void) {
}

static void test_io(void) {
    unsigned int v32 = 0x789ABCDE;
    unsigned int v16 = 0x3456;
    unsigned int v8 = 0x12;

    gpg_io_insert_u8(v8);

    gpg_io_insert_u16(v16);

    // Mark the current offset
    gpg_io_mark();

    gpg_io_insert_u32(v32);

    // rewind offset to the beginning to the buffer
    gpg_io_set_offset(0);

    TEST_ASSERT_EQUAL_UINT(v8, gpg_io_fetch_u8());
    TEST_ASSERT_EQUAL_UINT(v16, gpg_io_fetch_u16());
    TEST_ASSERT_EQUAL_UINT(v32, gpg_io_fetch_u32());

    // rewind offset to the mark
    gpg_io_set_offset(IO_OFFSET_MARK);

    TEST_ASSERT_EQUAL_UINT(v32, gpg_io_fetch_u32());
}

static void test_io_fetch_past_end(void) {
    gpg_io_insert_u16(0x1234);
    gpg_io_set_offset(0);

    TEST_ASSERT_LEDGER_ASSERT(gpg_io_fetch_u32());
}

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

static void test_io_truncated(void) {
    // Lc announces 5 bytes, 2 are received
    const uint8_t frame[] = {0x00, 0xDA, 0x00, 0x5B, 0x05, 'A', 'B'};

    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_WRONG_LENGTH, gpg_io_do(0));
}

static void test_io_transmit(void) {
    const uint8_t frame[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    gpg_io_insert_u16(0x9000);
    fake_io_push_rx(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_io_do(0));
    TEST_ASSERT_EQUAL_UINT(2, fake_io_tx_len);
    TEST_ASSERT_EQUAL_HEX8(0x90, fake_io_tx[0]);
    TEST_ASSERT_EQUAL_HEX8(0x00, fake_io_tx[1]);
}

static void test_nvm_write(void) {
    const unsigned char secret[] = "secret";
    unsigned char stored[sizeof(secret)] = {0};

    gpg_io_insert((unsigned char *) secret, sizeof(secret));
    gpg_io_set_offset(0);
    gpg_io_fetch_nv(stored, sizeof(stored));
    TEST_ASSERT_EQUAL_MEMORY(secret, stored, sizeof(secret));

    // A NULL source erases the destination
    nvm_write(stored, NULL, sizeof(stored));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, stored, sizeof(stored));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_io);
    RUN_TEST(test_io_fetch_past_end);
    RUN_TEST(test_io_receive);
    RUN_TEST(test_io_truncated);
    RUN_TEST(test_io_transmit);
    RUN_TEST(test_nvm_write);
    return UNITY_END();
}
