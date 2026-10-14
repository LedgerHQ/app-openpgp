#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "gpg_vars.h"
#include "mocks.h"

static int setup(void **state) {
    (void) state;

    // Init tests
    gpg_io_discard(1);
    mock_io_reset();
    return 0;
}

static void test_io(void **state) {
    (void) state;

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

    assert_int_equal(gpg_io_fetch_u8(), v8);
    assert_int_equal(gpg_io_fetch_u16(), v16);
    assert_int_equal(gpg_io_fetch_u32(), v32);

    // rewind offset to the mark
    gpg_io_set_offset(IO_OFFSET_MARK);

    assert_int_equal(gpg_io_fetch_u32(), v32);
}

static void test_io_receive(void **state) {
    (void) state;
    // GET DATA 6E, then PUT DATA 5B with "ABC"
    const uint8_t get_data[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};
    const uint8_t put_data[] = {0x00, 0xDA, 0x00, 0x5B, 0x03, 'A', 'B', 'C'};

    mock_io_push_rx(get_data, sizeof(get_data));
    assert_int_equal(gpg_io_do(0), SWO_SUCCESS);
    assert_int_equal(G_gpg_vstate.io_ins, 0xCA);
    assert_int_equal(G_gpg_vstate.io_p1p2, 0x006E);
    assert_int_equal(G_gpg_vstate.io_length, 0);

    mock_io_push_rx(put_data, sizeof(put_data));
    assert_int_equal(gpg_io_do(0), SWO_SUCCESS);
    assert_int_equal(G_gpg_vstate.io_ins, 0xDA);
    assert_int_equal(G_gpg_vstate.io_length, 3);
    assert_memory_equal(G_gpg_vstate.work.io_buffer, "ABC", 3);
}

static void test_io_truncated(void **state) {
    (void) state;
    // Lc announces 5 bytes, 2 are received
    const uint8_t frame[] = {0x00, 0xDA, 0x00, 0x5B, 0x05, 'A', 'B'};

    mock_io_push_rx(frame, sizeof(frame));
    assert_int_equal(gpg_io_do(0), SWO_WRONG_LENGTH);
}

static void test_io_transmit(void **state) {
    (void) state;
    const uint8_t frame[] = {0x00, 0xCA, 0x00, 0x6E, 0x00};

    gpg_io_insert_u16(0x9000);
    mock_io_push_rx(frame, sizeof(frame));
    assert_int_equal(gpg_io_do(0), SWO_SUCCESS);
    assert_int_equal(mock_io_tx_len, 2);
    assert_int_equal(mock_io_tx[0], 0x90);
    assert_int_equal(mock_io_tx[1], 0x00);
}

static void test_nvm_write(void **state) {
    (void) state;
    const unsigned char secret[] = "secret";
    unsigned char stored[sizeof(secret)] = {0};

    gpg_io_insert((unsigned char *) secret, sizeof(secret));
    gpg_io_set_offset(0);
    gpg_io_fetch_nv(stored, sizeof(stored));
    assert_memory_equal(stored, secret, sizeof(secret));

    // A NULL source erases the destination
    nvm_write(stored, NULL, sizeof(stored));
    for (size_t i = 0; i < sizeof(stored); i++) {
        assert_int_equal(stored[i], 0);
    }
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test_setup(test_io, setup),
                                       cmocka_unit_test_setup(test_io_receive, setup),
                                       cmocka_unit_test_setup(test_io_truncated, setup),
                                       cmocka_unit_test_setup(test_io_transmit, setup),
                                       cmocka_unit_test_setup(test_nvm_write, setup)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
