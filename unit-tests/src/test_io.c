#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "gpg_vars.h"

static int setup(void **state) {
    (void) state;

    // Init tests
    gpg_io_discard(1);
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

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test_setup(test_io, setup)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
