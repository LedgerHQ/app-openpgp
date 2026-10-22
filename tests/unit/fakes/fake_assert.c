#include <stdlib.h>

#include "ledger_assert.h"
#include "fake_assert.h"

static bool expected;
static bool triggered;

void fake_assert_expect(void) {
    expected = true;
    triggered = false;
}

bool fake_assert_triggered(void) {
    expected = false;
    return triggered;
}

// Like the device, never return to the asserting code
void assert_exit(bool confirm) {
    (void) confirm;
    triggered = true;
    if (!expected) {
        TEST_FAIL_MESSAGE("Unexpected LEDGER_ASSERT failure");
    }
    TEST_ABORT();
    abort();
}
