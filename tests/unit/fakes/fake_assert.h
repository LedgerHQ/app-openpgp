#pragma once

#include <setjmp.h>
#include <stdbool.h>
#include <string.h>

#include "unity.h"

// Arm assert_exit() to unwind back to the caller instead of failing the test
void fake_assert_expect(void);
// Disarm assert_exit(), and return whether it was reached since fake_assert_expect()
bool fake_assert_triggered(void);

// Run a statement and check that it ends in a LEDGER_ASSERT failure
#define TEST_ASSERT_LEDGER_ASSERT(statement)                                              \
    do {                                                                                  \
        jmp_buf fake_assert_outer_frame;                                                  \
        memcpy(fake_assert_outer_frame, Unity.AbortFrame, sizeof(jmp_buf));               \
        fake_assert_expect();                                                             \
        if (TEST_PROTECT()) {                                                             \
            statement;                                                                    \
        }                                                                                 \
        memcpy(Unity.AbortFrame, fake_assert_outer_frame, sizeof(jmp_buf));               \
        TEST_ASSERT_TRUE_MESSAGE(fake_assert_triggered(), "LEDGER_ASSERT not triggered"); \
    } while (0)
