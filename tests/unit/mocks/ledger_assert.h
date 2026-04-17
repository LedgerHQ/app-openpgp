#include <stdio.h>
#include <stdlib.h>

/* Fail-stop mock: abort the test process instead of silently returning so
 * that callers cannot continue after a violated precondition.  The original
 * bare-return behaviour masked real APDU boundary bugs in unit tests. */
#define LEDGER_ASSERT(test, message)                        \
    do {                                                    \
        if (!(test)) {                                      \
            fprintf(stderr,                                 \
                    "LEDGER_ASSERT failed: %s\n", message); \
            abort();                                        \
        }                                                   \
    } while (0)
