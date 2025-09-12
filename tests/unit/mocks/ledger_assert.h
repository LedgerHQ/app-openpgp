#define LEDGER_ASSERT(test, message) \
    do {                             \
        if (!(test)) {               \
            return;                  \
        }                            \
    } while (0)
