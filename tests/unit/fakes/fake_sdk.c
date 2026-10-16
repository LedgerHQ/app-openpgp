#include <stdlib.h>

#include "exceptions.h"
#include "os_seed.h"
#include "ox_ec.h"
#include "unity.h"

static try_context_t *current_context;

try_context_t *try_context_get(void) {
    return current_context;
}

try_context_t *try_context_set(try_context_t *context) {
    try_context_t *previous = current_context;
    current_context = context;
    return previous;
}

// Like the device without a TRY block, never return to the throwing code
void os_longjmp(unsigned int exception) {
    (void) exception;
    TEST_FAIL_MESSAGE("Unexpected exception");
    abort();
}

// Seed derivation is not emulated: tests reaching it must mock their caller
void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
    (void) mode;
    (void) curve;
    (void) path;
    (void) pathLength;
    (void) privateKey;
    (void) chain;
    (void) seed_key;
    (void) seed_key_length;
    TEST_FAIL_MESSAGE("Unexpected seed derivation");
}

// Curve parameters are not emulated: tests reaching them must mock their caller
cx_err_t cx_ecdomain_parameter(cx_curve_t cv, cx_curve_dom_param_t id, uint8_t *p, uint32_t p_len) {
    (void) cv;
    (void) id;
    (void) p;
    (void) p_len;
    TEST_FAIL_MESSAGE("Unexpected curve parameter request");
    return CX_INTERNAL_ERROR;
}
