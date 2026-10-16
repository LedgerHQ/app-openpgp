#include <stdlib.h>
#include <string.h>

#include "exceptions.h"
#include "os_seed.h"
#include "ox_bn.h"
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

// Deterministic stand-in for the seed derivation: a 32-byte key depending on the path
void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
    unsigned int tag = 0;

    (void) mode;
    (void) curve;
    (void) seed_key;
    (void) seed_key_length;
    for (unsigned int i = 0; i < pathLength; i++) {
        tag = (tag * 31) + path[i];
    }
    for (unsigned int i = 0; i < 32; i++) {
        privateKey[i] = (unsigned char) (tag + (i * 7));
        if (chain != NULL) {
            chain[i] = (unsigned char) (tag ^ i);
        }
    }
}

// Deterministic stand-in for the curve parameters: 0xFF bytes, then 0xFE as the last one
cx_err_t cx_ecdomain_parameter(cx_curve_t cv, cx_curve_dom_param_t id, uint8_t *p, uint32_t p_len) {
    (void) cv;
    (void) id;
    memset(p, 0xFF, p_len);
    if (p_len != 0) {
        p[p_len - 1] = 0xFE;
    }
    return CX_OK;
}

// Curve parameters lengths of the curves supported by the app
cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    switch (cv) {
        case CX_CURVE_SECP256K1:
        case CX_CURVE_SECP256R1:
        case CX_CURVE_Ed25519:
        case CX_CURVE_Curve25519:
            *length = 32;
            return CX_OK;
        default:
            return CX_EC_INVALID_CURVE;
    }
}

static bool bn_locked;

cx_err_t cx_bn_lock(size_t word_nbytes, uint32_t flags) {
    (void) word_nbytes;
    (void) flags;
    TEST_ASSERT_FALSE_MESSAGE(bn_locked, "BN already locked");
    bn_locked = true;
    return CX_OK;
}

uint32_t cx_bn_unlock(void) {
    TEST_ASSERT_TRUE_MESSAGE(bn_locked, "BN not locked");
    bn_locked = false;
    return CX_OK;
}

// Points keep their x coordinate, and get a constant y coordinate
static uint8_t point_x[32];

cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv) {
    (void) P;
    (void) cv;
    TEST_ASSERT_TRUE_MESSAGE(bn_locked, "BN not locked");
    return CX_OK;
}

cx_err_t cx_ecpoint_decompress(cx_ecpoint_t *P,
                               const uint8_t *xy_compressed,
                               size_t xy_compressed_len,
                               uint32_t sign) {
    (void) P;
    (void) sign;
    TEST_ASSERT_EQUAL_UINT(sizeof(point_x), xy_compressed_len);
    memcpy(point_x, xy_compressed, sizeof(point_x));
    return CX_OK;
}

cx_err_t cx_ecpoint_export(const cx_ecpoint_t *P,
                           uint8_t *x,
                           size_t x_len,
                           uint8_t *y,
                           size_t y_len) {
    (void) P;
    TEST_ASSERT_EQUAL_UINT(sizeof(point_x), x_len);
    memcpy(x, point_x, x_len);
    memset(y, 0x5A, y_len);
    return CX_OK;
}
