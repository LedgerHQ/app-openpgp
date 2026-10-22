#include <string.h>

#include "Mocklcx_hash.h"
#include "Mocklcx_sha256.h"
#include "Mocklcx_sha3.h"
#include "fake_digest.h"

size_t fake_shake_bits;

static uint32_t hash_acc;
static uint8_t shake_in[32];

static cx_err_t fake_sha256_init(cx_sha256_t *hash, int num_calls) {
    (void) hash;
    (void) num_calls;
    hash_acc = 0;
    return CX_OK;
}

static cx_err_t fake_hash(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len,
                          int num_calls) {
    (void) hash;
    (void) num_calls;
    for (size_t i = 0; i < len; i++) {
        hash_acc = (hash_acc * 31) + in[i];
    }
    if (mode & CX_LAST) {
        for (size_t i = 0; i < out_len; i++) {
            out[i] = (uint8_t) ((hash_acc >> ((i % 4) * 8)) ^ i);
        }
        hash_acc = 0;
    }
    return CX_OK;
}

static cx_err_t fake_shake_init(cx_sha3_t *hash, size_t out_size, int num_calls) {
    (void) hash;
    (void) num_calls;
    fake_shake_bits = out_size;
    return CX_OK;
}

static cx_err_t fake_sha3_update(cx_sha3_t *ctx, const uint8_t *data, size_t len, int num_calls) {
    (void) ctx;
    (void) num_calls;
    memcpy(shake_in, data, (len < sizeof(shake_in)) ? len : sizeof(shake_in));
    return CX_OK;
}

static cx_err_t fake_sha3_final(cx_sha3_t *ctx, uint8_t *digest, int num_calls) {
    (void) ctx;
    (void) num_calls;
    for (size_t i = 0; i < fake_shake_bits / 8; i++) {
        digest[i] = shake_in[i % sizeof(shake_in)] ^ 0xA5 ^ (uint8_t) i;
    }
    return CX_OK;
}

void fake_digest_install(void) {
    hash_acc = 0;
    fake_shake_bits = 0;
    cx_sha256_init_no_throw_StubWithCallback(fake_sha256_init);
    cx_hash_no_throw_StubWithCallback(fake_hash);
    cx_shake256_init_no_throw_StubWithCallback(fake_shake_init);
    cx_sha3_update_StubWithCallback(fake_sha3_update);
    cx_sha3_final_StubWithCallback(fake_sha3_final);
}
