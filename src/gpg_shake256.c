

#ifdef GPG_SHAKE256

#include "os.h"

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */

#define cx_rotr64(x, n) (((x) >> (n)) | ((x) << ((64) - (n))))

#define cx_rotl64(x, n) (((x) << (n)) | ((x) >> ((64) - (n))))

#define cx_shr64(x, n) ((x) >> (n))

// Assume state is a uint64_t array
#define S64(x, y) state[x + 5 * y]
#define ROTL64(x, n) cx_rotl64(x, n)

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
static void cx_sha3_theta(uint64_t state[]) {
  uint64_t C[5];
  uint64_t D[5];
  int      i, j;

  for (i = 0; i < 5; i++) {
    C[i] = S64(i, 0) ^ S64(i, 1) ^ S64(i, 2) ^ S64(i, 3) ^ S64(i, 4);
  }
  for (i = 0; i < 5; i++) {
    D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    for (j = 0; j < 5; j++) {
      S64(i, j) ^= D[i];
    }
  }
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
static const int C_cx_pi_table[] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

static const int C_cx_rho_table[] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                     27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

static void cx_sha3_rho_pi(uint64_t state[]) {
  int      i, j;
  uint64_t A;
  uint64_t tmp;

  A = state[1];
  for (i = 0; i < 24; i++) {
    j        = C_cx_pi_table[i];
    tmp      = state[j];
    state[j] = ROTL64(A, C_cx_rho_table[i]);
    A        = tmp;
  }
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
static void cx_sha3_chi(uint64_t state[]) {
  uint64_t C[5];

  int i, j;
  for (j = 0; j < 5; j++) {
    for (i = 0; i < 5; i++) {
      C[i] = S64(i, j);
    }
    for (i = 0; i < 5; i++) {
      S64(i, j) ^= (~C[(i + 1) % 5]) & C[(i + 2) % 5];
    }
  }
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */
#define _64BITS(h, l) (h##ULL << 32) | (l##ULL)

static const uint64_t C_cx_iota_RC[24] = {
    _64BITS(0x00000000, 0x00000001), _64BITS(0x00000000, 0x00008082), _64BITS(0x80000000, 0x0000808A),
    _64BITS(0x80000000, 0x80008000), _64BITS(0x00000000, 0x0000808B), _64BITS(0x00000000, 0x80000001),
    _64BITS(0x80000000, 0x80008081), _64BITS(0x80000000, 0x00008009), _64BITS(0x00000000, 0x0000008A),
    _64BITS(0x00000000, 0x00000088), _64BITS(0x00000000, 0x80008009), _64BITS(0x00000000, 0x8000000A),
    _64BITS(0x00000000, 0x8000808B), _64BITS(0x80000000, 0x0000008B), _64BITS(0x80000000, 0x00008089),
    _64BITS(0x80000000, 0x00008003), _64BITS(0x80000000, 0x00008002), _64BITS(0x80000000, 0x00000080),
    _64BITS(0x00000000, 0x0000800A), _64BITS(0x80000000, 0x8000000A), _64BITS(0x80000000, 0x80008081),
    _64BITS(0x80000000, 0x00008080), _64BITS(0x00000000, 0x80000001), _64BITS(0x80000000, 0x80008008)};

static void cx_sha3_iota(uint64_t state[], int round) {
  S64(0, 0) ^= C_cx_iota_RC[round];
}

/* ----------------------------------------------------------------------- */
/*                                                                         */
/* ----------------------------------------------------------------------- */

static void cx_sha3_block(cx_sha3_t *hash) {
  uint64_t *block;
  uint64_t *acc;
  int       r, i, n;

  block = (uint64_t *)hash->block;
  acc   = (uint64_t *)hash->acc;

  if (hash->block_size > 144) {
    n = 21;
  } else if (hash->block_size > 136) {
    n = 18;
  } else if (hash->block_size > 104) {
    n = 17;
  } else if (hash->block_size > 72) {
    n = 13;
  } else {
    n = 9;
  }
  for (i = 0; i < n; i++) {
    acc[i] ^= block[i];
  }

  for (r = 0; r < 24; r++) {
    cx_sha3_theta(acc);
    cx_sha3_rho_pi(acc);
    cx_sha3_chi(acc);
    cx_sha3_iota(acc, r);
  }
}

void cx_shake256_init(cx_sha3_t *hash, unsigned int out_length) {
  memset(hash, 0, sizeof(cx_sha3_t));
  hash->header.algo = CX_SHAKE256;
  hash->output_size = out_length;
  hash->block_size  = (1600 - 2 * 256) >> 3;
}

void cx_shake256_update(cx_sha3_t *ctx, const uint8_t *data, size_t len) {
  unsigned int   r;
  unsigned int   block_size;
  unsigned char *block;
  unsigned int   blen;

  block_size = ctx->block_size;

  block     = ctx->block;
  blen      = ctx->blen;
  ctx->blen = 0;

  // --- append input data and process all blocks ---
  if ((blen + len) >= block_size) {
    r = block_size - blen;
    do {
      if (ctx->header.counter == CX_HASH_MAX_BLOCK_COUNT) {
        THROW(INVALID_PARAMETER);
      }
      memcpy(block + blen, data, r);
      cx_sha3_block(ctx);

      blen = 0;
      ctx->header.counter++;
      data += r;
      len -= r;
      r = block_size;
    } while (len >= block_size);
  }

  // --- remind rest data---
  memcpy(block + blen, data, len);
  blen += len;
  ctx->blen = blen;
}

int cx_shake256_final(cx_sha3_t *hash, uint8_t *digest) {
  unsigned int   block_size;
  unsigned char *block;
  unsigned int   blen;
  unsigned int   len;

  block      = hash->block;
  block_size = hash->block_size;
  blen       = hash->blen;

  // CX_SHA3_XOF
  memset(block + blen, 0, (200 - blen));
  block[blen] |= 0x1F;
  block[block_size - 1] |= 0x80;
  cx_sha3_block(hash);
  // provide result
  len  = hash->output_size;
  blen = len;

  memset(block, 0, 200);

  while (blen > block_size) {
    memcpy(digest, hash->acc, block_size);
    blen -= block_size;
    digest += block_size;
    cx_sha3_block(hash);
  }
  memcpy(digest, hash->acc, blen);
  return 1;
}

#endif // GPG_SHAKE256