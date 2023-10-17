/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gpg_vars.h"
#include "cx_errors.h"

int gpg_apdu_get_challenge() {
    unsigned int olen, hlen;
    cx_err_t error = CX_INTERNAL_ERROR;

    if ((G_gpg_vstate.io_p1 & 0x80) == 0x80) {
        olen = G_gpg_vstate.io_p2;
    } else {
        olen = G_gpg_vstate.io_le;
    }
    if (olen == 0 || olen > GPG_EXT_CHALLENGE_LENTH) {
        THROW(SW_WRONG_LENGTH);
        return SW_WRONG_LENGTH;
    }

    if ((G_gpg_vstate.io_p1 & 0x82) == 0x82) {
        unsigned int path[2];
        unsigned char chain[32];
        unsigned char Sr[64];

        memset(chain, 0, 32);
        path[0] = 0x80475047;
        path[1] = 0x0F0F0F0F;
        CX_CHECK(os_derive_bip32_no_throw(CX_CURVE_SECP256K1, path, 2, Sr, chain));
        chain[0] = 'r';
        chain[1] = 'n';
        chain[2] = 'd';

        cx_sha256_init(&G_gpg_vstate.work.md.sha256);
        CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, Sr, 32, NULL, 0));
        CX_CHECK(
            cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256, 0, chain, 3, NULL, 0));
        CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256,
                                  CX_LAST,
                                  G_gpg_vstate.work.io_buffer,
                                  G_gpg_vstate.io_length,
                                  G_gpg_vstate.work.io_buffer,
                                  32));
        hlen = cx_hash_get_size((const cx_hash_t *) &G_gpg_vstate.work.md.sha256);

        CX_CHECK(cx_sha3_xof_init_no_throw(&G_gpg_vstate.work.md.sha3, 256, olen));
        CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha3,
                                  CX_LAST,
                                  G_gpg_vstate.work.io_buffer,
                                  hlen,
                                  G_gpg_vstate.work.io_buffer,
                                  olen));
    } else {
        cx_rng(G_gpg_vstate.work.io_buffer, olen);
        error = CX_OK;
    }

    if ((G_gpg_vstate.io_p1 & 0x81) == 0x81) {
        CX_CHECK(cx_math_next_prime_no_throw(G_gpg_vstate.work.io_buffer, olen));
    }

end:
    if (error != CX_OK) {
        THROW(error);
    }
    gpg_io_discard(0);
    gpg_io_inserted(olen);
    return SW_OK;
}
