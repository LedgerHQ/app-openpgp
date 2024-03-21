/*****************************************************************************
 *   Ledger App OpenPGP.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "gpg_vars.h"
#include "cx_errors.h"

/**
 * Generate a Random Number
 *
 * @return Status Word
 *
 */
int gpg_apdu_get_challenge() {
    unsigned int olen;
    cx_err_t error = CX_INTERNAL_ERROR;
    unsigned char Sr[64];

    switch (G_gpg_vstate.io_p1) {
        case CHALLENGE_NOMINAL:
        case PRIME_MODE:
            olen = G_gpg_vstate.io_le;
            break;
        case SEEDED_MODE:
            olen = G_gpg_vstate.io_p2;
            break;
        default:
            return SW_WRONG_P1P2;
    }
    if (olen == 0 || olen > GPG_EXT_CHALLENGE_LENTH) {
        return SW_WRONG_LENGTH;
    }

    if (G_gpg_vstate.io_p1 == SEEDED_MODE) {
        // Ledger Add-on: Seeded random
        unsigned int path[2];
        unsigned char chain[32] = {0};

        explicit_bzero(chain, 32);
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
        CX_CHECK(cx_sha3_xof_init_no_throw(&G_gpg_vstate.work.md.sha3, 256, olen));
        CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha3,
                                  CX_LAST,
                                  G_gpg_vstate.work.io_buffer,
                                  32,
                                  G_gpg_vstate.work.io_buffer,
                                  olen));
    } else {
        cx_rng(G_gpg_vstate.work.io_buffer, olen);
        error = CX_OK;
    }

    if (G_gpg_vstate.io_p1 == PRIME_MODE) {
        // Ledger Add-on: Prime random
        CX_CHECK(cx_math_next_prime_no_throw(G_gpg_vstate.work.io_buffer, olen));
    }

end:
    explicit_bzero(&Sr, sizeof(Sr));
    if (error != CX_OK) {
        return error;
    }
    gpg_io_discard(0);
    gpg_io_inserted(olen);
    return SW_OK;
}
