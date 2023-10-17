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

const unsigned char C_MF[] = {0x3F, 0x00};

int gpg_apdu_select() {
    int sw;

    // MF
    if ((G_gpg_vstate.io_length == 2) &&
        (memcmp(G_gpg_vstate.work.io_buffer, C_MF, G_gpg_vstate.io_length) == 0)) {
        gpg_io_discard(0);
        sw = SW_OK;
    }
    // AID APP
    else if ((G_gpg_vstate.io_length == 6) && (memcmp(G_gpg_vstate.work.io_buffer,
                                                      (const void *) N_gpg_pstate->AID,
                                                      G_gpg_vstate.io_length) == 0)) {
        G_gpg_vstate.DO_current = 0;
        G_gpg_vstate.DO_reccord = 0;
        G_gpg_vstate.DO_offset = 0;
        if (G_gpg_vstate.selected == 0) {
            G_gpg_vstate.verified_pin[0] = 0;
            G_gpg_vstate.verified_pin[1] = 0;
            G_gpg_vstate.verified_pin[2] = 0;
            G_gpg_vstate.verified_pin[3] = 0;
            G_gpg_vstate.verified_pin[4] = 0;
        }

        gpg_io_discard(0);
        if (N_gpg_pstate->histo[7] != STATE_ACTIVATE) {
            THROW(SW_STATE_TERMINATED);
        }
        sw = SW_OK;
    }
    // NOT FOUND
    else {
        THROW(SW_FILE_NOT_FOUND);
        return SW_FILE_NOT_FOUND;
    }
    return sw;
}
