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

const unsigned char C_MF[] = {0x3F, 0x00};
const unsigned char C_ATR[] = {0x2F, 0x02};

int gpg_apdu_select() {
    int sw = SW_UNKNOWN;

    // MF
    if ((G_gpg_vstate.io_length == sizeof(C_MF)) &&
        (memcmp(G_gpg_vstate.work.io_buffer, C_MF, G_gpg_vstate.io_length) == 0)) {
        gpg_io_discard(0);
        sw = SW_OK;
    }
    // EF.ATR
    else if ((G_gpg_vstate.io_length == sizeof(C_ATR)) &&
             (memcmp(G_gpg_vstate.work.io_buffer, C_ATR, G_gpg_vstate.io_length) == 0)) {
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
        if (N_gpg_pstate->histo[HISTO_OFFSET_STATE] != STATE_ACTIVATE) {
            sw = SW_STATE_TERMINATED;
        } else {
            sw = SW_OK;
        }
    }
    // NOT FOUND
    else {
        sw = SW_FILE_NOT_FOUND;
    }
    return sw;
}
