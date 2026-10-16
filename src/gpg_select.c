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

/**
 * APDU handler to Select the card
 *
 * @return Status Word
 *
 */
int gpg_apdu_select() {
    int sw = SWO_UNKNOWN;

    // MF
    if ((G_gpg_vstate.io_length == sizeof(C_MF)) &&
        (memcmp(G_gpg_vstate.work.io_buffer, C_MF, G_gpg_vstate.io_length) == 0)) {
        gpg_io_discard(0);
        sw = SWO_SUCCESS;
    }
    // EF.ATR
    else if ((G_gpg_vstate.io_length == sizeof(C_ATR)) &&
             (memcmp(G_gpg_vstate.work.io_buffer, C_ATR, G_gpg_vstate.io_length) == 0)) {
        gpg_io_discard(0);
        sw = SWO_SUCCESS;
    }
    // AID APP
    else if ((G_gpg_vstate.io_length == 6) && (memcmp(G_gpg_vstate.work.io_buffer,
                                                      (const void *) N_gpg_pstate->AID,
                                                      G_gpg_vstate.io_length) == 0)) {
        G_gpg_vstate.DO_current = 0;
        G_gpg_vstate.DO_reccord = 0;
        G_gpg_vstate.DO_offset = 0;
        // PINs stay verified until the card is reset: only the first selection opens a session
        if (G_gpg_vstate.selected == 0) {
            explicit_bzero(G_gpg_vstate.verified_pin, sizeof(G_gpg_vstate.verified_pin));
            G_gpg_vstate.selected = 1;
        }
        // the default keys are restored on every selection
        gpg_mse_reset();

        gpg_io_discard(0);
        if (N_gpg_pstate->histo[HISTO_OFFSET_STATE] != STATE_ACTIVATE) {
            sw = SWO_NO_INPUT_DATA_AVAILABLE;
        } else {
            sw = SWO_SUCCESS;
        }
    }
    // NOT FOUND
    else {
        sw = SWO_FILE_NOT_FOUND;
    }
    return sw;
}
