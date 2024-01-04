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
#include "gpg_ux.h"
#include "io.h"
#include "usbd_ccid_if.h"

/* ----------------------------------------------------------------------- */
/* ---                            Application Entry                    --- */
/* ----------------------------------------------------------------------- */

void app_main(void) {
    unsigned int io_flags = 0;
    io_flags = 0;
    volatile unsigned short sw = SW_UNKNOWN;

    // start communication with MCU
    ui_CCID_reset();

    // set up
    io_init();

    gpg_init();

    // set up initial screen
    ui_init();

    // start the application
    // the first exchange will:
    // - display the initial screen
    // - send the ATR
    // - receive the first command
    for (;;) {
        gpg_io_do(io_flags);
        sw = gpg_dispatch();
        if (sw) {
            PRINTF("[MAIN] - FINALLY INSERT sw=0x%x\n", sw);
            gpg_io_insert_u16(sw);
            io_flags = 0;
        } else {
            io_flags = IO_ASYNCH_REPLY;
        }
    }
}
