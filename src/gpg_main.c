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
#include "io.h"
#include "usbd_ccid_if.h"

/* ----------------------------------------------------------------------- */
/* ---                            Application Entry                    --- */
/* ----------------------------------------------------------------------- */

void app_main(void) {
    unsigned int io_flags = 0;
    io_flags = 0;

    // start communication with MCU
    ui_CCID_reset();

    // set up
    io_init();

    gpg_init();

    // set up initial screen
    ui_init();

    // start the application
    // the first exchange will:
    // - display the  initial screen
    // - send the ATR
    // - receive the first command
    for (;;) {
        volatile unsigned short sw = 0;
        BEGIN_TRY {
            TRY {
                gpg_io_do(io_flags);
                sw = gpg_dispatch();
            }
            CATCH_OTHER(e) {
                gpg_io_discard(1);
                if ((e & 0xFFFF0000) || (((e & 0xF000) != 0x6000) && ((e & 0xF000) != 0x9000))) {
                    gpg_io_insert_u32(e);
                    sw = 0x6f42;
                } else {
                    sw = e;
                }
            }
            FINALLY {
                if (sw) {
                    gpg_io_insert_u16(sw);
                    io_flags = 0;
                } else {
                    io_flags = IO_ASYNCH_REPLY;
                }
            }
        }
        END_TRY;
    }
}
