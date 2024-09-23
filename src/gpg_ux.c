
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
#include "usbd_ccid_if.h"

/**
 * Reset CCID
 *
 */
void ui_CCID_reset(void) {
    io_usb_ccid_set_card_inserted(0);
    io_usb_ccid_set_card_inserted(1);
}

/**
 * Exit app
 *
 */
void app_quit(void) {
    // exit app here
    os_sched_exit(0);
}

/**
 * Reset app
 *
 */
void app_reset(void) {
    unsigned char magic[MAGIC_LENGTH];

    explicit_bzero(magic, MAGIC_LENGTH);
    nvm_write((void*) (N_gpg_pstate->magic), magic, MAGIC_LENGTH);
    gpg_init();
    ui_CCID_reset();
}
