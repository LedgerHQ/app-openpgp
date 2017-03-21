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


#include "os.h"
#include "cx.h"
#include "gpg_types.h"
#include "gpg_api.h"
#include "gpg_vars.h"

int gpg_apdu_select() {
  int sw;
  if ( (G_gpg_vstate.io_length = 6) &&
       (os_memcmp(G_gpg_vstate.work.io_buffer, N_gpg_pstate->AID, G_gpg_vstate.io_length) == 0) ) {
    G_gpg_vstate.DO_current = 0;
    G_gpg_vstate.DO_reccord = 0;
    G_gpg_vstate.DO_offset  = 0;
    if ( G_gpg_vstate.selected == 0) {
      G_gpg_vstate.verified_pin[ID_PW1] = 0;
      G_gpg_vstate.verified_pin[ID_PW2] = 0;
      G_gpg_vstate.verified_pin[ID_PW3] = 0;
      G_gpg_vstate.verified_pin[ID_RC]  = 0;
    }
    gpg_io_discard(0);
    sw = SW_OK;
  } else {
    THROW(SW_FILE_NOT_FOUND);
  }
  return sw;
}
