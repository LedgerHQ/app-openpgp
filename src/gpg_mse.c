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

static int gpg_mse_set(int crt, int ref) {
  if (crt == 0xA4) {
    if (ref == 0x02) {
      G_gpg_vstate.mse_aut = &G_gpg_vstate.kslot->dec;
    }
    if (ref == 0x03) {
      G_gpg_vstate.mse_aut = &G_gpg_vstate.kslot->aut;
    }
  }

  if (crt == 0xB8) {
    if (ref == 0x02) {
      G_gpg_vstate.mse_dec = &G_gpg_vstate.kslot->dec;
    }
    if (ref == 0x03) {
      G_gpg_vstate.mse_dec = &G_gpg_vstate.kslot->aut;
    }
  }
  return 0;
}

int gpg_mse_reset() {
  gpg_mse_set(0xA4, 0x03);
  gpg_mse_set(0xB8, 0x02);
  return 0;
}

int gpg_apdu_mse() {
  int crt, ref;

  if ((G_gpg_vstate.io_p1 != 0x41) || ((G_gpg_vstate.io_p2 != 0xA4) && (G_gpg_vstate.io_p2 != 0xB8))) {
    THROW(SW_INCORRECT_P1P2);
    return SW_INCORRECT_P1P2;
  }

  crt = gpg_io_fetch_u16();
  if (crt != 0x8301) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  ref = gpg_io_fetch_u8();
  if ((ref != 0x02) && (ref != 0x03)) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  gpg_mse_set(crt, ref);
  gpg_io_discard(1);
  return SW_OK;
}