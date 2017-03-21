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

int gpg_apdu_get_challenge() {

  if (G_gpg_vstate.io_le > GPG_EXT_CHALLENGE_LENTH) {
    THROW(SW_WRONG_LENGTH);
  }
  gpg_io_discard(1);
  cx_rng(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_le);
  cx_rng(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_le);
  cx_rng(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_le);
  cx_rng(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_le);
  cx_rng(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset, G_gpg_vstate.io_le);

  if (G_gpg_vstate.io_p1 & 0x80) {
    cx_math_next_prime(G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,G_gpg_vstate.io_le);
  }
  gpg_io_inserted(G_gpg_vstate.io_le);
  return SW_OK;
}
