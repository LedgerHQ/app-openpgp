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
#include "os_io_seproxyhal.h"

#ifdef TARGET_NANOX
#include "ux.h"
ux_state_t        G_ux;
bolos_ux_params_t G_ux_params;
#else
ux_state_t           ux;
#endif

#ifndef GPG_DEBUG_MAIN
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
#else
extern unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
int                  apdu_n;
#endif

gpg_v_state_t G_gpg_vstate;

#ifdef HAVE_RSA
union cx_u G_cx;
#endif // HAVE_RSA