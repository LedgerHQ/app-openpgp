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

#ifndef GPG_VARS_H
#define GPG_VARS_H

#include "os.h"
#include "cx.h"
#include "ux.h"
#include "os_io_seproxyhal.h"
#include "gpg_types.h"
#include "gpg_api.h"

extern const unsigned char C_ext_capabilities[10];
extern const unsigned char C_ext_length[8];
extern const unsigned char C_OID_SECP256K1[5];
extern const unsigned char C_OID_SECP256R1[8];
extern const unsigned char C_OID_BRAINPOOL256R1[9];
extern const unsigned char C_OID_BRAINPOOL256T1[9];
extern const unsigned char C_OID_Ed25519[9];
extern const unsigned char C_OID_cv25519[10];

extern gpg_v_state_t G_gpg_vstate;

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
extern const gpg_nv_state_t N_state_pic;
#define N_gpg_pstate ((volatile gpg_nv_state_t *)PIC(&N_state_pic))
#else
extern gpg_nv_state_t N_state_pic;
#define N_gpg_pstate ((WIDE gpg_nv_state_t *)PIC(&N_state_pic))
#endif

#ifdef GPG_DEBUG_MAIN
extern int apdu_n;
#endif

extern ux_state_t ux;

#ifdef HAVE_RSA
#include "cx_ram.h"
extern union cx_u G_cx;
#endif // HAVE_RSA
#endif
