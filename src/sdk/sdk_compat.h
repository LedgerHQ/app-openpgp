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

#ifndef SDK_COMPAT_H
#define SDK_COMPAT_H

#include "bolos_target.h"

#if TARGET_ID == 0x31100004
//Use original naming of NanoS 1.5.5

#elif TARGET_ID == 0x33000004
#include "os_io_usb.h"
// from NanoX 1.2.4 remap G_io_apdu_xx
#define G_io_apdu_state       G_io_app.apdu_state
#define G_io_apdu_length      G_io_app.apdu_length
#define G_io_apdu_state       G_io_app.apdu_state


#else
//Unknown
#error Target Not Supported
#endif

#endif