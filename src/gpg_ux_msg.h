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

#ifndef GPG_UX_MSG_H
#define GPG_UX_MSG_H

extern const char *const C_TEMPLATE_TYPE;
extern const char *const C_TEMPLATE_KEY;
extern const char *const C_INVALID_SELECTION;

extern const char *const C_OK;
extern const char *const C_NOK;

extern const char *const C_WRONG_PIN;
extern const char *const C_RIGHT_PIN;
extern const char *const C_PIN_CHANGED;
extern const char *const C_PIN_DIFFERS;
extern const char *const C_PIN_USER;
extern const char *const C_PIN_ADMIN;

extern const char *const C_VERIFIED;
extern const char *const C_NOT_VERIFIED;
extern const char *const C_NOT_ALLOWED;

extern const char *const C_DEFAULT_MODE;

extern const char *const C_UIF_LOCKED;
extern const char *const C_UIF_INVALID;

#define PICSTR(x) ((char *)PIC(x))

#define TEMPLATE_TYPE PICSTR(C_TEMPLATE_TYPE)
#define TEMPLATE_KEY PICSTR(C_TEMPLATE_KEY)
#define INVALID_SELECTION PICSTR(C_INVALID_SELECTION)
#define OK PICSTR(C_OK)
#define NOK PICSTR(C_NOK)
#define WRONG_PIN PICSTR(C_WRONG_PIN)
#define RIGHT_PIN PICSTR(C_RIGHT_PIN)
#define PIN_CHANGED PICSTR(C_PIN_CHANGED)
#define PIN_DIFFERS PICSTR(C_PIN_DIFFERS)
#define PIN_USER PICSTR(C_PIN_USER)
#define PIN_ADMIN PICSTR(C_PIN_ADMIN)
#define VERIFIED PICSTR(C_VERIFIED)
#define NOT_VERIFIED PICSTR(C_NOT_VERIFIED)
#define ALLOWED PICSTR(C_ALLOWED)
#define NOT_ALLOWED PICSTR(C_NOT_ALLOWED)
#define DEFAULT_MODE PICSTR(C_DEFAULT_MODE)
#define UIF_LOCKED PICSTR(C_UIF_LOCKED)
#define UIF_INVALID PICSTR(C_UIF_INVALID)

#endif
