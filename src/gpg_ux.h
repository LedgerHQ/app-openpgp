
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

#ifndef GPG_UX_H
#define GPG_UX_H

#define STR(x)  #x
#define XSTR(x) STR(x)

#define LABEL_SIG "Signature"
#define LABEL_AUT "Authentication"
#define LABEL_DEC "Decryption"

#define LABEL_RSA2048   "RSA 2048"
#define LABEL_RSA3072   "RSA 3072"
#define LABEL_RSA4096   "RSA 4096"
#define LABEL_NISTP256  "NIST P256"
#define LABEL_SECP256K1 "SECP 256K1"
#define LABEL_Ed25519   "Ed25519"

void ui_CCID_reset(void);
void ui_init(void);
void ui_menu_pinconfirm_display(unsigned int value);
void ui_menu_pinentry_display(unsigned int value);
void ui_menu_uifconfirm_display(unsigned int value);

#endif  // GPG_UX_H
