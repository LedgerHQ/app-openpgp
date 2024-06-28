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

#ifndef GPG_API_H
#define GPG_API_H

/* ----------------------------------------------------------------------- */
/* ---                              INIT                              ---- */
/* ----------------------------------------------------------------------- */

void gpg_activate_pinpad(uint8_t enabled);
unsigned int gpg_oid2curve(unsigned char *oid, unsigned int len);
unsigned char *gpg_curve2oid(unsigned int cv, unsigned int *len);
unsigned int gpg_curve2domainlen(unsigned int cv);

void gpg_init(void);
void gpg_install(unsigned char app_state);

/* ----------------------------------------------------------------------- */
/* ---                            DISPATCH                            ---- */
/* ----------------------------------------------------------------------- */

int gpg_dispatch(void);

/* ----------------------------------------------------------------------- */
/* ---                              DATA                              ---- */
/* ----------------------------------------------------------------------- */

void gpg_apdu_select_data(unsigned int ref, int record);
int gpg_apdu_get_data(unsigned int ref);
int gpg_apdu_get_next_data(unsigned int ref);
int gpg_apdu_put_data(unsigned int ref);
int gpg_apdu_get_key_data(unsigned int ref);
int gpg_apdu_put_key_data(unsigned int ref);

/* ----------------------------------------------------------------------- */
/* ---                              PSO                               ---- */
/* ----------------------------------------------------------------------- */

int gpg_pso_derive_slot_seed(int slot, unsigned char *seed);
int gpg_pso_derive_key_seed(unsigned char *Sn,
                            unsigned char *key_name,
                            unsigned int idx,
                            unsigned char *Ski,
                            unsigned int Ski_len);
int gpg_apdu_pso(void);
int gpg_apdu_internal_authenticate(void);

/* ----------------------------------------------------------------------- */
/* ---                              GEN                               ---- */
/* ----------------------------------------------------------------------- */

int gpg_apdu_gen(void);

/* ----------------------------------------------------------------------- */
/* ---                           CHALLENGE                            ---- */
/* ----------------------------------------------------------------------- */

int gpg_apdu_get_challenge(void);

/* ----------------------------------------------------------------------- */
/* ---                            SELECT                              ---- */
/* ----------------------------------------------------------------------- */

int gpg_apdu_select(void);

/* ----------------------------------------------------------------------- */
/* ---                              PIN                               ---- */
/* ----------------------------------------------------------------------- */

int gpg_apdu_verify(void);
int gpg_apdu_change_ref_data(void);
int gpg_apdu_reset_retry_counter(void);

gpg_pin_t *gpg_pin_get_pin(int id);
int gpg_pin_is_verified(int pinID);
void gpg_pin_set_verified(int pinID, int verified);
int gpg_pin_check(gpg_pin_t *pin, int pinID, const unsigned char *pin_val, unsigned int pin_len);
int gpg_pin_set(gpg_pin_t *pin, unsigned char *pin_val, unsigned int pin_len);

/* ----------------------------------------------------------------------- */
/* ---                              MSE                               ---- */
/* ----------------------------------------------------------------------- */

void gpg_mse_reset();
int gpg_apdu_mse();

/* ----------------------------------------------------------------------- */
/* ---                               IO                               ---- */
/* ----------------------------------------------------------------------- */
void gpg_io_discard(int clear);
void gpg_io_clear(void);
void gpg_io_set_offset(unsigned int offset);
void gpg_io_mark(void);
void gpg_io_rewind(void);
void gpg_io_inserted(unsigned int len);
void gpg_io_insert(unsigned char const *buffer, unsigned int len);
void gpg_io_insert_u32(unsigned int v32);
void gpg_io_insert_u24(unsigned int v24);
void gpg_io_insert_u16(unsigned int v16);
void gpg_io_insert_u8(unsigned int v8);
void gpg_io_insert_t(unsigned int T);
void gpg_io_insert_tl(unsigned int T, unsigned int L);
void gpg_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V);

void gpg_io_fetch_buffer(unsigned char *buffer, unsigned int len);
unsigned int gpg_io_fetch_u32(void);
unsigned int gpg_io_fetch_u24(void);
unsigned int gpg_io_fetch_u16(void);
unsigned int gpg_io_fetch_u8(void);
void gpg_io_fetch_t(unsigned int *T);
void gpg_io_fetch_l(unsigned int *L);
void gpg_io_fetch_tl(unsigned int *T, unsigned int *L);
void gpg_io_fetch_nv(unsigned char *buffer, int len);
int gpg_io_fetch(unsigned char *buffer, int len);

void gpg_io_do(unsigned int io_flags);

#endif
