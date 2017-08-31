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

#ifndef GPG_API_H
#define  GPG_API_H

int  gpg_oid2curve(unsigned char* oid, unsigned int len);

void gpg_init(void);
void gpg_init_ux(void);
int  gpg_install(unsigned char app_state) ;
int  gpg_dispatch(void);

int  gpg_apdu_select_data(unsigned int ref, int reccord) ;
int  gpg_apdu_get_data(unsigned int ref)  ;
int  gpg_apdu_get_next_data(unsigned int ref)  ;
int  gpg_apdu_put_data(unsigned int ref) ;

int  gpg_apdu_pso(unsigned int ref);
int  gpg_apdu_internal_authenticate(void);
int  gpg_apdu_gen(void );
int  gpg_apdu_get_challenge(void) ;

int  gpg_apdu_select(void) ;

int  gpg_apdu_verify(void) ;
int  gpg_apdu_change_ref_data(void) ;
int  gpg_apdu_reset_retry_counter(void) ;

gpg_pin_t *gpg_pin_get_pin(int id);
int  gpg_pin_is_blocked(gpg_pin_t *pin);
int  gpg_pin_is_verified(int pinID);
int  gpg_pin_set_verified(int pinID, int verified);
int  gpg_pin_check(gpg_pin_t *pin, int pinID,unsigned char *pin_val, unsigned int pin_len);
void gpg_pin_set(gpg_pin_t *pin, unsigned char *pin_val, unsigned int pin_len);

int gpg_mse_reset(); 
int gpg_apdu_mse();

/* ----------------------------------------------------------------------- */
/* ---                                  IO                            ---- */
/* ----------------------------------------------------------------------- */
void gpg_io_discard(int clear) ;
void gpg_io_clear(void);
void gpg_io_set_offset(unsigned int offset) ;
void gpg_io_mark(void) ;
void gpg_io_rewind(void) ;
void gpg_io_hole(unsigned int sz) ;
void gpg_io_inserted(unsigned int len);
void gpg_io_insert(unsigned char const * buffer, unsigned int len) ;
void gpg_io_insert_u32(unsigned  int v32) ;
void gpg_io_insert_u24(unsigned  int v24) ;
void gpg_io_insert_u16(unsigned  int v16) ;
void gpg_io_insert_u8(unsigned int v8) ;
void gpg_io_insert_t(unsigned int T) ;
void gpg_io_insert_tl(unsigned int T, unsigned int L) ;
void gpg_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) ;

void gpg_io_fetch_buffer(unsigned char  * buffer, unsigned int len) ;
unsigned int gpg_io_fetch_u32(void) ;
unsigned int gpg_io_fetch_u24(void) ;
unsigned int gpg_io_fetch_u16(void) ;
unsigned int gpg_io_fetch_u8(void) ;
int gpg_io_fetch_t(unsigned int *T) ;
int gpg_io_fetch_l(unsigned int *L) ;
int gpg_io_fetch_tl(unsigned int *T, unsigned int *L) ;
int gpg_io_fetch_nv(unsigned char* buffer, int len) ;
int gpg_io_fetch(unsigned char* buffer, int len) ;

int gpg_io_do(unsigned int io_flags) ;

/* ----------------------------------------------------------------------- */
/* ---                                 TMP                           ---- */
/* ----------------------------------------------------------------------- */
void io_usb_ccid_set_card_inserted(unsigned int inserted);

/* ----------------------------------------------------------------------- */
/* ---                                DEBUG                           ---- */
/* ----------------------------------------------------------------------- */
#ifdef GPG_DEBUG

#include "gpg_debug.h"

#else

#define gpg_nvm_write   nvm_write
#define gpg_io_exchange io_exchange

#endif

#endif
