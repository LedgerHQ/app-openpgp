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


static gpg_pin_t *gpg_get_pin(int id) {
  switch (id) {
  case ID_PW1 :
  case ID_PW2 :
    return &N_gpg_pstate->PW1;
  case ID_PW3:
    return &N_gpg_pstate->PW3;
  case ID_RC:
    return &N_gpg_pstate->RC;
  }
  return NULL;
}



static void gpg_set_verified(int id, int verified) {
  G_gpg_vstate.verified_pin[id] = verified;
}

static int gpg_check_pin(gpg_pin_t *pin, unsigned char *pin_val, int pin_len) {
  cx_sha256_t sha256;
  unsigned int counter;

  if (pin->counter == 0) {
    return -1;
  }

  counter = pin->counter-1;
  gpg_nvm_write(&(pin->counter), &counter, sizeof(int));

  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t*)&sha256, CX_LAST, pin_val, pin_len, NULL);
  if (os_memcmp(sha256.acc, pin->value, 32)) {
    return 0;
  }

  counter = 3;
  gpg_nvm_write(&(pin->counter), &counter, sizeof(int));
  return 1;
}

static void gpg_set_pin(gpg_pin_t *pin, unsigned char *pin_val, unsigned int pin_len) {
  cx_sha256_t sha256;

  gpg_pin_t newpin;

  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t*)&sha256, CX_LAST, pin_val, pin_len, newpin.value);
  newpin.length = pin_len;
  newpin.counter = 3;

  gpg_nvm_write(pin, &newpin, sizeof(gpg_pin_t));
}

/*
static void gpg_unblock_pin(int id) {
  gpg_pin_t *pin;
  int counter;
  pin = gpg_get_pin(id);
  counter = 3;
  gpg_nvm_write(&(pin->counter), &counter, sizeof(int));
}
*/


/*
 *
 */
int gpg_is_pin_verified(int id) {
 return G_gpg_vstate.verified_pin[id] != 0;
}

/*
 *
 */
int gpg_is_pin_blocked(int id) {
 gpg_pin_t *pin;
 pin = gpg_get_pin(id);
 return  pin->counter == 0;
}




/* @return: 1 verified
 *          0 not verified
 *          -1 blocked
 */
int gpg_apdu_verify(int id) {
  gpg_pin_t *pin;

  gpg_set_verified(id,0);
  pin = gpg_get_pin(id);
  if (gpg_check_pin(pin,
                    G_gpg_vstate.work.io_buffer+ G_gpg_vstate.io_offset,
                    G_gpg_vstate.io_lc)) {
    gpg_set_verified(id,1);
    gpg_io_discard(1);
    return SW_OK;
  }
  THROW(SW_SECURITY_STATUS_NOT_SATISFIED);
  return 0;
}

int gpg_apdu_change_ref_data(int id) {
  gpg_pin_t *pin;
  int len, newlen;

  gpg_set_verified(id,0);
  pin = gpg_get_pin(id);
  if (pin == NULL) {
    THROW(SW_WRONG_DATA);
  }

  // --- RC pin ---
  if (id == ID_RC) {
    newlen = G_gpg_vstate.io_lc;
    if (newlen == 0) {
      gpg_nvm_write(pin, NULL, sizeof(gpg_pin_t));

    }
    else if ((newlen > GPG_MAX_PW_LENGTH) ||
             (newlen < 8)) {
        THROW(SW_WRONG_DATA);
    } else {
      gpg_set_pin(pin,
                  G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                  newlen);
    }
    gpg_io_discard(1);
    return SW_OK;
  }

  // --- PW1/PW3 pin ---

  //avoid any-overflow whitout giving info
  if (pin->length > G_gpg_vstate.io_lc) {
    len =  G_gpg_vstate.io_lc;
  } else {
    len = pin->length;
  }

  if (gpg_check_pin(pin,
                    G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                    len)) {

    newlen = G_gpg_vstate.io_lc-len;
    if ( (newlen > GPG_MAX_PW_LENGTH)     ||
         ((id == ID_PW1) && (newlen < 6)) ||
         ((id == ID_PW3) && (newlen < 8)) ) {
      THROW(SW_WRONG_DATA);
    }
    gpg_set_pin(pin,
                G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset+len,
                newlen);
    gpg_io_discard(1);
    return SW_OK;
  }
  THROW(SW_SECURITY_STATUS_NOT_SATISFIED);
  return 0.;
}

int gpg_apdu_reset_retry_counter() {
  gpg_pin_t *pin_pw1;
  gpg_pin_t *pin_rc;
  int rc_len, pw1_len;

  pin_pw1 = gpg_get_pin(ID_PW1);

  if (G_gpg_vstate.io_p1 == 2) {
    if (!G_gpg_vstate.verified_pin[ID_PW3]) {
      THROW(SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    rc_len = 0;
    pw1_len = G_gpg_vstate.io_lc;
  } else {
    pin_rc = gpg_get_pin(ID_RC);
    //avoid any-overflow whitout giving info
    if (pin_rc->length > G_gpg_vstate.io_lc) {
      rc_len =  G_gpg_vstate.io_lc;
    } else {
      rc_len = pin_rc->length;
    }
    pw1_len = G_gpg_vstate.io_lc-rc_len;
    if (!gpg_check_pin(pin_rc,
                       G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                       rc_len)) {
      THROW(SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  if ((pw1_len > GPG_MAX_PW_LENGTH) ||(pw1_len < 6)) {
    THROW(SW_WRONG_DATA);
  }
  gpg_set_pin(pin_pw1,
              G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset+rc_len,
              pw1_len);
  gpg_io_discard(1);
  return SW_OK;

}
