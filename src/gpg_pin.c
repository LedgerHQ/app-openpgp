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

#include "gpg_ux_nanos.h"

gpg_pin_t *gpg_pin_get_pin(int pinref) {
  switch (pinref) {
  case PIN_ID_PW1 :
  case PIN_ID_PW2 :
    return &N_gpg_pstate->PW1;
  case PIN_ID_PW3:
    return &N_gpg_pstate->PW3;
  case PIN_ID_RC:
    return &N_gpg_pstate->RC;
  }
  return NULL;
}



static  int gpg_pin_get_state_index(unsigned int pinref) {
  switch (pinref) {
  case PIN_ID_PW1 :
    return 1;
  case PIN_ID_PW2 :
    return 2;
  case PIN_ID_PW3 :
     return 3;
  case PIN_ID_RC :
    return 4;
  
  }
  return -1;
}

static int gpg_pin_check_internal(gpg_pin_t *pin,  unsigned char *pin_val, int pin_len) {
  cx_sha256_t sha256;
  unsigned int counter;


  if (pin->counter == 0) {
    return SW_PIN_BLOCKED;
  }

  counter = pin->counter-1;
  gpg_nvm_write(&(pin->counter), &counter, sizeof(int));
  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t*)&sha256, CX_LAST, pin_val, pin_len, NULL);
  if (os_memcmp(sha256.acc, pin->value, 32)) {
    return SW_SECURITY_STATUS_NOT_SATISFIED;
  }

  counter = 3;
  gpg_nvm_write(&(pin->counter), &counter, sizeof(int));
  return SW_OK;
}

static void gpg_pin_check_throw(gpg_pin_t *pin, int pinID,
                                unsigned char *pin_val, int pin_len) {
  int sw;
  gpg_pin_set_verified(pinID,0);
  sw = gpg_pin_check_internal(pin,pin_val,pin_len);
  if (sw == SW_OK) {
    gpg_pin_set_verified(pinID,1);
    return;
  }
  THROW(sw);
}

int gpg_pin_check(gpg_pin_t *pin, int pinID,
                  unsigned char *pin_val, unsigned int pin_len) {
  int sw;
  gpg_pin_set_verified(pinID,0);
  sw = gpg_pin_check_internal(pin,pin_val,pin_len);
  if (sw == SW_OK) {
   gpg_pin_set_verified(pinID,1);
  }
  return sw;
}

void gpg_pin_set(gpg_pin_t *pin, unsigned char *pin_val, unsigned int pin_len) {
  cx_sha256_t sha256;

  gpg_pin_t newpin;

  cx_sha256_init(&sha256);
  cx_hash((cx_hash_t*)&sha256, CX_LAST, pin_val, pin_len, newpin.value);
  newpin.length = pin_len;
  newpin.counter = 3;

  gpg_nvm_write(pin, &newpin, sizeof(gpg_pin_t));
}

int gpg_pin_set_verified(int pinID, int verified) {
  int idx;
  idx = gpg_pin_get_state_index(pinID);
  if (idx >= 0) {
   G_gpg_vstate.verified_pin[idx]=verified;
   return verified;
 }
 return 0;
}

int gpg_pin_is_verified(int pinID) {
  int idx;
  idx = gpg_pin_get_state_index(pinID);
  if (idx >= 0) {
   return G_gpg_vstate.verified_pin[idx];
 }
 return 0;
}


int gpg_pin_is_blocked(gpg_pin_t *pin) {
 return  pin->counter == 0;
}


int gpg_apdu_verify() {
  gpg_pin_t *pin;

  pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
  if (pin == NULL) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }
  
  

   //PINPAD
  if (G_gpg_vstate.io_cla==0xFF) {
    if (gpg_pin_is_blocked(pin)) {
      THROW(SW_PIN_BLOCKED);
      return SW_PIN_BLOCKED;
    }

    if (G_gpg_vstate.pinmode == PIN_MODE_SCREEN) {
      //Delegate pin check to ui 
      gpg_io_discard(1);
      ui_menu_pinentry_display(0);
      return 0;
    }
    if (G_gpg_vstate.pinmode == PIN_MODE_CONFIRM) {
      //Delegate pin check to ui 
      gpg_io_discard(1);
      ui_menu_pinconfirm_display(0);
      return 0;
    }
    if (G_gpg_vstate.pinmode == PIN_MODE_TRUST) {
        gpg_pin_set_verified(G_gpg_vstate.io_p2,1);
        gpg_io_discard(1);
        return SW_OK;
    }
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  //NORMAL CHECK
  if ((G_gpg_vstate.io_p1==0) && G_gpg_vstate.io_length) {
    if (gpg_pin_is_blocked(pin)) {
      THROW(SW_PIN_BLOCKED);
      return SW_PIN_BLOCKED;
    }
    gpg_pin_check_throw(pin, G_gpg_vstate.io_p2, 
                        G_gpg_vstate.work.io_buffer+ G_gpg_vstate.io_offset,
                        G_gpg_vstate.io_length);
    gpg_io_discard(1);
    return SW_OK;
  }

  gpg_io_discard(1);

  //STATUS REQUEST
  if ((G_gpg_vstate.io_p1==0) && G_gpg_vstate.io_length==0) {  
    if (gpg_pin_is_verified(G_gpg_vstate.io_p2)) {
      return SW_OK;
    }
    return 0x63C0 | pin->counter;
  }

  //RESET REQUEST
  if ((G_gpg_vstate.io_p1==0xFF) && G_gpg_vstate.io_length==0) {  
    gpg_pin_set_verified(G_gpg_vstate.io_p2,0);
    return SW_OK;
  }

  THROW(SW_WRONG_DATA);
  return SW_WRONG_DATA;

}

int gpg_apdu_change_ref_data() {
  gpg_pin_t *pin;
  int len, newlen;
  
  pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
  if (pin == NULL) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }

  gpg_pin_set_verified(pin->ref,0);
  
  
  // --- RC pin ---
  if (pin->ref == PIN_ID_RC) {
    newlen = G_gpg_vstate.io_length;
    if (newlen == 0) {
      gpg_nvm_write(pin, NULL, sizeof(gpg_pin_t));

    }
    else if ((newlen > GPG_MAX_PW_LENGTH) ||
             (newlen < 8)) {
        THROW(SW_WRONG_DATA);
      return SW_WRONG_DATA;
    } else {
      gpg_pin_set(pin,
                      G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                      newlen);
    }
    gpg_io_discard(1);
    return SW_OK;
  }

  // --- PW1/PW3 pin ---
  if (gpg_pin_is_blocked(pin)) {
    THROW(SW_PIN_BLOCKED);
    return SW_PIN_BLOCKED;
  }
  //avoid any-overflow whitout giving info
  if (G_gpg_vstate.io_length == 0) {
    if (G_gpg_vstate.pinmode != PIN_MODE_HOST) {
      //Delegate pin change to ui 
      gpg_io_discard(1);
      ui_menu_pinentry_display(0);
      return 0;
    }   
  }

  if (pin->length > G_gpg_vstate.io_length) {
    len =  G_gpg_vstate.io_length;
  } else {
    len = pin->length;
  }

  gpg_pin_check_throw(pin, pin->ref,
                      G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                      len);

  newlen = G_gpg_vstate.io_length-len;
  if ( (newlen > GPG_MAX_PW_LENGTH)     ||
       ((pin->ref == PIN_ID_PW1) && (newlen < 6)) ||
       ((pin->ref == PIN_ID_PW3) && (newlen < 8)) ) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }
  gpg_pin_set(pin,
              G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset+len,
              newlen);
  gpg_io_discard(1);
  return SW_OK;
}

int gpg_apdu_reset_retry_counter() {
  gpg_pin_t *pin_pw1;
  gpg_pin_t *pin_pw3;
  gpg_pin_t *pin_rc;
  int rc_len, pw1_len;

  pin_pw1 = gpg_pin_get_pin(PIN_ID_PW1);
  pin_pw3 = gpg_pin_get_pin(PIN_ID_PW3);
  pin_rc = gpg_pin_get_pin(PIN_ID_RC);

  if (G_gpg_vstate.io_p1 == 2) {
    if (!gpg_pin_is_verified(PIN_ID_PW3)) {
      THROW(SW_SECURITY_STATUS_NOT_SATISFIED);
      return SW_SECURITY_STATUS_NOT_SATISFIED;
    }
    rc_len = 0;
    pw1_len = G_gpg_vstate.io_length;
  } else {
    
    //avoid any-overflow whitout giving info
    if (pin_rc->length > G_gpg_vstate.io_length) {
      rc_len =  G_gpg_vstate.io_length;
    } else {
      rc_len = pin_rc->length;
    }
    pw1_len = G_gpg_vstate.io_length-rc_len;
    gpg_pin_check_throw(pin_rc,pin_rc->ref,
                        G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset,
                        rc_len);
  }

  if ((pw1_len > GPG_MAX_PW_LENGTH) ||(pw1_len < 6)) {
    THROW(SW_WRONG_DATA);
    return SW_WRONG_DATA;
  }
  gpg_pin_set(pin_pw1,
              G_gpg_vstate.work.io_buffer+G_gpg_vstate.io_offset+rc_len,
              pw1_len);
  gpg_io_discard(1);
  return SW_OK;
}
