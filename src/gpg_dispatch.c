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


int gpg_is_verified(id) {
  return G_gpg_vstate.verified_pin[id] ;
}

void gpg_check_access_ins() {
  switch (G_gpg_vstate.io_ins) {
  case INS_SELECT:
    return;
  case INS_GET_DATA:
  case INS_GET_NEXT_DATA:
    return;

  case INS_VERIFY:
    return;

  case INS_CHANGE_REFERENCE_DATA:
  if (gpg_is_verified(ID_PW1) || gpg_is_verified(ID_RC)) {
      return;
    }
    break;

  case INS_RESET_RETRY_COUNTER:
    if (gpg_is_verified(ID_PW3) || gpg_is_verified(ID_RC)) {
      return;
    }

  case INS_PUT_DATA:
  case INS_PUT_DATA_ODD:
    return;

  case INS_GEN_ASYM_KEYPAIR:
    if (G_gpg_vstate.io_p1 == 0x81) {
      return;
    }
    if (gpg_is_verified(ID_PW3)) {
      return;
    } 
    break;
    
  case INS_PSO:
    if (gpg_is_verified(ID_PW1) || gpg_is_verified(ID_PW2)) {
      return;
    }
    break;

  case INS_INTERNAL_AUTHENTICATE:
    if (gpg_is_verified(ID_PW2)) {
      return;
    }
    break;  

  case INS_GET_CHALLENGE:
    return;

  case INS_TERMINATE_DF:
    if (gpg_is_pin_verified(ID_PW3) || gpg_is_pin_blocked(ID_PW3)) {
      return;
    }
    break;

  case INS_ACTIVATE_FILE:
    return;
  }
  THROW(SW_CONDITIONS_NOT_SATISFIED);
}

void gpg_check_access_read_DO() {
  unsigned int ref;
  ref = (G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2 ;

  switch(ref) {
    //ALWAYS
  case 0x0101:
  case 0x0102:
  case 0x006E:
  case 0x0065:
  case 0x0073:
  case 0x007A:
  case 0x004F:
  case 0x005E:
  case 0x005B:
  case 0x5F2D:
  case 0x5F35:
  case 0x5F50:
  case 0x5F52:
  case 0x7F21:
  case 0x0093:
  case 0x00C0:
  case 0x00C1:
  case 0x00C2:
  case 0x00C3:
  case 0x00C4:
  case 0x00C5:
  case 0x00C7:
  case 0x00C8:
  case 0x00C9:
  case 0x00C6:
  case 0x00CA:
  case 0x00CD:
  case 0x00CC:
  case 0x00CE:
  case 0x00CF:
  case 0x00D0:
  case 0x7F74:
  case 0x7F66:
  case 0x00D6:
  case 0x00D7:
  case 0x00D8:
    return;

    //PW1
  case 0x0103:
    if (gpg_is_verified(ID_PW1)) {
      return;
    }
    break;

  //PW3
  case 0x0104:
     if (gpg_is_verified(ID_PW3)) {
      return;
    }
    break;
  } 

  THROW(SW_CONDITIONS_NOT_SATISFIED);
}

void gpg_check_access_write_DO() {
  unsigned int ref;
  ref = (G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2 ;


  switch(ref) {
  //PW1
  case 0x0101:
  case 0x0103:  
  case 0x01F2:
    if (gpg_is_verified(ID_PW1)) {
      return;
    }
    break;
  
  //PW3
  case 0x3FFF: //only used for putkey under PW3 control
  case 0x4f:
  case 0x0102:
  case 0x0104:
  case 0x01F1:
  case 0x005E:
  case 0x005B:
  case 0x5F2D:
  case 0x5F35:
  case 0x5F50:
  case 0x5F48:
  case 0x7F21:
  case 0x00C1:
  case 0x00C2:
  case 0x00C3:
  case 0x00C4:
  case 0x00C5:
  case 0x00C7:
  case 0x00C8:
  case 0x00C9:
  case 0x00C6:
  case 0x00CA:
  case 0x00CD:
  case 0x00CC:
  case 0x00CE:
  case 0x00CF:
  case 0x00D0:
  case 0x00D1:
  case 0x00D2:
  case 0x00D3:
  case 0x00D5:
  case 0x00F4:
  case 0x00D6:
  case 0x00D7:
  case 0x00D8:
    if (gpg_is_verified(ID_PW3)) {
      return;
    }
   break;

  } 

  THROW(SW_CONDITIONS_NOT_SATISFIED);
}



/* assume command is fully received */
int gpg_dispatch() {
  unsigned int tag,t,l;
  int sw;



  tag = (G_gpg_vstate.io_p1 << 8) | G_gpg_vstate.io_p2 ;

  switch (G_gpg_vstate.io_ins) {
    /* --- SELECT --- */
  case INS_SELECT:
    sw = gpg_apdu_select();
    return sw;
    break;


    /* --- ACTIVATE/TERMINATE FILE --- */
  case INS_ACTIVATE_FILE:
    gpg_io_discard(0);
    if (N_gpg_pstate->histo[7] == STATE_TERMINATE) {
      gpg_install(STATE_ACTIVATE);
    }
    return(SW_OK);
    break;

  case INS_TERMINATE_DF:
    gpg_io_discard(0);
    if (G_gpg_vstate.verified_pin[ID_PW3] || (N_gpg_pstate->PW3.counter == 0)) {
      gpg_install(STATE_TERMINATE);
      return(SW_OK);
      break;
    }
    THROW(SW_CONDITIONS_NOT_SATISFIED);
  }



  /* Other commands allowed if not terminated */
  if (N_gpg_pstate->histo[7] != 0x07) {
    THROW(SW_STATE_TERMINATED);
  }

  /* Process */
  gpg_check_access_ins();

  switch (G_gpg_vstate.io_ins) {


#ifdef GPG_DEBUG_APDU
  case 0x42:
    sw = debug_apdu();
    break;
#endif
    /* --- CHALLENGE --- */
  case INS_GET_CHALLENGE:
    sw = gpg_apdu_get_challenge();
    break;

    /* --- DATA --- */

  case INS_SELECT_DATA:
    if ((G_gpg_vstate.io_p1 > 2) || (G_gpg_vstate.io_p2 != 0x04)) {
      THROW(SW_WRONG_P1P2);
    }
    gpg_io_fetch_tl(&t,&l);
    if (t != 0x60) {
      //TODO add l check
      THROW(SW_DATA_INVALID);
    }
    gpg_io_fetch_tl(&t,&l);
    if (t != 0x5C) {
      //TODO add l check
      THROW(SW_WRONG_DATA);
    }
    if (l == 1) {
      tag = gpg_io_fetch_u8();
    } else  if (l == 2) {
      tag = gpg_io_fetch_u16();
    } else {
      THROW(SW_WRONG_DATA);
    }
    sw = gpg_apdu_select_data(tag, G_gpg_vstate.io_p1);
    break;

  case INS_GET_DATA:
    gpg_check_access_read_DO();

    sw = gpg_apdu_get_data(tag);
    break;

  case INS_GET_NEXT_DATA:
    gpg_check_access_read_DO();
    sw = gpg_apdu_get_next_data(tag);
    break;


    case INS_PUT_DATA_ODD:
    case INS_PUT_DATA:
    gpg_check_access_write_DO();
    sw = gpg_apdu_put_data(tag);
    break;

    /* --- PIN -- */
  case INS_VERIFY:
    if ((G_gpg_vstate.io_p2 == 0x81) ||
        (G_gpg_vstate.io_p2 == 0x82) ||
        (G_gpg_vstate.io_p2 == 0x83)
        ) {
      sw = gpg_apdu_verify(G_gpg_vstate.io_p2&0x0F);
      break;
    }
    THROW(SW_INCORRECT_P1P2);

  case INS_CHANGE_REFERENCE_DATA:
      if ((G_gpg_vstate.io_p2 == 0x81) ||
          (G_gpg_vstate.io_p2 == 0x83)
          ) {
        sw = gpg_apdu_change_ref_data(G_gpg_vstate.io_p2&0x0F);
        break;
      }
      THROW(SW_INCORRECT_P1P2);

  case INS_RESET_RETRY_COUNTER:
  if ((G_gpg_vstate.io_p2 == 0x81) &&
      ( (G_gpg_vstate.io_p1 == 0) ||
        (G_gpg_vstate.io_p1 == 2) )
     ) {
       sw = gpg_apdu_reset_retry_counter();
       break;
     }
     THROW(SW_INCORRECT_P1P2);

     /* --- Key Management --- */
  case INS_GEN_ASYM_KEYPAIR:
     sw = gpg_apdu_gen();
     break;

     /* --- PSO --- */
  case INS_PSO:
     sw = gpg_apdu_pso(tag);
     break;
  case INS_INTERNAL_AUTHENTICATE:
     sw = gpg_apdu_internal_authenticate();
     break;

  default:
    THROW( SW_INS_NOT_SUPPORTED);
    break;
  }

  return sw;
}
