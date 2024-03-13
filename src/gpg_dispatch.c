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

#include "gpg_vars.h"

static int gpg_check_access_ins() {
    int sw = SW_UNKNOWN;

    switch (G_gpg_vstate.io_ins) {
        case INS_EXIT:
            if (gpg_pin_is_verified(PIN_ID_PW2)) {
                sw = SW_OK;
            }
            break;

        case INS_RESET_RETRY_COUNTER:
            if (gpg_pin_is_verified(PIN_ID_PW3) || gpg_pin_is_verified(PIN_ID_RC)) {
                sw = SW_OK;
            }
            break;

        case INS_GEN_ASYM_KEYPAIR:
            if ((G_gpg_vstate.io_p1 == ((READ_ASYM_KEY >> 8) & 0xFF)) ||
                (gpg_pin_is_verified(PIN_ID_PW3))) {
                sw = SW_OK;
            }
            break;

        case INS_PSO:
            if ((G_gpg_vstate.io_p1p2 == PSO_CDS) && gpg_pin_is_verified(PIN_ID_PW1)) {
                // pso:sign
                if (N_gpg_pstate->PW_status[0] == 0) {
                    gpg_pin_set_verified(PIN_ID_PW1, 0);
                }
                sw = SW_OK;
                break;
            }
            if (((G_gpg_vstate.io_p1p2 == PSO_DEC) || (G_gpg_vstate.io_p1p2 == PSO_ENC)) &&
                gpg_pin_is_verified(PIN_ID_PW2)) {
                // pso:dec/enc
                sw = SW_OK;
            }
            break;

        case INS_INTERNAL_AUTHENTICATE:
            if (gpg_pin_is_verified(PIN_ID_PW2)) {
                sw = SW_OK;
            }
            break;

        case INS_TERMINATE_DF:
            if (gpg_pin_is_verified(PIN_ID_PW3)) {
                sw = SW_OK;
            }
            break;

#ifdef GPG_LOG
#warning GPG_LOG activated
        case INS_GET_LOG:
#endif
        case INS_SELECT:
        case INS_GET_DATA:
        case INS_GET_NEXT_DATA:
        case INS_VERIFY:
        case INS_CHANGE_REFERENCE_DATA:
        case INS_PUT_DATA:
        case INS_PUT_DATA_ODD:
        case INS_MSE:
        case INS_GET_CHALLENGE:
        case INS_ACTIVATE_FILE:
            sw = SW_OK;
            break;

        default:
            sw = SW_INS_NOT_SUPPORTED;
            break;
    }
    return sw;
}

static int gpg_check_access_read_DO() {
    int sw = SW_UNKNOWN;

    switch (G_gpg_vstate.io_p1p2) {
            // ALWAYS
        case 0x0101:
        case 0x0102:
        case 0x01F0:
        case 0x01F1:
        case 0x01F2:
        case 0x01F8:
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
            sw = SW_OK;
            break;

            // PW2
        case 0x0103:
            if (gpg_pin_is_verified(PIN_ID_PW2)) {
                sw = SW_OK;
            }
            break;

        // PW3
        case 0x00B6:
        case 0x00A4:
        case 0x00B8:
        case 0x0104:
            if (gpg_pin_is_verified(PIN_ID_PW3)) {
                sw = SW_OK;
            }
            break;
        default:
            sw = SW_CONDITIONS_NOT_SATISFIED;
            break;
    }
    return sw;
}

static int gpg_check_access_write_DO() {
    int sw = SW_UNKNOWN;

    switch (G_gpg_vstate.io_p1p2) {
        // PW2
        case 0x0101:
        case 0x0103:
        case 0x01F2:
            if (gpg_pin_is_verified(PIN_ID_PW2)) {
                sw = SW_OK;
            }
            break;

        // PW3
        case 0x3FFF:  // only used for putkey under PW3 control
        case 0x4f:
        case 0x0102:
        case 0x0104:
        case 0x01F1:
        case 0x01F8:
        case 0x005E:
        case 0x005B:
        case 0x5F2D:
        case 0x5F35:
        case 0x5F50:
        case 0x5F48:
        case 0x7F21:
        case 0x00B6:
        case 0x00A4:
        case 0x00B8:
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
        case 0x00CB:
        case 0x00CC:
        case 0x00CD:
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
            if (gpg_pin_is_verified(PIN_ID_PW3)) {
                sw = SW_OK;
            }
            break;
        default:
            sw = SW_CONDITIONS_NOT_SATISFIED;
            break;
    }
    return sw;
}

/* assume command is fully received */
int gpg_dispatch() {
    unsigned int tag, t, l;
    int sw = SW_UNKNOWN;

    if ((G_gpg_vstate.io_cla != CLA_APP_DEF) && (G_gpg_vstate.io_cla != CLA_APP_CHAIN) &&
        (G_gpg_vstate.io_cla != CLA_APP_APDU_PIN)) {
        return SW_CLA_NOT_SUPPORTED;
    }

    switch (G_gpg_vstate.io_ins) {
#ifdef GPG_LOG
        case INS_GET_LOG:
            gpg_io_discard(1);
            gpg_io_insert(G_gpg_vstate.log_buffer, 32);
            return SW_OK;
#endif

            /* --- SELECT --- */
        case INS_SELECT:
            return gpg_apdu_select();
            break;

            /* --- ACTIVATE/TERMINATE FILE --- */
        case INS_ACTIVATE_FILE:
            gpg_io_discard(0);
            if (N_gpg_pstate->histo[HISTO_OFFSET_STATE] == STATE_TERMINATE) {
                gpg_install(STATE_ACTIVATE);
            }
            return SW_OK;
            break;

        case INS_TERMINATE_DF:
            gpg_io_discard(0);
            if (gpg_pin_is_verified(PIN_ID_PW3) || (N_gpg_pstate->PW3.counter == 0)) {
                gpg_install(STATE_TERMINATE);
                return SW_OK;
                break;
            }
            return SW_CONDITIONS_NOT_SATISFIED;
            break;
    }

    /* Other commands allowed if not terminated */
    if (N_gpg_pstate->histo[HISTO_OFFSET_STATE] != STATE_ACTIVATE) {
        return SW_STATE_TERMINATED;
    }

    /* Process */
    sw = gpg_check_access_ins();
    if (sw != SW_OK) {
        return sw;
    }

    switch (G_gpg_vstate.io_ins) {
#ifdef GPG_DEBUG_APDU
        case 0x42:
            sw = debug_apdu();
            break;
#endif

        case INS_EXIT:
            os_sched_exit(0);
            sw = SW_OK;
            break;

            /* --- CHALLENGE --- */
        case INS_GET_CHALLENGE:
            sw = gpg_apdu_get_challenge();
            break;

            /* --- DATA --- */

        case INS_SELECT_DATA:
            if ((G_gpg_vstate.io_p1 > SELECT_MAX_INSTANCE) || (G_gpg_vstate.io_p2 != SELECT_SKIP)) {
                sw = SW_WRONG_P1P2;
                break;
            }
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x60) {
                sw = SW_WRONG_DATA;
                break;
            }
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x5C) {
                sw = SW_WRONG_DATA;
                break;
            }
            if (l == 1) {
                tag = gpg_io_fetch_u8();
            } else if (l == 2) {
                tag = gpg_io_fetch_u16();
            } else {
                sw = SW_WRONG_DATA;
                break;
            }
            gpg_apdu_select_data(tag, G_gpg_vstate.io_p1);
            sw = SW_OK;
            break;

        case INS_GET_DATA:
            sw = gpg_check_access_read_DO();
            if (sw != SW_OK) {
                break;
            }
            switch (G_gpg_vstate.io_p1p2) {
                case 0x00B6:
                case 0x00A4:
                case 0x00B8:
                    sw = gpg_apdu_get_key_data(G_gpg_vstate.io_p1p2);
                    break;
                default:
                    sw = gpg_apdu_get_data(G_gpg_vstate.io_p1p2);
                    break;
            }
            break;

        case INS_GET_NEXT_DATA:
            sw = gpg_check_access_read_DO();
            if (sw != SW_OK) {
                break;
            }
            sw = gpg_apdu_get_next_data(G_gpg_vstate.io_p1p2);
            break;

        case INS_PUT_DATA_ODD:
        case INS_PUT_DATA:
            sw = gpg_check_access_write_DO();
            if (sw != SW_OK) {
                break;
            }
            switch (G_gpg_vstate.io_p1p2) {
                case 0x00B6:
                case 0x00A4:
                case 0x00B8:
                    sw = gpg_apdu_put_key_data(G_gpg_vstate.io_p1p2);
                    break;
                default:
                    sw = gpg_apdu_put_data(G_gpg_vstate.io_p1p2);
                    break;
            }
            break;

            /* --- PIN -- */
        case INS_VERIFY:
            if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) || (G_gpg_vstate.io_p2 == PIN_ID_PW2) ||
                (G_gpg_vstate.io_p2 == PIN_ID_PW3)) {
                sw = gpg_apdu_verify();
                break;
            }
            sw = SW_WRONG_P1P2;
            break;

        case INS_CHANGE_REFERENCE_DATA:
            if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) || (G_gpg_vstate.io_p2 == PIN_ID_PW3)) {
                sw = gpg_apdu_change_ref_data();
                break;
            }
            sw = SW_WRONG_P1P2;
            break;

        case INS_RESET_RETRY_COUNTER:
            if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) &&
                ((G_gpg_vstate.io_p1 == RESET_RETRY_WITH_CODE) ||
                 (G_gpg_vstate.io_p1 == RESET_RETRY_WITH_PW3))) {
                sw = gpg_apdu_reset_retry_counter();
                break;
            }
            sw = SW_WRONG_P1P2;
            break;

            /* --- Key Management --- */
        case INS_GEN_ASYM_KEYPAIR:
            sw = gpg_apdu_gen();
            break;

            /* --- MSE --- */
        case INS_MSE:
            sw = gpg_apdu_mse();
            break;

            /* --- PSO --- */
        case INS_PSO:
            sw = gpg_apdu_pso();
            break;

        case INS_INTERNAL_AUTHENTICATE:
            sw = gpg_apdu_internal_authenticate();
            break;

        default:
            sw = SW_INS_NOT_SUPPORTED;
            break;
    }
    return sw;
}
