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
#include "gpg_ux.h"

gpg_pin_t *gpg_pin_get_pin(int pinref) {
    switch (pinref) {
        case PIN_ID_PW1:
        case PIN_ID_PW2:
            return (gpg_pin_t *) &N_gpg_pstate->PW1;
        case PIN_ID_PW3:
            return (gpg_pin_t *) &N_gpg_pstate->PW3;
        case PIN_ID_RC:
            return (gpg_pin_t *) &N_gpg_pstate->RC;
    }
    return NULL;
}

static int gpg_pin_get_state_index(unsigned int pinref) {
    switch (pinref) {
        case PIN_ID_PW1:
            return 1;
        case PIN_ID_PW2:
            return 2;
        case PIN_ID_PW3:
            return 3;
        case PIN_ID_RC:
            return 4;
    }
    return -1;
}

static int gpg_pin_check_internal(gpg_pin_t *pin, const unsigned char *pin_val, int pin_len) {
    unsigned int counter;
    cx_err_t error = CX_INTERNAL_ERROR;

    if (pin->counter == 0) {
        return SW_PIN_BLOCKED;
    }

    counter = pin->counter - 1;
    cx_sha256_init(&G_gpg_vstate.work.md.sha256);
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &G_gpg_vstate.work.md.sha256,
                              CX_LAST,
                              pin_val,
                              pin_len,
                              G_gpg_vstate.work.md.H,
                              sizeof(G_gpg_vstate.work.md.H)));
    if (memcmp(G_gpg_vstate.work.md.H, pin->value, 32)) {
        error = (counter == 0) ? SW_PIN_BLOCKED : SW_SECURITY_STATUS_NOT_SATISFIED;
    } else {
        counter = 3;
        error = SW_OK;
    }

end:
    if (counter != pin->counter) {
        nvm_write(&(pin->counter), &counter, sizeof(int));
    }
    return error;
}

int gpg_pin_check(gpg_pin_t *pin, int pinID, const unsigned char *pin_val, unsigned int pin_len) {
    int sw = SW_UNKNOWN;
    gpg_pin_set_verified(pinID, 0);
    sw = gpg_pin_check_internal(pin, pin_val, pin_len);
    if (sw == SW_OK) {
        gpg_pin_set_verified(pinID, 1);
    }
    return sw;
}

int gpg_pin_set(gpg_pin_t *pin, unsigned char *pin_val, unsigned int pin_len) {
    cx_sha256_t sha256;
    cx_err_t error = CX_INTERNAL_ERROR;
    gpg_pin_t newpin;

    cx_sha256_init(&sha256);
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &sha256, CX_LAST, pin_val, pin_len, newpin.value, 32));
    newpin.length = pin_len;
    newpin.counter = 3;

    nvm_write(pin, &newpin, sizeof(gpg_pin_t));
end:
    if (error != CX_OK) {
        return error;
    }
    return SW_OK;
}

void gpg_pin_set_verified(int pinID, int verified) {
    int idx;
    idx = gpg_pin_get_state_index(pinID);
    if (idx >= 0) {
        G_gpg_vstate.verified_pin[idx] = verified;
    }
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
    return pin->counter == 0;
}

int gpg_apdu_verify() {
    int sw = SW_UNKNOWN;
    gpg_pin_t *pin;

    pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
    if (pin == NULL) {
        return SW_WRONG_DATA;
    }

    // PINPAD
    if (G_gpg_vstate.io_cla == CLA_APP_APDU_PIN) {
        if (gpg_pin_is_blocked(pin)) {
            return SW_PIN_BLOCKED;
        }

        switch (G_gpg_vstate.pinmode) {
            case PIN_MODE_SCREEN:
                // Delegate pin check to ui
                gpg_io_discard(1);
                ui_menu_pinentry_display(0);
                sw = 0;
                break;
            case PIN_MODE_CONFIRM:
                // Delegate pin check to ui
                gpg_io_discard(1);
                ui_menu_pinconfirm_display(G_gpg_vstate.io_p2);
                sw = 0;
                break;
            case PIN_MODE_TRUST:
                gpg_pin_set_verified(G_gpg_vstate.io_p2, 1);
                gpg_io_discard(1);
                sw = 0;
                break;
            default:
                sw = SW_WRONG_DATA;
                break;
        }
        return sw;
    }

    // NORMAL CHECK
    if ((G_gpg_vstate.io_p1 == PIN_VERIFY) && G_gpg_vstate.io_length) {
        if (gpg_pin_is_blocked(pin)) {
            return SW_PIN_BLOCKED;
        }
        sw = gpg_pin_check(pin,
                           G_gpg_vstate.io_p2,
                           G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                           G_gpg_vstate.io_length);
        gpg_io_discard(1);
        return sw;
    }

    gpg_io_discard(1);

    // STATUS REQUEST
    if ((G_gpg_vstate.io_p1 == PIN_VERIFY) && G_gpg_vstate.io_length == 0) {
        if (gpg_pin_is_verified(G_gpg_vstate.io_p2)) {
            return SW_OK;
        }
        return SW_PWD_NOT_CHECKED | pin->counter;
    }

    // RESET REQUEST
    if ((G_gpg_vstate.io_p1 == PIN_NOT_VERIFIED) && G_gpg_vstate.io_length == 0) {
        gpg_pin_set_verified(G_gpg_vstate.io_p2, 0);
        return SW_OK;
    }

    return SW_WRONG_DATA;
}

int gpg_apdu_change_ref_data() {
    int sw = SW_UNKNOWN;
    gpg_pin_t *pin;
    int len, newlen;

    pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
    if (pin == NULL) {
        return SW_WRONG_DATA;
    }

    gpg_pin_set_verified(pin->ref, 0);

    // --- PW1/PW3 pin ---
    if (gpg_pin_is_blocked(pin)) {
        return SW_PIN_BLOCKED;
    }
    // avoid any-overflow without giving info
    if (G_gpg_vstate.io_length == 0) {
        // Delegate pin change to ui
        gpg_io_discard(1);
        ui_menu_pinentry_display(0);
        return 0;
    }

    len = MIN(G_gpg_vstate.io_length, pin->length);
    sw = gpg_pin_check(pin, pin->ref, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, len);
    if (sw != SW_OK) {
        return sw;
    }

    newlen = G_gpg_vstate.io_length - len;
    if ((newlen > GPG_MAX_PW_LENGTH) ||
        ((pin->ref == PIN_ID_PW1) && (newlen < GPG_MIN_PW1_LENGTH)) ||
        ((pin->ref == PIN_ID_PW3) && (newlen < GPG_MIN_PW3_LENGTH))) {
        return SW_WRONG_DATA;
    }
    sw = gpg_pin_set(pin, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + len, newlen);
    gpg_io_discard(1);
    return sw;
}

int gpg_apdu_reset_retry_counter() {
    int sw = SW_UNKNOWN;
    gpg_pin_t *pin_pw1;
    gpg_pin_t *pin_rc;
    int rc_len, pw1_len;

    pin_pw1 = gpg_pin_get_pin(PIN_ID_PW1);
    pin_rc = gpg_pin_get_pin(PIN_ID_RC);

    if (G_gpg_vstate.io_p1 == RESET_RETRY_WITH_PW3) {
        // PW3 must be verified, and the data contain the new PW1
        if (!gpg_pin_is_verified(PIN_ID_PW3)) {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        rc_len = 0;
        pw1_len = G_gpg_vstate.io_length;
    } else {
        // The data contain the Resetting Code + the new PW1
        // avoid any-overflow without giving info
        rc_len = MIN(G_gpg_vstate.io_length, pin_rc->length);
        pw1_len = G_gpg_vstate.io_length - rc_len;
        sw = gpg_pin_check(pin_rc,
                           pin_rc->ref,
                           G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                           rc_len);
        if (sw != SW_OK) {
            return sw;
        }
    }

    if ((pw1_len > GPG_MAX_PW_LENGTH) || (pw1_len < GPG_MIN_PW1_LENGTH)) {
        return SW_WRONG_DATA;
    }
    sw = gpg_pin_set(pin_pw1,
                     G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + rc_len,
                     pw1_len);
    gpg_io_discard(1);
    return sw;
}
