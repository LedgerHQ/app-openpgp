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

#include "bolos_target.h"
#if defined(HAVE_BAGL) && (defined(TARGET_NANOX) || defined(TARGET_NANOS2))

#include "gpg_vars.h"
#include "gpg_ux_msg.h"
#include "gpg_ux.h"
#include "usbd_ccid_if.h"

/* ----------------------------------------------------------------------- */
/* ---                        NanoX  UI layout                         --- */
/* ----------------------------------------------------------------------- */
void ui_menu_tmpl_set_action(unsigned int value);
void ui_menu_tmpl_key_action(unsigned int value);
void ui_menu_tmpl_type_action(unsigned int value);
void ui_menu_seedmode_action(unsigned int value);
void ui_menu_reset_action(unsigned int value);

void ui_menu_settings_display(unsigned int value);
void ui_menu_main_display(unsigned int value);
unsigned int ui_pinentry_action_button(unsigned int button_mask, unsigned int button_mask_counter);

/* ------------------------------- Helpers  UX ------------------------------- */

#define ui_flow_display(f, i)     \
    if ((i) < ARRAYLEN(f))        \
        ux_flow_init(0, f, f[i]); \
    else                          \
        ux_flow_init(0, f, NULL)

UX_STEP_CB(ux_menu_popup_1_step,
           bnnn_paging,
           ui_menu_main_display(0),
           {.title = "Info", .text = G_gpg_vstate.menu});

UX_FLOW(ux_flow_popup, &ux_menu_popup_1_step);

void ui_info(const char *msg1, const char *msg2) {
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s. %s", msg1, msg2);
    ux_flow_init(0, ux_flow_popup, NULL);
};

/* ------------------------------ UIF CONFIRM UX ----------------------------- */

unsigned int ui_uifconfirm_action(unsigned int value);
void ui_menu_uifconfirm_predisplay(void);

UX_STEP_NOCB_INIT(ux_menu_uifconfirm_1_step,
                  nnn,
                  ui_menu_uifconfirm_predisplay(),
                  {"Confirm operation", G_gpg_vstate.menu, ""});

UX_STEP_CB(ux_menu_uifconfirm_2_step, pb, ui_uifconfirm_action(0), {&C_icon_crossmark, "No"});

UX_STEP_CB(ux_menu_uifconfirm_3_step, pb, ui_uifconfirm_action(1), {&C_icon_validate_14, "Yes"});

UX_FLOW(ux_flow_uifconfirm,
        &ux_menu_uifconfirm_1_step,
        &ux_menu_uifconfirm_3_step,
        &ux_menu_uifconfirm_2_step);

void ui_menu_uifconfirm_predisplay() {
    switch (G_gpg_vstate.io_ins) {
        case INS_INTERNAL_AUTHENTICATE:
            snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Authentication");
            break;
        case INS_PSO:
            switch (G_gpg_vstate.io_p1p2) {
                case PSO_CDS:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Signature");
                    break;
                case PSO_ENC:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Encryption");
                    break;
                case PSO_DEC:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Decryption");
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    if (G_gpg_vstate.menu[0] == 0) {
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
    }
}

void ui_menu_uifconfirm_display(unsigned int value) {
    ui_flow_display(ux_flow_uifconfirm, value);
}

unsigned int ui_uifconfirm_action(unsigned int value) {
    unsigned int sw = SW_SECURITY_UIF_ISSUE;

    if (value == 1) {
        G_gpg_vstate.UIF_flags = 1;
        switch (G_gpg_vstate.io_ins) {
            case INS_PSO:
                sw = gpg_apdu_pso();
                break;
            case INS_INTERNAL_AUTHENTICATE:
                sw = gpg_apdu_internal_authenticate();
                break;
            default:
                gpg_io_discard(1);
                sw = SW_CONDITIONS_NOT_SATISFIED;
                break;
        }
        G_gpg_vstate.UIF_flags = 0;
    } else {
        gpg_io_discard(1);
    }
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

/* ------------------------------ PIN CONFIRM UX ----------------------------- */

unsigned int ui_pinconfirm_action(unsigned int value);
void ui_menu_pinconfirm_predisplay(void);

UX_STEP_NOCB_INIT(ux_menu_pinconfirm_1_step,
                  nnn,
                  ui_menu_pinconfirm_predisplay(),
                  {"Confirm PIN", G_gpg_vstate.menu, ""});

UX_STEP_CB(ux_menu_pinconfirm_2_step,
           pb,
           ui_pinconfirm_action(0),
           {
               &C_icon_crossmark,
               "No",
           });

UX_STEP_CB(ux_menu_pinconfirm_3_step,
           pb,
           ui_pinconfirm_action(1),
           {
               &C_icon_validate_14,
               "Yes",
           });

UX_FLOW(ux_flow_pinconfirm,
        &ux_menu_pinconfirm_1_step,
        &ux_menu_pinconfirm_2_step,
        &ux_menu_pinconfirm_3_step);

void ui_menu_pinconfirm_predisplay() {
    if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) || (G_gpg_vstate.io_p2 == PIN_ID_PW2) ||
        (G_gpg_vstate.io_p2 == PIN_ID_PW3)) {
        snprintf(G_gpg_vstate.menu,
                 sizeof(G_gpg_vstate.menu),
                 "%s %x",
                 G_gpg_vstate.io_p2 == PIN_ID_PW3 ? "Admin" : "User",
                 G_gpg_vstate.io_p2);
    } else {
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
    }
}

void ui_menu_pinconfirm_display(unsigned int value) {
    UNUSED(value);
    ux_flow_init(0, ux_flow_pinconfirm, NULL);
}

unsigned int ui_pinconfirm_action(unsigned int value) {
    unsigned int sw = SW_UNKNOWN;

    if (value == 1) {
        gpg_pin_set_verified(G_gpg_vstate.io_p2, 1);
        sw = SW_OK;
    } else {
        gpg_pin_set_verified(G_gpg_vstate.io_p2, 0);
        sw = SW_CONDITIONS_NOT_SATISFIED;
    }
    gpg_io_discard(0);
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

/* ------------------------------- PIN ENTRY UX ------------------------------ */

const bagl_element_t ui_pinentry_action[] = {
    // type             userid    x    y    w    h    str   rad  fill              fg        bg
    // font_id icon_id

    // clear screen
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, BAGL_HEIGHT, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
     NULL},

    // left/rights icons
    {{BAGL_ICON, 0x00, 0, 30, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0, 0},
     (const char *) &C_icon_down},
    {{BAGL_ICON, 0x00, 120, 30, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0, 0},
     (const char *) &C_icon_up},

    // PIN text identifier
    {{BAGL_LABELINE,
      0x01,
      10,
      25,
      117,
      15,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu},

    // PIN Value
    {{BAGL_LABELINE,
      0x02,
      10,
      45,
      117,
      15,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu}};

static const char C_pin_digit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '<', 'A', 'V'};

unsigned int ui_pinentry_predisplay(const bagl_element_t *element) {
    if (element->component.userid == 1) {
        if (G_gpg_vstate.io_ins == INS_CHANGE_REFERENCE_DATA) {
            switch (G_gpg_vstate.io_p1) {
                case 0:
                    snprintf(G_gpg_vstate.menu,
                             sizeof(G_gpg_vstate.menu),
                             "Current %s PIN",
                             (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");
                    break;
                case 1:
                    snprintf(G_gpg_vstate.menu,
                             sizeof(G_gpg_vstate.menu),
                             "New %s PIN",
                             (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");
                    break;
                case 2:
                    snprintf(G_gpg_vstate.menu,
                             sizeof(G_gpg_vstate.menu),
                             "Confirm %s PIN",
                             (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");
                    break;
                default:
                    snprintf(G_gpg_vstate.menu,
                             sizeof(G_gpg_vstate.menu),
                             "WAT %s PIN",
                             (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");
                    break;
            }
        } else {
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     "%s PIN",
                     (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");
        }
    } else if (element->component.userid == 2) {
        unsigned int i;
        G_gpg_vstate.menu[0] = ' ';
        for (i = 1; i < G_gpg_vstate.ux_pinentry[0]; i++) {
            G_gpg_vstate.menu[i] = '*';
        }
        G_gpg_vstate.menu[i] = C_pin_digit[G_gpg_vstate.ux_pinentry[i]];
        i++;
        for (; i <= GPG_MAX_PW_LENGTH; i++) {
            G_gpg_vstate.menu[i] = '-';
        }
        G_gpg_vstate.menu[i] = 0;
    }

    return 1;
}

void ui_menu_pinentry_display(unsigned int value) {
    if (value == 0) {
        memset(G_gpg_vstate.ux_pinentry, 0, sizeof(G_gpg_vstate.ux_pinentry));
        G_gpg_vstate.ux_pinentry[0] = 1;
        G_gpg_vstate.ux_pinentry[1] = 5;
    }
    UX_DISPLAY(ui_pinentry_action, (void *) ui_pinentry_predisplay);
}

static void validate_pin() {
    unsigned int offset, len, sw = SW_UNKNOWN;
    gpg_pin_t *pin;

    for (offset = 1; offset <= G_gpg_vstate.ux_pinentry[0]; offset++) {
        G_gpg_vstate.menu[offset] = C_pin_digit[G_gpg_vstate.ux_pinentry[offset]];
    }

    if (G_gpg_vstate.io_ins == INS_VERIFY) {
        pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
        sw = gpg_pin_check(pin,
                           G_gpg_vstate.io_p2,
                           (unsigned char *) (G_gpg_vstate.menu + 1),
                           G_gpg_vstate.ux_pinentry[0]);
        gpg_io_discard(1);
        gpg_io_insert_u16(sw);
        gpg_io_do(IO_RETURN_AFTER_TX);
        if (sw != SW_OK) {
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     " %d tries remaining",
                     pin->counter);
            ui_info(WRONG_PIN, G_gpg_vstate.menu);
        } else {
            ui_menu_main_display(0);
        }
    }

    if (G_gpg_vstate.io_ins == INS_CHANGE_REFERENCE_DATA) {
        if (G_gpg_vstate.io_p1 <= 2) {
            gpg_io_insert_u8(G_gpg_vstate.ux_pinentry[0]);
            gpg_io_insert((unsigned char *) (G_gpg_vstate.menu + 1), G_gpg_vstate.ux_pinentry[0]);
            G_gpg_vstate.io_p1++;
        }
        if (G_gpg_vstate.io_p1 == 3) {
            pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
            if (gpg_pin_check(pin,
                              G_gpg_vstate.io_p2,
                              G_gpg_vstate.work.io_buffer + 1,
                              G_gpg_vstate.work.io_buffer[0]) != SW_OK) {
                gpg_io_discard(1);
                gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
                gpg_io_do(IO_RETURN_AFTER_TX);
                snprintf(G_gpg_vstate.menu,
                         sizeof(G_gpg_vstate.menu),
                         " %d tries remaining",
                         pin->counter);
                ui_info(WRONG_PIN, EMPTY);
                return;
            }
            offset = 1 + G_gpg_vstate.work.io_buffer[0];
            len = G_gpg_vstate.work.io_buffer[offset];
            if ((len != G_gpg_vstate.work.io_buffer[offset + 1 + len]) ||
                (memcmp(G_gpg_vstate.work.io_buffer + offset + 1,
                        G_gpg_vstate.work.io_buffer + offset + 1 + len + 1,
                        len) != 0)) {
                gpg_io_discard(1);
                gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
                gpg_io_do(IO_RETURN_AFTER_TX);
                ui_info(PIN_DIFFERS, EMPTY);
            } else {
                sw = gpg_pin_set(gpg_pin_get_pin(G_gpg_vstate.io_p2),
                                 G_gpg_vstate.work.io_buffer + offset + 1,
                                 len);
                gpg_io_discard(1);
                gpg_io_insert_u16(sw);
                gpg_io_do(IO_RETURN_AFTER_TX);
                ui_menu_main_display(0);
            }
        } else {
            ui_menu_pinentry_display(0);
        }
    }
}

unsigned int ui_pinentry_action_button(unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    unsigned int offset = G_gpg_vstate.ux_pinentry[0];
    char digit;

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:  // Down
            if (G_gpg_vstate.ux_pinentry[offset]) {
                G_gpg_vstate.ux_pinentry[offset]--;
            } else {
                G_gpg_vstate.ux_pinentry[offset] = sizeof(C_pin_digit) - 1;
            }
            ui_menu_pinentry_display(1);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:  // up
            G_gpg_vstate.ux_pinentry[offset]++;
            if (G_gpg_vstate.ux_pinentry[offset] == sizeof(C_pin_digit)) {
                G_gpg_vstate.ux_pinentry[offset] = 0;
            }
            ui_menu_pinentry_display(1);
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            digit = C_pin_digit[G_gpg_vstate.ux_pinentry[offset]];
            // next digit
            if ((digit >= '0') && (digit <= '9')) {
                offset++;
                G_gpg_vstate.ux_pinentry[0] = offset;
                if (offset == GPG_MAX_PW_LENGTH + 1) {
                    validate_pin();
                } else {
                    G_gpg_vstate.ux_pinentry[offset] = 5;
                    ui_menu_pinentry_display(1);
                }
            }
            // cancel digit
            else if (digit == '<') {
                if (offset > 1) {
                    offset--;
                    G_gpg_vstate.ux_pinentry[0] = offset;
                }
                ui_menu_pinentry_display(1);
            }
            // validate pin
            else if (digit == 'V') {
                G_gpg_vstate.ux_pinentry[0] = offset - 1;
                validate_pin();
            }
            // cancel input without check
            else {  //(digit == 'A')
                gpg_io_discard(0);
                gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
                gpg_io_do(IO_RETURN_AFTER_TX);
                ui_menu_main_display(0);
            }
            break;
    }
    return 0;
}

/* ------------------------------- template UX ------------------------------- */

void ui_menu_template_display(unsigned int value);

const char *const tmpl_key_getter_values[] = {LABEL_SIG, LABEL_DEC, LABEL_AUT};

const unsigned int tmpl_key_getter_values_map[] = {1, 2, 3};

const char *tmpl_key_getter(unsigned int idx) {
    if (idx < ARRAYLEN(tmpl_key_getter_values)) {
        return tmpl_key_getter_values[idx];
    }
    return NULL;
}

void tmpl_key_selector(unsigned int idx) {
    if (idx < ARRAYLEN(tmpl_key_getter_values)) {
        idx = tmpl_key_getter_values_map[idx];
    } else {
        idx = 0;
    }
    G_gpg_vstate.ux_key = idx;
    ui_menu_template_display(0);
}

const char *const tmpl_type_getter_values[] = {LABEL_RSA2048,
                                               LABEL_RSA3072,
#ifdef WITH_SUPPORT_RSA4096
                                               LABEL_RSA4096,
#endif
                                               LABEL_SECP256K1,
                                               LABEL_Ed25519};

const unsigned int tmpl_type_getter_values_map[] = {2048,
                                                    3072,
#ifdef WITH_SUPPORT_RSA4096
                                                    4096,
#endif
                                                    CX_CURVE_SECP256R1,
                                                    CX_CURVE_Ed25519};

const char *tmpl_type_getter(unsigned int idx) {
    if (idx < ARRAYLEN(tmpl_type_getter_values)) {
        return tmpl_type_getter_values[idx];
    }
    return NULL;
}

void tmpl_type_selector(unsigned int idx) {
    if (idx < ARRAYLEN(tmpl_type_getter_values)) {
        idx = tmpl_type_getter_values_map[idx];
    } else {
        idx = 0;
    }
    G_gpg_vstate.ux_type = idx;
    ui_menu_template_display(1);
}

#define KEY_KEY  G_gpg_vstate.ux_buff1
#define KEY_TYPE G_gpg_vstate.ux_buff2

void ui_menu_templet_action();
void ui_menu_template_predisplay(void);

UX_STEP_CB_INIT(ux_menu_template_1_step,
                bn,
                ui_menu_template_predisplay(),
                ux_menulist_init(G_ux.stack_count - 1, tmpl_key_getter, tmpl_key_selector),
                {
                    "Key",
                    KEY_KEY,
                });

UX_STEP_CB_INIT(ux_menu_template_2_step,
                bn,
                ui_menu_template_predisplay(),
                ux_menulist_init(G_ux.stack_count - 1, tmpl_type_getter, tmpl_type_selector),
                {
                    "Type",
                    KEY_TYPE,
                });

UX_STEP_CB(ux_menu_template_3_step,
           nnbnn,
           ui_menu_tmpl_set_action(0),
           {NULL, NULL, "Set Template", NULL, NULL});

UX_STEP_CB(ux_menu_template_4_step,
           pb,
           ui_menu_settings_display(0),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_template,
        &ux_menu_template_1_step,
        &ux_menu_template_2_step,
        &ux_menu_template_3_step,
        &ux_menu_template_4_step);

void ui_menu_template_predisplay() {
    switch (G_gpg_vstate.ux_key) {
        case 1:
            snprintf(KEY_KEY, sizeof(KEY_KEY), "%s", LABEL_SIG);
            break;
        case 2:
            snprintf(KEY_KEY, sizeof(KEY_KEY), "%s", LABEL_DEC);
            break;
        case 3:
            snprintf(KEY_KEY, sizeof(KEY_KEY), "%s", LABEL_AUT);
            break;
        default:
            snprintf(KEY_KEY, sizeof(KEY_KEY), "Choose key...");
            break;
    }

    switch (G_gpg_vstate.ux_type) {
        case 2048:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_RSA2048);
            break;
        case 3072:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_RSA3072);
            break;
#ifdef WITH_SUPPORT_RSA4096
        case 4096:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_RSA4096);
            break;
#endif
        case CX_CURVE_SECP256R1:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_SECP256K1);
            break;
        case CX_CURVE_Ed25519:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_Ed25519);
            break;
        default:
            snprintf(KEY_TYPE, sizeof(KEY_TYPE), "Choose type...");
            break;
    }
}

void ui_menu_template_display(unsigned int value) {
    ui_flow_display(ux_flow_template, value);
}

void ui_menu_tmpl_set_action(unsigned int value) {
    UNUSED(value);
    LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
    gpg_key_t *dest = NULL;
    const unsigned char *oid = NULL;
    unsigned int oid_len;

    memset(&attributes, 0, sizeof(attributes));
    switch (G_gpg_vstate.ux_type) {
        case 2048:
        case 3072:
#ifdef WITH_SUPPORT_RSA4096
        case 4096:
#endif
            attributes.value[0] = KEY_ID_RSA;
            U2BE_ENCODE(attributes.value, 1, G_gpg_vstate.ux_type);
            attributes.value[3] = 0x00;
            attributes.value[4] = 0x20;
            attributes.value[5] = 0x01;
            attributes.length = 6;
            break;

        case CX_CURVE_SECP256R1:
            oid = gpg_curve2oid(G_gpg_vstate.ux_type, &oid_len);
            if (oid == NULL) {
                break;
            }
            if (G_gpg_vstate.ux_key == 2) {
                attributes.value[0] = KEY_ID_ECDH;
            } else {
                attributes.value[0] = KEY_ID_ECDSA;
            }
            memmove(attributes.value + 1, oid, oid_len);
            attributes.length = 1 + oid_len;
            break;

        case CX_CURVE_Ed25519:
            if (G_gpg_vstate.ux_key == 2) {
                attributes.value[0] = KEY_ID_ECDH;
                memmove(attributes.value + 1, C_OID_cv25519, sizeof(C_OID_cv25519));
                attributes.length = 1 + sizeof(C_OID_cv25519);
            } else {
                attributes.value[0] = KEY_ID_EDDSA;
                memmove(attributes.value + 1, C_OID_Ed25519, sizeof(C_OID_Ed25519));
                attributes.length = 1 + sizeof(C_OID_Ed25519);
            }
            break;

        default:
            break;
    }
    if (attributes.value[0] == 0) {
        ui_info(INVALID_SELECTION, TEMPLATE_TYPE);
        return;
    }

    switch (G_gpg_vstate.ux_key) {
        case 1:
            dest = &G_gpg_vstate.kslot->sig;
            break;
        case 2:
            dest = &G_gpg_vstate.kslot->dec;
            break;
        case 3:
            dest = &G_gpg_vstate.kslot->aut;
            break;
        default:
            break;
    }

    if (dest != NULL) {
        nvm_write(dest, NULL, sizeof(gpg_key_t));
        nvm_write(&dest->attributes, &attributes, sizeof(attributes));
        ui_menu_template_display(1);
    } else {
        ui_info(INVALID_SELECTION, TEMPLATE_KEY);
    }
}

/* --------------------------------- SEED UX --------------------------------- */

#define CUR_SEED_MODE G_gpg_vstate.ux_buff1

void ui_menu_seedmode_action(unsigned int);
void ui_menu_seedmode_predisplay(void);

UX_STEP_CB_INIT(ux_menu_seedmode_1_step,
                bn,
                ui_menu_seedmode_predisplay(),
                ui_menu_seedmode_action(G_gpg_vstate.seed_mode),
                {"Toggle seed mode", CUR_SEED_MODE});

UX_STEP_CB(ux_menu_seedmode_2_step,
           pb,
           ui_menu_settings_display(1),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_seedmode, &ux_menu_seedmode_1_step, &ux_menu_seedmode_2_step);

void ui_menu_seedmode_predisplay() {
    snprintf(CUR_SEED_MODE, sizeof(CUR_SEED_MODE), "%s", G_gpg_vstate.seed_mode ? "ON" : "OFF");
}

void ui_menu_seedmode_display(unsigned int value) {
    ui_flow_display(ux_flow_seedmode, value);
}

static void toggle_seed() {
    if (G_gpg_vstate.seed_mode) {
        G_gpg_vstate.seed_mode = 0;
    } else {
        G_gpg_vstate.seed_mode = 1;
    }
    ui_menu_seedmode_display(0);
}

UX_STEP_NOCB(ui_seed_warning_step,
             paging,
             {.title = "Warning",
              .text = "SEED mode allows to derive "
                      "your key from Master SEED.\n"
                      "Without such mode,\n"
                      "an OS or App update\n"
                      "will cause your private key to be lost!\n\n"
                      "Are you sure you want "
                      "to disable SEED mode?"});

UX_STEP_CB(ui_seed_warning_flow_cancel_step,
           pb,
           ui_menu_seedmode_display(0),
           {
               &C_icon_crossmark,
               "Cancel",
           });

UX_STEP_CB(ui_seed_disabling_flow_confirm_step,
           pbb,
           toggle_seed(),
           {
               &C_icon_validate_14,
               "Disable",
               "SEED Mode",
           });

UX_FLOW(ui_seed_disabling_flow,
        &ui_seed_warning_step,
        &ui_seed_warning_flow_cancel_step,
        &ui_seed_disabling_flow_confirm_step);

void ui_menu_seedmode_action(unsigned int value) {
    if (value == 1) {
        // Current value is 'enable' -> Confirm deactivate
        ux_flow_init(0, ui_seed_disabling_flow, NULL);
    } else {
        // Current value is 'disable' -> Reactivate
        G_gpg_vstate.seed_mode = 1;
        ui_menu_seedmode_display(0);
    }
}

/* ------------------------------- PIN MODE UX ------------------------------ */

void ui_menu_pinmode_action(unsigned int value);
void ui_menu_pinmode_predisplay(void);

#define ONSCR_BUFF G_gpg_vstate.ux_buff1
#define CONFI_BUFF G_gpg_vstate.ux_buff2
#define TRUST_BUFF G_gpg_vstate.ux_buff3

UX_STEP_CB_INIT(ux_menu_pinmode_1_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_SCREEN),
                {"On Screen", ONSCR_BUFF, ONSCR_BUFF + 5});

UX_STEP_CB_INIT(ux_menu_pinmode_2_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_CONFIRM),
                {"Confirm Only", CONFI_BUFF, CONFI_BUFF + 5});

UX_STEP_CB_INIT(ux_menu_pinmode_3_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_TRUST),
                {"Trust", TRUST_BUFF, TRUST_BUFF + 5});

UX_STEP_CB(ux_menu_pinmode_4_step,
           pb,
           ui_menu_pinmode_action(128),
           {
               &C_icon_validate_14,
               "Set as Default",
           });

UX_STEP_CB(ux_menu_pinmode_5_step,
           pb,
           ui_menu_settings_display(2),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_pinmode,
        &ux_menu_pinmode_1_step,
        &ux_menu_pinmode_2_step,
        &ux_menu_pinmode_3_step,
        &ux_menu_pinmode_4_step,
        &ux_menu_pinmode_5_step);

void ui_menu_pinmode_predisplay() {
    snprintf(ONSCR_BUFF, 5, "%s", PIN_MODE_SCREEN == G_gpg_vstate.pinmode ? "ON" : "OFF");
    snprintf(CONFI_BUFF, 5, "%s", PIN_MODE_CONFIRM == G_gpg_vstate.pinmode ? "ON" : "OFF");
    snprintf(TRUST_BUFF, 5, "%s", PIN_MODE_TRUST == G_gpg_vstate.pinmode ? "ON" : "OFF");

    snprintf(ONSCR_BUFF + 5,
             sizeof(ONSCR_BUFF) - 5,
             "%s",
             PIN_MODE_SCREEN == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
    snprintf(CONFI_BUFF + 5,
             sizeof(CONFI_BUFF) - 5,
             "%s",
             PIN_MODE_CONFIRM == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
    snprintf(TRUST_BUFF + 5,
             sizeof(TRUST_BUFF) - 5,
             "%s",
             PIN_MODE_TRUST == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
}

void ui_menu_pinmode_display(unsigned int value) {
    ui_flow_display(ux_flow_pinmode, value);
}

UX_STEP_NOCB(ui_trust_warning_step,
             paging,
             {.title = "Warning",
              .text = "TRUST mode won't request any more PINs "
                      "or validation before operations!\n\n"
                      "Are you sure you want "
                      "to select TRUST mode?"});

UX_STEP_CB(ui_trust_warning_flow_cancel_step,
           pb,
           ui_menu_pinmode_display(PIN_MODE_TRUST),
           {
               &C_icon_crossmark,
               "Cancel",
           });

UX_STEP_CB(ui_trust_selecting_flow_confirm_step,
           pbb,
           ui_menu_pinmode_action(127),
           {
               &C_icon_validate_14,
               "Select",
               "TRUST Mode",
           });

UX_FLOW(ui_trust_selecting_flow,
        &ui_trust_warning_step,
        &ui_trust_warning_flow_cancel_step,
        &ui_trust_selecting_flow_confirm_step);

void ui_menu_pinmode_action(unsigned int value) {
    unsigned char s;

    switch (value) {
        case 128:
            if (G_gpg_vstate.pinmode != N_gpg_pstate->config_pin[0]) {
                if (G_gpg_vstate.pinmode == PIN_MODE_TRUST) {
                    ui_info(DEFAULT_MODE, NOT_ALLOWED);
                    return;
                }
                // set new mode
                s = G_gpg_vstate.pinmode;
                nvm_write((void *) (&N_gpg_pstate->config_pin[0]), &s, 1);
                gpg_activate_pinpad(3);
            }
            value = G_gpg_vstate.pinmode;
            break;
        case PIN_MODE_SCREEN:
        case PIN_MODE_CONFIRM:
            if (value == G_gpg_vstate.pinmode) {
                // Current selected mode
                break;
            }
            if ((gpg_pin_is_verified(PIN_ID_PW1) == 0) && (gpg_pin_is_verified(PIN_ID_PW2) == 0)) {
                ui_info(PIN_USER, NOT_VERIFIED);
                return;
            }
            G_gpg_vstate.pinmode = value;
            break;
        case PIN_MODE_TRUST:
            if (value == G_gpg_vstate.pinmode) {
                // Current selected mode
                break;
            }
            if (!gpg_pin_is_verified(PIN_ID_PW3)) {
                ui_info(PIN_ADMIN, NOT_VERIFIED);
                return;
            }
            // Confirm request
            ux_flow_init(0, ui_trust_selecting_flow, NULL);
            return;
        case 127:
            G_gpg_vstate.pinmode = PIN_MODE_TRUST;
            value = PIN_MODE_TRUST;
            break;
        default:
            value = 0;
            ui_info(INVALID_SELECTION, EMPTY);
            break;
    }

    // redisplay active pin mode entry
    ui_menu_pinmode_display(value);
}

/* ------------------------------- UIF MODE UX ------------------------------ */

void ui_menu_uifmode_action(unsigned int value);
void ui_menu_uifmode_predisplay(void);

#define SIG_BUFF G_gpg_vstate.ux_buff1
#define DEC_BUFF G_gpg_vstate.ux_buff2
#define AUT_BUFF G_gpg_vstate.ux_buff3

UX_STEP_CB_INIT(ux_menu_uif_1_step,
                bn,
                ui_menu_uifmode_predisplay(),
                ui_menu_uifmode_action(0),
                {"UIF for Signature", SIG_BUFF});

UX_STEP_CB_INIT(ux_menu_uif_2_step,
                bn,
                ui_menu_uifmode_predisplay(),
                ui_menu_uifmode_action(1),
                {"UIF for Decryption", DEC_BUFF});

UX_STEP_CB_INIT(ux_menu_uif_3_step,
                bn,
                ui_menu_uifmode_predisplay(),
                ui_menu_uifmode_action(2),
                {"UIF for Authentication", AUT_BUFF});

UX_STEP_CB(ux_menu_uif_4_step,
           pb,
           ui_menu_settings_display(3),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_uif,
        &ux_menu_uif_1_step,
        &ux_menu_uif_2_step,
        &ux_menu_uif_3_step,
        &ux_menu_uif_4_step);

void ui_menu_uifmode_predisplay() {
    snprintf(SIG_BUFF, sizeof(SIG_BUFF), "%s", G_gpg_vstate.kslot->sig.UIF[0] ? "ON" : "OFF");
    snprintf(DEC_BUFF, sizeof(DEC_BUFF), "%s", G_gpg_vstate.kslot->dec.UIF[0] ? "ON" : "OFF");
    snprintf(AUT_BUFF, sizeof(AUT_BUFF), "%s", G_gpg_vstate.kslot->aut.UIF[0] ? "ON" : "OFF");
}

void ui_menu_uifmode_display(unsigned int value) {
    ui_flow_display(ux_flow_uif, value);
}

void ui_menu_uifmode_action(unsigned int value) {
    unsigned char *uif;
    unsigned char new_uif;
    switch (value) {
        case 0:
            uif = &G_gpg_vstate.kslot->sig.UIF[0];
            break;
        case 1:
            uif = &G_gpg_vstate.kslot->dec.UIF[0];
            break;
        case 2:
            uif = &G_gpg_vstate.kslot->aut.UIF[0];
            break;
        default:
            ui_info(INVALID_SELECTION, EMPTY);
            return;
    }
    if (uif[0] == 0) {
        new_uif = 1;
        nvm_write(&uif[0], &new_uif, 1);
    } else if (uif[0] == 1) {
        new_uif = 0;
        nvm_write(&uif[0], &new_uif, 1);
    } else /*if (uif[0] == 2 )*/ {
        ui_info(UIF_LOCKED, EMPTY);
        return;
    }
    ui_menu_uifmode_display(value);
}

/* -------------------------------- RESET UX --------------------------------- */

void ui_menu_reset_action(unsigned int value);

UX_STEP_CB(ux_menu_reset_1_step,
           bnn,
           ui_menu_settings_display(4),
           {"Ooops, NO!", "Do not reset", "the application"});

UX_STEP_CB(ux_menu_reset_2_step, bn, ui_menu_reset_action(0), {"YES!", "Reset the application"});

UX_FLOW(ux_flow_reset, &ux_menu_reset_1_step, &ux_menu_reset_2_step);

void ui_menu_reset_display(unsigned int value) {
    ux_flow_init(value, ux_flow_reset, NULL);
}

void ui_menu_reset_action(unsigned int value) {
    UNUSED(value);
    unsigned char magic[4];
    magic[0] = 0;
    magic[1] = 0;
    magic[2] = 0;
    magic[3] = 0;
    nvm_write((void *) (N_gpg_pstate->magic), magic, 4);
    gpg_init();
    ui_CCID_reset();
    ui_menu_main_display(0);
}

/* ------------------------------- SETTINGS UX ------------------------------- */

const char *const settings_getter_values[] =
    {"Key template", "Seed mode", "PIN mode", "UIF mode", "Reset", "Back"};

const char *settings_getter(unsigned int idx) {
    if (idx < ARRAYLEN(settings_getter_values)) {
        return settings_getter_values[idx];
    }
    return NULL;
}

void settings_selector(unsigned int idx) {
    switch (idx) {
        case 0:
            ui_menu_template_display(0);
            break;
        case 1:
            ui_menu_seedmode_display(0);
            break;
        case 2:
            ui_menu_pinmode_display(0);
            break;
        case 3:
            ui_menu_uifmode_display(0);
            break;
        case 4:
            ui_menu_reset_display(0);
            break;
        default:
            ui_menu_main_display(1);
            break;
    }
}

void ui_menu_settings_display(unsigned int value) {
    ux_menulist_init_select(G_ux.stack_count - 1, settings_getter, settings_selector, value);
}

/* --------------------------------- SLOT UX --------------------------------- */

void ui_menu_slot_action(unsigned int value);
void ui_menu_slot_predisplay(void);

#define SLOT1 G_gpg_vstate.ux_buff1
#define SLOT2 G_gpg_vstate.ux_buff2
#define SLOT3 G_gpg_vstate.ux_buff3

UX_STEP_CB_INIT(ux_menu_slot_1_step,
                bn,
                ui_menu_slot_predisplay(),
                ui_menu_slot_action(1),
                {"Select Slot", SLOT1});

UX_STEP_CB_INIT(ux_menu_slot_2_step,
                bn,
                ui_menu_slot_predisplay(),
                ui_menu_slot_action(2),
                {"Select Slot", SLOT2});

UX_STEP_CB_INIT(ux_menu_slot_3_step,
                bn,
                ui_menu_slot_predisplay(),
                ui_menu_slot_action(3),
                {"Select Slot", SLOT3});

UX_STEP_CB(ux_menu_slot_4_step,
           bn,
           ui_menu_slot_action(128),
           {"Set selected Slot", "as default slot"});

UX_STEP_CB(ux_menu_slot_5_step,
           pn,
           ui_menu_main_display(1),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_slot,
        &ux_menu_slot_1_step,
        &ux_menu_slot_2_step,
        &ux_menu_slot_3_step,
        &ux_menu_slot_4_step,
        &ux_menu_slot_5_step);

void ui_menu_slot_predisplay() {
    snprintf(SLOT1,
             sizeof(SLOT1),
             "1 %s %s",
             1 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
             1 == G_gpg_vstate.slot + 1 ? "+" : " ");
    snprintf(SLOT2,
             sizeof(SLOT2),
             "2 %s %s",
             2 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
             2 == G_gpg_vstate.slot + 1 ? "+" : " ");
    snprintf(SLOT3,
             sizeof(SLOT3),
             "3 %s %s",
             3 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
             3 == G_gpg_vstate.slot + 1 ? "+" : " ");
}

void ui_menu_slot_display(unsigned int value) {
    ui_flow_display(ux_flow_slot, value);
}

void ui_menu_slot_action(unsigned int value) {
    unsigned char s;

    if (value == 128) {
        s = G_gpg_vstate.slot;
        nvm_write((void *) (&N_gpg_pstate->config_slot[1]), &s, 1);
    } else {
        s = (unsigned char) (value - 1);
        if (s != G_gpg_vstate.slot) {
            G_gpg_vstate.slot = s;
            G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[G_gpg_vstate.slot];
            gpg_mse_reset();
            ui_CCID_reset();
        }
    }
    ui_menu_slot_display(G_gpg_vstate.slot);
}

/* --------------------------------- INFO UX --------------------------------- */

UX_STEP_NOCB(ux_menu_info_1_step,
             bnnn,
             {
                 "OpenPGP Card",
                 "(c) Ledger SAS",
                 "Spec  " XSTR(SPEC_VERSION),
#ifdef HAVE_PRINTF
                 "[DBG] App  " XSTR(APPVERSION),
#else
                 "App  " XSTR(APPVERSION),
#endif
             });

UX_STEP_CB(ux_menu_info_2_step,
           pb,
           ui_menu_main_display(0),
           {
               &C_icon_back_x,
               "Back",
           });

UX_FLOW(ux_flow_info, &ux_menu_info_1_step, &ux_menu_info_2_step);

void ui_menu_info_display(unsigned int value) {
    UNUSED(value);
    ux_flow_init(0, ux_flow_info, NULL);
}

/* --------------------------------- MAIN UX --------------------------------- */

void ui_menu_main_predisplay(void);

UX_STEP_NOCB_INIT(ux_menu_main_1_step,
                  pnn,
                  ui_menu_main_predisplay(),
                  {
                      &C_gpg_16px,
                      G_gpg_vstate.ux_buff1,
                      G_gpg_vstate.ux_buff2,
                  });

UX_STEP_CB(ux_menu_main_2_step, pb, ui_menu_slot_display(0), {&C_icon_coggle, "Select Slot"});

UX_STEP_CB(ux_menu_main_3_step, pb, ui_menu_settings_display(0), {&C_icon_coggle, "Settings"});

UX_STEP_CB(ux_menu_main_4_step, pb, ui_menu_info_display(0), {&C_icon_certificate, "About"});

UX_STEP_CB(ux_menu_main_5_step, pb, os_sched_exit(0), {&C_icon_dashboard_x, "Quit app"});

UX_FLOW(ux_flow_main,
        &ux_menu_main_1_step,
        &ux_menu_main_2_step,
        &ux_menu_main_3_step,
        &ux_menu_main_4_step,
        &ux_menu_main_5_step);

void ui_menu_main_predisplay() {
    memset(G_gpg_vstate.ux_buff1, 0, sizeof(G_gpg_vstate.ux_buff1));
    memmove(G_gpg_vstate.ux_buff1, (void *) (N_gpg_pstate->name.value), 20);
    if (G_gpg_vstate.ux_buff1[0] == 0) {
        memmove(G_gpg_vstate.ux_buff1, "<No Name>", 9);
    } else {
        for (int i = 0; i < 12; i++) {
            if (G_gpg_vstate.ux_buff1[i] == '<') {
                G_gpg_vstate.ux_buff1[i] = ' ';
            }
        }
    }

    unsigned int serial = U4BE(G_gpg_vstate.kslot->serial, 0);
    memset(G_gpg_vstate.ux_buff2, 0, sizeof(G_gpg_vstate.ux_buff2));
    snprintf(G_gpg_vstate.ux_buff2,
             sizeof(G_gpg_vstate.ux_buff2),
             "ID: %x / %d",
             serial,
             G_gpg_vstate.slot + 1);
}

void ui_menu_main_display(unsigned int value) {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    ui_flow_display(ux_flow_main, value);
}

/* --- INIT --- */

void ui_init(void) {
    ui_menu_main_display(0);
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *) element);
}

#endif  // defined(HAVE_BAGL) && (defined(TARGET_NANOX) || defined(TARGET_NANOS2))
