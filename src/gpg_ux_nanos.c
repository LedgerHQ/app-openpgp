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
#if defined(HAVE_BAGL) && defined(TARGET_NANOS)

#include "gpg_vars.h"
#include "gpg_ux_msg.h"
#include "gpg_ux.h"
#include "usbd_ccid_if.h"

/* ----------------------------------------------------------------------- */
/* ---                        NanoS  UI layout                         --- */
/* ----------------------------------------------------------------------- */

void ui_menu_tmpl_set_action(unsigned int value);
void ui_menu_tmpl_key_action(unsigned int value);
void ui_menu_tmpl_type_action(unsigned int value);
void ui_menu_seedmode_action(unsigned int value);
void ui_menu_reset_action(unsigned int value);

const ux_menu_entry_t ui_menu_settings[];
void ui_menu_main_display(unsigned int value);
unsigned int ui_pinentry_action_button(unsigned int button_mask, unsigned int button_mask_counter);

/* ------------------------------- Helpers  UX ------------------------------- */

/**
 * Display popup message on screen
 *
 * @param[in] msg1 1st part of the message
 * @param[in] msg2 2nd part of the message
 * @param[in] menu_display next page display callback
 *
 */
void ui_info(const char *msg1, const char *msg2, const void *menu_display) {
    explicit_bzero(&G_gpg_vstate.ui_dogsays[0], sizeof(ux_menu_entry_t));
    G_gpg_vstate.ui_dogsays[0].callback = menu_display;
    G_gpg_vstate.ui_dogsays[0].userid = 0;
    G_gpg_vstate.ui_dogsays[0].line1 = msg1;
    G_gpg_vstate.ui_dogsays[0].line2 = msg2;

    explicit_bzero(&G_gpg_vstate.ui_dogsays[1], sizeof(ux_menu_entry_t));
    UX_MENU_DISPLAY(0, G_gpg_vstate.ui_dogsays, NULL);
};

/* ------------------------------ UIF CONFIRM UX ----------------------------- */

unsigned int ui_uifconfirm_action_button(unsigned int button_mask,
                                         unsigned int button_mask_counter);
unsigned int ui_uifconfirm_predisplay(const bagl_element_t *element);

const bagl_element_t ui_uifconfirm_action[] = {
    // type             userid    x    y    w    h    str   rad  fill              fg        bg
    // font_id icon_id
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS}, NULL},

    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK}, NULL},

    {{BAGL_LABELINE,
      0x01,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu},
    {{BAGL_LABELINE,
      0x02,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu},
};

/**
 * UIF page display
 *
 * @param[in] value unused
 *
 */
void ui_menu_uifconfirm_display(unsigned int value) {
    UNUSED(value);
    UX_DISPLAY(ui_uifconfirm_action, (void *) ui_uifconfirm_predisplay);
}

/**
 * UIF page display preparation callback
 *
 * @param[in] element selected element to display
 *
 * @return Error code
 *
 */
unsigned int ui_uifconfirm_predisplay(const bagl_element_t *element) {
    explicit_bzero(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu));

    switch (element->component.userid) {
        case 1:
            snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Confirm:");
            break;
        case 2:
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
            break;
        default:
            break;
    }
    if (G_gpg_vstate.menu[0] == 0) {
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
    }
    return 1;
}

/**
 * UIF page Action callback
 *
 * @param[in] button_mask selected button
 * @param[in] button_mask_counter unused
 *
 * @return Error code
 *
 */
unsigned int ui_uifconfirm_action_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    unsigned int sw = SW_SECURITY_UIF_ISSUE;

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:  // CANCEL
            gpg_io_discard(1);
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:  // OK
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
            break;
    }
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    return 0;
}

/* ------------------------------ PIN CONFIRM UX ----------------------------- */

unsigned int ui_pinconfirm_action_button(unsigned int button_mask,
                                         unsigned int button_mask_counter);

const bagl_element_t ui_pinconfirm_action[] = {
    // type             userid    x    y    w    h    str   rad  fill              fg        bg
    // font_id icon_id
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS}, NULL},

    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK}, NULL},

    {{BAGL_LABELINE,
      0x01,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu},
    {{BAGL_LABELINE,
      0x02,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu},
};

/**
 * Pin Confirm display preparation callback
 *
 * @param[in] element selected element to display
 *
 * @return Error code
 *
 */
unsigned int ui_pinconfirm_predisplay(const bagl_element_t *element) {
    if (element->component.userid == 1) {
        if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) || (G_gpg_vstate.io_p2 == PIN_ID_PW2) ||
            (G_gpg_vstate.io_p2 == PIN_ID_PW3)) {
            snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Confirm PIN");
            return 1;
        }
    }
    if (element->component.userid == 2) {
        if ((G_gpg_vstate.io_p2 == PIN_ID_PW1) || (G_gpg_vstate.io_p2 == PIN_ID_PW2) ||
            (G_gpg_vstate.io_p2 == PIN_ID_PW3)) {
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     "%s %x",
                     G_gpg_vstate.io_p2 == PIN_ID_PW3 ? "Admin" : "User",
                     G_gpg_vstate.io_p2);
            return 1;
        }
    }
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
    return 1;
}

/**
 * Pin Confirm page display
 *
 * @param[in] value unused
 *
 */
void ui_menu_pinconfirm_display(unsigned int value) {
    UNUSED(value);
    UX_DISPLAY(ui_pinconfirm_action, (void *) ui_pinconfirm_predisplay);
}

/**
 * Pin Confirm Action callback
 *
 * @param[in] button_mask selected button
 * @param[in] button_mask_counter unused
 *
 * @return Error code
 *
 */
unsigned int ui_pinconfirm_action_button(unsigned int button_mask,
                                         unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    unsigned int sw = SW_CONDITIONS_NOT_SATISFIED;

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:  // CANCEL
            gpg_pin_set_verified(G_gpg_vstate.io_p2, 0);
            sw = SW_CONDITIONS_NOT_SATISFIED;
            break;

        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:  // OK
            gpg_pin_set_verified(G_gpg_vstate.io_p2, 1);
            sw = SW_OK;
            break;
        default:
            return 0;
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
    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_DOWN}, NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_UP}, NULL},

    // PIN text identifier
    {{BAGL_LABELINE,
      0x01,
      0,
      12,
      128,
      32,
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
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_gpg_vstate.menu}};

static const char C_pin_digit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '<', 'A', 'V'};

/**
 * Pin Entry display preparation callback
 *
 * @param[in] element selected element to display
 *
 * @return Error code
 *
 */
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
        for (i = 0; i < G_gpg_vstate.ux_pinLen; i++) {
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

/**
 * Pin Entry page display
 *
 * @param[in] value indicate if pin is reset
 *
 */
void ui_menu_pinentry_display(unsigned int value) {
    if (value == 0) {
        explicit_bzero(G_gpg_vstate.ux_pinentry, sizeof(G_gpg_vstate.ux_pinentry));
        G_gpg_vstate.ux_pinLen = 0;
        G_gpg_vstate.ux_pinentry[0] = 5;
    }
    UX_DISPLAY(ui_pinentry_action, (void *) ui_pinentry_predisplay);
}

/**
 * Pin Entry Validation callback
 *
 */
static void validate_pin() {
    unsigned int offset, len, sw = SW_UNKNOWN;
    gpg_pin_t *pin;

    for (offset = 0; offset <= G_gpg_vstate.ux_pinLen; offset++) {
        G_gpg_vstate.menu[offset] = C_pin_digit[G_gpg_vstate.ux_pinentry[offset]];
    }

    if (G_gpg_vstate.io_ins == INS_VERIFY) {
        pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
        sw = gpg_pin_check(pin,
                           G_gpg_vstate.io_p2,
                           (unsigned char *) G_gpg_vstate.menu,
                           G_gpg_vstate.ux_pinLen);
        gpg_io_discard(1);
        gpg_io_insert_u16(sw);
        gpg_io_do(IO_RETURN_AFTER_TX);
        if (sw != SW_OK) {
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     " %d tries remaining",
                     pin->counter);
            ui_info(WRONG_PIN, G_gpg_vstate.menu, ui_menu_main_display);
        } else {
            ui_menu_main_display(0);
        }
    }

    if (G_gpg_vstate.io_ins == INS_CHANGE_REFERENCE_DATA) {
        if (G_gpg_vstate.io_p1 <= 2) {
            gpg_io_insert_u8(G_gpg_vstate.ux_pinLen);
            gpg_io_insert((unsigned char *) G_gpg_vstate.menu, G_gpg_vstate.ux_pinLen);
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
                ui_info(WRONG_PIN, G_gpg_vstate.menu, ui_menu_main_display);
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
                ui_info(PIN_DIFFERS, EMPTY, ui_menu_main_display);
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

/**
 * Pin Entry page Action callback
 *
 * @param[in] button_mask selected button
 * @param[in] button_mask_counter unused
 *
 * @return Error code
 *
 */
unsigned int ui_pinentry_action_button(unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    unsigned int offset = G_gpg_vstate.ux_pinLen;
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
                G_gpg_vstate.ux_pinLen = ++offset;
                if (offset == GPG_MAX_PW_LENGTH) {
                    validate_pin();
                } else {
                    G_gpg_vstate.ux_pinentry[offset] = 5;
                    ui_menu_pinentry_display(1);
                }
            }
            // cancel digit
            else if (digit == '<') {
                if (offset > 0) {
                    G_gpg_vstate.ux_pinLen--;
                }
                ui_menu_pinentry_display(1);
            }
            // validate pin
            else if (digit == 'V') {
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
#ifdef NO_DECRYPT_cv25519
void ui_menu_template_display_type(unsigned int value);
#endif

const ux_menu_entry_t ui_menu_tmpl_key[];
const ux_menu_entry_t ui_menu_tmpl_type[];

const ux_menu_entry_t ui_menu_template[] = {
    {ui_menu_tmpl_key, NULL, -1, NULL, "Choose key...", NULL, 0, 0},
#ifdef NO_DECRYPT_cv25519
    {NULL, ui_menu_template_display_type, -1, NULL, "Choose type...", NULL, 0, 0},
#else
    {ui_menu_tmpl_type, NULL, -1, NULL, "Choose type...", NULL, 0, 0},
#endif
    {NULL, ui_menu_tmpl_set_action, -1, NULL, "Set template", NULL, 0, 0},
    {ui_menu_settings, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t ui_menu_tmpl_key[] = {
    {NULL, ui_menu_tmpl_key_action, 1, NULL, LABEL_SIG, NULL, 0, 0},
    {NULL, ui_menu_tmpl_key_action, 2, NULL, LABEL_DEC, NULL, 0, 0},
    {NULL, ui_menu_tmpl_key_action, 3, NULL, LABEL_AUT, NULL, 0, 0},
    {ui_menu_template, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t ui_menu_tmpl_type[] = {
    {NULL, ui_menu_tmpl_type_action, 2048, NULL, LABEL_RSA2048, NULL, 0, 0},
    {NULL, ui_menu_tmpl_type_action, 3072, NULL, LABEL_RSA3072, NULL, 0, 0},
#ifdef WITH_SUPPORT_RSA4096
    {NULL, ui_menu_tmpl_type_action, 4096, NULL, LABEL_RSA4096, NULL, 0, 0},
#endif
    {NULL, ui_menu_tmpl_type_action, CX_CURVE_SECP256K1, NULL, LABEL_SECP256K1, NULL, 0, 0},
    {NULL, ui_menu_tmpl_type_action, CX_CURVE_SECP256R1, NULL, LABEL_SECP256R1, NULL, 0, 0},
    {NULL, ui_menu_tmpl_type_action, CX_CURVE_Ed25519, NULL, LABEL_Ed25519, NULL, 0, 0},
    {ui_menu_template, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

#ifdef NO_DECRYPT_cv25519
const ux_menu_entry_t ui_menu_tmpl_Dectype[] = {
    {NULL, ui_menu_tmpl_type_action, 2048, NULL, LABEL_RSA2048, NULL, 0, 0},
    {NULL, ui_menu_tmpl_type_action, 3072, NULL, LABEL_RSA3072, NULL, 0, 0},
#ifdef WITH_SUPPORT_RSA4096
    {NULL, ui_menu_tmpl_type_action, 4096, NULL, LABEL_RSA4096, NULL, 0, 0},
#endif
    {NULL, ui_menu_tmpl_type_action, CX_CURVE_SECP256K1, NULL, LABEL_SECP256K1, NULL, 0, 0},
    {NULL, ui_menu_tmpl_type_action, CX_CURVE_SECP256R1, NULL, LABEL_SECP256R1, NULL, 0, 0},
    {ui_menu_template, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};
#endif

/**
 * Template page display preparation callback
 *
 * @param[in] entry selected menu to display
 * @param[in] element selected element to display
 *
 * @return Eelement to display
 *
 */
const bagl_element_t *ui_menu_template_predisplay(const ux_menu_entry_t *entry,
                                                  bagl_element_t *element) {
    if (element->component.userid == 0x20) {
        if (entry == &ui_menu_template[0]) {
            switch (G_gpg_vstate.ux_key) {
                case 1:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s", LABEL_SIG);
                    break;
                case 2:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s", LABEL_DEC);
                    break;
                case 3:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s", LABEL_AUT);
                    break;
                default:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Choose key...");
                    break;
            }
            element->text = G_gpg_vstate.menu;
        }
        if (entry == &ui_menu_template[1]) {
            switch (G_gpg_vstate.ux_type) {
                case 2048:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %s", LABEL_RSA2048);
                    break;
                case 3072:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %s", LABEL_RSA3072);
                    break;
#ifdef WITH_SUPPORT_RSA4096
                case 4096:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %s", LABEL_RSA4096);
                    break;
#endif
                case CX_CURVE_SECP256K1:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %s", LABEL_SECP256K1);
                    break;
                case CX_CURVE_SECP256R1:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %s", LABEL_SECP256R1);
                    break;
                case CX_CURVE_Ed25519:
#ifdef NO_DECRYPT_cv25519
                    if (G_gpg_vstate.ux_key == 2) {
                        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Choose type...");
                    } else
#endif
                    {
                        snprintf(G_gpg_vstate.menu,
                                 sizeof(G_gpg_vstate.menu),
                                 " %s",
                                 LABEL_Ed25519);
                    }
                    break;
                default:
                    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Choose type...");
                    break;
            }
            element->text = G_gpg_vstate.menu;
        }
    }
    return element;
}

/**
 * Template page display
 *
 * @param[in] value flow step
 *
 */
void ui_menu_template_display(unsigned int value) {
    UX_MENU_DISPLAY(value, ui_menu_template, ui_menu_template_predisplay);
}
#ifdef NO_DECRYPT_cv25519
void ui_menu_template_display_type(unsigned int value) {
    UNUSED(value);
    if (G_gpg_vstate.ux_key == 2) {
        UX_MENU_DISPLAY(0, ui_menu_tmpl_Dectype, ui_menu_template_predisplay);
    } else {
        UX_MENU_DISPLAY(0, ui_menu_tmpl_type, ui_menu_template_predisplay);
    }
}
#endif
/**
 * Template Action callback
 *
 * @param[in] value unused
 *
 */
void ui_menu_tmpl_set_action(unsigned int value) {
    UNUSED(value);
    LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
    gpg_key_t *dest = NULL;
    const unsigned char *oid;
    unsigned int oid_len;

    explicit_bzero(&attributes, sizeof(attributes));
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

        case CX_CURVE_SECP256K1:
        case CX_CURVE_SECP256R1:
            if (G_gpg_vstate.ux_key == 2) {
                attributes.value[0] = KEY_ID_ECDH;
            } else {
                attributes.value[0] = KEY_ID_ECDSA;
            }
            oid = gpg_curve2oid(G_gpg_vstate.ux_type, &oid_len);
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
        ui_info(INVALID_SELECTION, TEMPLATE_TYPE, ui_menu_template_display);
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
        ui_info(OK, EMPTY, ui_menu_template_display);
    } else {
        ui_info(INVALID_SELECTION, TEMPLATE_KEY, ui_menu_template_display);
    }
}

/**
 * Key Name Template Action callback
 *
 * @param[in] value selected key
 *
 */
void ui_menu_tmpl_key_action(unsigned int value) {
    G_gpg_vstate.ux_key = value;
    ui_menu_template_display(0);
}

/**
 * Key Type Template Action callback
 *
 * @param[in] value selected key
 *
 */
void ui_menu_tmpl_type_action(unsigned int value) {
    G_gpg_vstate.ux_type = value;
    ui_menu_template_display(1);
}

/* --------------------------------- SEED UX --------------------------------- */

const ux_menu_entry_t ui_menu_seedmode[] = {
    {NULL, NULL, 0, NULL, "", NULL, 0, 0},
    {NULL, ui_menu_seedmode_action, 1, NULL, "Set on", NULL, 0, 0},
    {NULL, ui_menu_seedmode_action, 0, NULL, "Set off", NULL, 0, 0},
    {ui_menu_settings, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

/**
 * Seed Mode page display preparation callback
 *
 * @param[in] entry selected menu to display
 * @param[in] element selected element to display
 *
 * @return Eelement to display
 *
 */
const bagl_element_t *ui_menu_seedmode_predisplay(const ux_menu_entry_t *entry,
                                                  bagl_element_t *element) {
    if (element->component.userid == 0x20) {
        if (entry == &ui_menu_seedmode[0]) {
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     "< %s >",
                     G_gpg_vstate.seed_mode ? "ON" : "OFF");
            element->text = G_gpg_vstate.menu;
        }
    }
    return element;
}

/**
 * Seed Mode page display
 *
 * @param[in] value flow step
 *
 */
void ui_menu_seedmode_display(unsigned int value) {
    UX_MENU_DISPLAY(value, ui_menu_seedmode, ui_menu_seedmode_predisplay);
}

/**
 * Seed Mode toggle callback
 *
 * @param[in] value selected seed mode
 *
 */
static void toggle_seed(unsigned int value) {
    if (value != 128) {
        return;
    }
    if (G_gpg_vstate.seed_mode) {
        G_gpg_vstate.seed_mode = 0;
    } else {
        G_gpg_vstate.seed_mode = 1;
    }
    ui_menu_seedmode_display(0);
}

const ux_menu_entry_t ui_seed_warning[] = {
    {NULL, NULL, -1, &C_icon_warning, "Warning", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "SEED mode", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "allows to", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "derive your", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "key from", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Master SEED.", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Without such", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "mode, an OS", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "or App update", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "will cause", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "your private", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "key to be", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "lost!", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Are you sure", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "you want to", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "disable", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "SEED mode?", NULL, 0, 0},
    {NULL, ui_menu_seedmode_display, 0, &C_icon_back, "Cancel", NULL, 61, 40},
    {NULL, toggle_seed, 128, &C_icon_validate_14, "Disable", NULL, 0, 0},
    UX_MENU_END};

/**
 * Seed Mode Action callback
 *
 * @param[in] value selected mode
 *
 */
void ui_menu_seedmode_action(unsigned int value) {
    if (value == 0) {
        // Request deactivate
        UX_MENU_DISPLAY(0, ui_seed_warning, NULL);
    } else {
        // Reactivate
        G_gpg_vstate.seed_mode = 1;
        ui_menu_seedmode_display(0);
    }
}

/* ------------------------------- PIN MODE UX ------------------------------ */

void ui_menu_pinmode_action(unsigned int value);
const bagl_element_t *ui_menu_pinmode_predisplay(const ux_menu_entry_t *entry,
                                                 bagl_element_t *element);

const ux_menu_entry_t ui_menu_pinmode[] = {
    {NULL, NULL, -1, NULL, "Choose:", NULL, 0, 0},
    {NULL, ui_menu_pinmode_action, 0x8000 | PIN_MODE_SCREEN, NULL, "On Screen", NULL, 0, 0},
    {NULL, ui_menu_pinmode_action, 0x8000 | PIN_MODE_CONFIRM, NULL, "Confirm only", NULL, 0, 0},
    {NULL, ui_menu_pinmode_action, 0x8000 | PIN_MODE_TRUST, NULL, "Trust", NULL, 0, 0},
    {NULL, ui_menu_pinmode_action, 128, NULL, "Set Default", NULL, 0, 0},
    {ui_menu_settings, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

/**
 * Pin Mode page display
 *
 * @param[in] value flow step
 *
 */
void ui_menu_pinmode_display(unsigned int value) {
    UX_MENU_DISPLAY(value, ui_menu_pinmode, ui_menu_pinmode_predisplay);
}

/**
 * Pin Mode page display preparation callback
 *
 * @param[in] entry selected menu to display
 * @param[in] element selected element to display
 *
 * @return element to display
 *
 */
const bagl_element_t *ui_menu_pinmode_predisplay(const ux_menu_entry_t *entry,
                                                 bagl_element_t *element) {
    if (element->component.userid == 0x20) {
        if ((entry->userid >= (0x8000 | PIN_MODE_SCREEN)) &&
            (entry->userid <= (0x8000 | PIN_MODE_TRUST))) {
            unsigned char id = entry->userid & 0x7FFFF;
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     "%s  %s  %s",
                     (char *) PIC(entry->line1),
                     id == N_gpg_pstate->config_pin[0] ? "#" : " ", /* default */
                     id == G_gpg_vstate.pinmode ? "+" : " " /* selected*/);
            element->text = G_gpg_vstate.menu;
            element->component.height = 32;
        }
    }
    return element;
}

const ux_menu_entry_t ui_trust_warning[] = {
    {NULL, NULL, -1, &C_icon_warning, "Warning", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "TRUST mode", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "won't request", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "any more PINs", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "or validation", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "before", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "operations!", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Are you sure", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "you want to", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "select", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "TRUST mode?", NULL, 0, 0},
    {NULL, ui_menu_pinmode_display, 3, &C_icon_back, "Cancel", NULL, 61, 40},
    {NULL, ui_menu_pinmode_action, 127, &C_icon_validate_14, "Select", NULL, 61, 40},
    UX_MENU_END};

/**
 * Pin Mode Action callback
 *
 * @param[in] value selected mode
 *
 */
void ui_menu_pinmode_action(unsigned int value) {
    unsigned char s;
    value = value & 0x7FFF;

    switch (value) {
        case 128:
            if (G_gpg_vstate.pinmode != N_gpg_pstate->config_pin[0]) {
                if (G_gpg_vstate.pinmode == PIN_MODE_TRUST) {
                    ui_info(DEFAULT_MODE, NOT_ALLOWED, ui_menu_pinmode_display);
                    return;
                }
                // set new mode
                s = G_gpg_vstate.pinmode;
                nvm_write((void *) (&N_gpg_pstate->config_pin[0]), &s, 1);
                gpg_activate_pinpad(3);
            }
            value = G_gpg_vstate.pinmode + 1;
            break;
        case PIN_MODE_SCREEN:
        case PIN_MODE_CONFIRM:
            if (value == G_gpg_vstate.pinmode) {
                // Current selected mode
                value++;
                break;
            }
            if ((gpg_pin_is_verified(PIN_ID_PW1) == 0) && (gpg_pin_is_verified(PIN_ID_PW2) == 0)) {
                ui_info(PIN_USER, NOT_VERIFIED, ui_menu_pinmode_display);
                return;
            }
            G_gpg_vstate.pinmode = value;
            value++;
            break;
        case PIN_MODE_TRUST:
            if (value == G_gpg_vstate.pinmode) {
                // Current selected mode
                value++;
                break;
            }
            if (!gpg_pin_is_verified(PIN_ID_PW3)) {
                ui_info(PIN_ADMIN, NOT_VERIFIED, ui_menu_pinmode_display);
                return;
            }
            // Confirm request
            UX_MENU_DISPLAY(0, ui_trust_warning, NULL);
            return;
        case 127:
            G_gpg_vstate.pinmode = PIN_MODE_TRUST;
            value = PIN_MODE_TRUST + 1;
            break;
        default:
            value = 0;
            ui_info(INVALID_SELECTION, EMPTY, ui_menu_pinmode_display);
            break;
    }
    ui_menu_pinmode_display(value);
}

/* ------------------------------- UIF MODE UX ------------------------------ */

void ui_menu_uifmode_action(unsigned int value);
const bagl_element_t *ui_menu_uifmode_predisplay(const ux_menu_entry_t *entry,
                                                 bagl_element_t *element);

const ux_menu_entry_t ui_menu_uifmode[] = {
    {NULL, NULL, -1, NULL, "Activate (+) for:", NULL, 0, 0},
    {NULL, ui_menu_uifmode_action, 1, NULL, "Signature", NULL, 0, 0},
    {NULL, ui_menu_uifmode_action, 2, NULL, "Decryption", NULL, 0, 0},
    {NULL, ui_menu_uifmode_action, 3, NULL, "Authentication", NULL, 0, 0},
    {ui_menu_settings, NULL, 0, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

void ui_menu_uifmode_display(unsigned int value) {
    UX_MENU_DISPLAY(value, ui_menu_uifmode, ui_menu_uifmode_predisplay);
}

/**
 * UIF page display preparation callback
 *
 * @param[in] entry selected menu to display
 * @param[in] element selected element to display
 *
 * @return element to display
 *
 */
const bagl_element_t *ui_menu_uifmode_predisplay(const ux_menu_entry_t *entry,
                                                 bagl_element_t *element) {
    if (element->component.userid == 0x20) {
        if ((entry->userid >= 1) && (entry->userid <= 3)) {
            unsigned char uif[2];
            uif[0] = 0;
            uif[1] = 0;
            switch (entry->userid) {
                case 1:
                    *uif = G_gpg_vstate.kslot->sig.UIF[0] ? '+' : ' ';
                    break;
                case 2:
                    *uif = G_gpg_vstate.kslot->dec.UIF[0] ? '+' : ' ';
                    break;
                case 3:
                    *uif = G_gpg_vstate.kslot->aut.UIF[0] ? '+' : ' ';
                    break;
            }
            snprintf(G_gpg_vstate.menu,
                     sizeof(G_gpg_vstate.menu),
                     "%s  %s",
                     (char *) PIC(entry->line1),
                     uif);
            element->text = G_gpg_vstate.menu;
            element->component.height = 32;
        }
    }
    return element;
}

/**
 * UIF Action callback
 *
 * @param[in] value selected key
 *
 */
void ui_menu_uifmode_action(unsigned int value) {
    unsigned char *uif;
    unsigned char new_uif;
    switch (value) {
        case 1:
            uif = &G_gpg_vstate.kslot->sig.UIF[0];
            break;
        case 2:
            uif = &G_gpg_vstate.kslot->dec.UIF[0];
            break;
        case 3:
            uif = &G_gpg_vstate.kslot->aut.UIF[0];
            break;
        default:
            ui_info(INVALID_SELECTION, EMPTY, ui_menu_uifmode_display);
            return;
    }
    if (uif[0] == 0) {
        new_uif = 1;
        nvm_write(&uif[0], &new_uif, 1);
    } else if (uif[0] == 1) {
        new_uif = 0;
        nvm_write(&uif[0], &new_uif, 1);
    } else /*if (uif[0] == 2 )*/ {
        ui_info(UIF_LOCKED, EMPTY, ui_menu_uifmode_display);
        return;
    }
    ui_menu_uifmode_display(value);
}

/* -------------------------------- RESET UX --------------------------------- */

const ux_menu_entry_t ui_menu_reset[] = {
    {NULL, NULL, 0, NULL, "Really Reset ?", NULL, 0, 0},
    {NULL, ui_menu_main_display, 0, &C_icon_back, "No", NULL, 61, 40},
    {NULL, ui_menu_reset_action, 0, NULL, "Yes", NULL, 0, 0},
    UX_MENU_END};

/**
 * Reset Action callback
 *
 * @param[in] value unused
 *
 */
void ui_menu_reset_action(unsigned int value) {
    UNUSED(value);

    app_reset();
    ui_init();
}

/* ------------------------------- SETTINGS UX ------------------------------- */

const ux_menu_entry_t ui_menu_settings[] = {
    {NULL, ui_menu_template_display, 0, NULL, "Key template", NULL, 0, 0},
    {NULL, ui_menu_seedmode_display, 0, NULL, "Seed mode", NULL, 0, 0},
    {NULL, ui_menu_pinmode_display, 0, NULL, "PIN mode", NULL, 0, 0},
    {NULL, ui_menu_uifmode_display, 0, NULL, "UIF mode", NULL, 0, 0},
    {ui_menu_reset, NULL, 0, NULL, "Reset App", NULL, 0, 0},
    {NULL, ui_menu_main_display, 2, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

/* --------------------------------- INFO UX --------------------------------- */

const ux_menu_entry_t ui_menu_info[] = {
    {NULL, NULL, -1, NULL, "OpenPGP Card", NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Version  " APPVERSION, NULL, 0, 0},
    {NULL, NULL, -1, NULL, "Spec  " XSTR(SPEC_VERSION), NULL, 0, 0},
    {NULL, NULL, -1, NULL, "(c) Ledger SAS", NULL, 0, 0},
    {NULL, ui_menu_main_display, 3, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

/* --------------------------------- MAIN UX --------------------------------- */

const ux_menu_entry_t ui_menu_main[] = {
    {NULL, NULL, 0, NULL, "", "", 0, 0},
    {ui_menu_settings, NULL, 0, NULL, "Settings", NULL, 0, 0},
    {ui_menu_info, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, (void *) app_quit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

/**
 * Main page display preparation callback
 *
 * @param[in] entry selected menu to display
 * @param[in] element selected element to display
 *
 * @return Eelement to display
 *
 */
const bagl_element_t *ui_menu_main_predisplay(const ux_menu_entry_t *entry,
                                              bagl_element_t *element) {
    if (entry == &ui_menu_main[0]) {
        explicit_bzero(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu));
        if (element->component.userid == 0x21) {
            memmove(G_gpg_vstate.menu, (void *) (N_gpg_pstate->name.value), 12);
            if (G_gpg_vstate.menu[0] != 0) {
                for (int i = 0; i < 12; i++) {
                    if ((G_gpg_vstate.menu[i] == '<') || (G_gpg_vstate.menu[i] == '>')) {
                        G_gpg_vstate.menu[i] = ' ';
                    }
                }
            }
        }
        if (element->component.userid == 0x22) {
            unsigned int serial = U4BE(G_gpg_vstate.kslot->serial, 0);
            explicit_bzero(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu));
            snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "ID: %x", serial);
        }
        if (G_gpg_vstate.menu[0] != 0) {
            element->text = G_gpg_vstate.menu;
        }
    }
    return element;
}
/**
 * Main page display
 *
 * @param[in] value flow step
 *
 */
void ui_menu_main_display(unsigned int value) {
    UX_MENU_DISPLAY(value, ui_menu_main, ui_menu_main_predisplay);
}

/* --- INIT --- */

/**
 * home page definition
 *
 */
void ui_init(void) {
    ui_menu_main_display(0);
    // setup the first screen changing
    UX_CALLBACK_SET_INTERVAL(1000);
}

#endif  // defined(HAVE_BAGL) && defined(TARGET_NANOS)
