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

#ifdef UI_NANO_X

#include "os.h"
#include "cx.h"
#include "gpg_types.h"
#include "gpg_api.h"
#include "gpg_vars.h"

#include "gpg_ux_msg.h"
#include "os_io_seproxyhal.h"
#include "usbd_ccid_impl.h"
#include "string.h"
#include "glyphs.h"

/* ----------------------------------------------------------------------- */
/* ---                        NanoS  UI layout                         --- */
/* ----------------------------------------------------------------------- */
void ui_menu_settings_display(unsigned int value);

void ui_menu_template_display(unsigned int value);
void ui_menu_tmpl_set_action(unsigned int value);
void ui_menu_tmpl_key_action(unsigned int value);
void ui_menu_tmpl_type_action(unsigned int value);

void ui_menu_seed_display(unsigned int value);
void ui_menu_seed_action(unsigned int value);

void ui_menu_reset_action(unsigned int value);

#if GPG_MULTISLOT
void ui_menu_slot_display(unsigned int value);
void ui_menu_slot_action(unsigned int value);
#endif

void ui_menu_main_display(unsigned int value);

void         ui_menu_pinconfirm_action(unsigned int value);
unsigned int ui_pinconfirm_nanos_button(unsigned int button_mask, unsigned int button_mask_counter);
unsigned int ui_pinconfirm_prepro(const bagl_element_t *element);

const bagl_element_t ui_pinentry_nanos[];
void                 ui_menu_pinentry_display(unsigned int value);
void                 ui_menu_pinentry_action(unsigned int value);
unsigned int         ui_pinentry_nanos_button(unsigned int button_mask, unsigned int button_mask_counter);
unsigned int         ui_pinentry_prepro(const bagl_element_t *element);
static unsigned int  validate_pin();

/* ------------------------------- Helpers  UX ------------------------------- */
#define ui_flow_display(f, i)                                                                                          \
  if ((i) < ARRAYLEN(f))                                                                                               \
    ux_flow_init(0, f, f[i]);                                                                                          \
  else                                                                                                                 \
    ux_flow_init(0, f, NULL)

void ui_CCID_reset(void) {
#ifdef HAVE_USB_CLASS_CCID
  io_usb_ccid_set_card_inserted(0);
  io_usb_ccid_set_card_inserted(1);
#endif
}

UX_STEP_CB(ux_menu_popup_1_step, bnnn_paging, ui_menu_main_display(0), {.title = "Info", .text = G_gpg_vstate.menu});

UX_FLOW(ux_flow_popup, &ux_menu_popup_1_step);

void ui_info(const char *msg1, const char *msg2, const void *menu_display, unsigned int value) {
  snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s. %s", msg1, msg2);
  ux_flow_init(0, ux_flow_popup, NULL);
};

/* ------------------------------ UIF CONFIRM UX ----------------------------- */

unsigned int ui_uifconfirm_action(unsigned int value);
void         ui_menu_uifconfirm_predisplay(void);

UX_STEP_NOCB_INIT(ux_menu_uifconfirm_1_step,
                  nnn,
                  ui_menu_uifconfirm_predisplay(),
                  {"Confirm operation", G_gpg_vstate.menu, ""});

UX_STEP_CB(ux_menu_uifconfirm_2_step, pb, ui_uifconfirm_action(0), {&C_icon_crossmark, "No"});

UX_STEP_CB(ux_menu_uifconfirm_3_step, pb, ui_uifconfirm_action(1), {&C_icon_validate_14, "Yes"});

UX_FLOW(ux_flow_uifconfirm, &ux_menu_uifconfirm_1_step, &ux_menu_uifconfirm_3_step, &ux_menu_uifconfirm_2_step);

void ui_menu_uifconfirm_predisplay() {
  unsigned int uif_case = (G_gpg_vstate.io_ins << 16) | (G_gpg_vstate.io_p1 << 8) | (G_gpg_vstate.io_p2);
  switch (uif_case) {
  case 0x002A9E9A:
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Signature");
    break;
  case 0x002A8680:
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Encryption");
    break;
  case 0x002A8086:
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Decryption");
    break;
  case 0x00880000:
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Authentication");
    break;
  default:
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
  }
}

void ui_menu_uifconfirm_display(unsigned int value) {
  ui_flow_display(ux_flow_uifconfirm, value);
}

unsigned int ui_uifconfirm_action(unsigned int value) {
  unsigned int sw;

  sw = 0x6985;
  if (value == 1) {
    BEGIN_TRY {
      TRY {
        G_gpg_vstate.UIF_flags = 1;
        if (G_gpg_vstate.io_ins == INS_PSO) {
          sw = gpg_apdu_pso();
        } else if (G_gpg_vstate.io_ins == INS_INTERNAL_AUTHENTICATE) {
          sw = gpg_apdu_internal_authenticate();
        } else {
          gpg_io_discard(1);
          sw = 0x6985;
        }
      }
      CATCH_OTHER(e) {
        gpg_io_discard(1);
        if ((e & 0xFFFF0000) || (((e & 0xF000) != 0x6000) && ((e & 0xF000) != 0x9000))) {
          gpg_io_insert_u32(e);
          sw = 0x6f42;
        } else {
          sw = e;
        }
      }
      FINALLY {
        G_gpg_vstate.UIF_flags = 0;
        gpg_io_insert_u16(sw);
        gpg_io_do(IO_RETURN_AFTER_TX);
        ui_menu_main_display(0);
      }
    }
    END_TRY;
  } else {
    gpg_io_discard(1);
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_menu_main_display(0);
    sw = 0x6985;
  }
  return 0;
}

/* ------------------------------ PIN CONFIRM UX ----------------------------- */
unsigned int ui_pinconfirm_action(unsigned int value);
void         ui_menu_pinconfirm_predisplay(void);
void         ui_menu_pinconfirm_display(unsigned int value);

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

UX_FLOW(ux_flow_pinconfirm, &ux_menu_pinconfirm_1_step, &ux_menu_pinconfirm_2_step, &ux_menu_pinconfirm_3_step);

void ui_menu_pinconfirm_predisplay() {
  if ((G_gpg_vstate.io_p2 == 0x81) || (G_gpg_vstate.io_p2 == 0x82) || (G_gpg_vstate.io_p2 == 0x83)) {
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s %x", G_gpg_vstate.io_p2 == 0x83 ? "Admin" : "User",
             G_gpg_vstate.io_p2);
  } else {
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
  }
}

void ui_menu_pinconfirm_display(unsigned int value) {
  ux_flow_init(0, ux_flow_pinconfirm, NULL);
}

unsigned int ui_pinconfirm_action(unsigned int value) {
  unsigned int sw;

  sw = 0x6985;
  if (value == 1) {
    gpg_pin_set_verified(G_gpg_vstate.io_p2, 1);
    sw = 0x9000;
  } else {
    gpg_pin_set_verified(G_gpg_vstate.io_p2, 0);
    sw = 0x6985;
  }
  gpg_io_discard(0);
  gpg_io_insert_u16(sw);
  gpg_io_do(IO_RETURN_AFTER_TX);
  ui_menu_main_display(0);
  return 0;
}

/* ------------------------------- PIN ENTRY UX ------------------------------ */

const bagl_element_t ui_pinentry_nanos[] = {
    // type             userid    x    y    w    h    str   rad  fill              fg        bg     font_id icon_id

    // clrar screen
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 64, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0}, NULL, 0, 0, 0, NULL, NULL, NULL},

    // left/rights icons
    {{BAGL_ICON, 0x00, 0, 30, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0, 0},
     (const char *)&C_icon_down,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 120, 30, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0, 0},
     (const char *)&C_icon_up,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // PIN text identifier
    {{BAGL_LABELINE, 0x01, 10, 25, 117, 15, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     G_gpg_vstate.menu,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // PIN Value
    {{BAGL_LABELINE, 0x02, 10, 45, 117, 15, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     G_gpg_vstate.menu,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
static const char C_pin_digit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '<', 'A', 'V'};

void ui_menu_pinentry_display(unsigned int value) {
  if (value == 0) {
    os_memset(G_gpg_vstate.ux_pinentry, 0, sizeof(G_gpg_vstate.ux_pinentry));
    G_gpg_vstate.ux_pinentry[0] = 1;
    G_gpg_vstate.ux_pinentry[1] = 5;
  }
  UX_DISPLAY(ui_pinentry_nanos, (void *)ui_pinentry_prepro);
}

unsigned int ui_pinentry_prepro(const bagl_element_t *element) {
  if (element->component.userid == 1) {
    if (G_gpg_vstate.io_ins == 0x24) {
      switch (G_gpg_vstate.io_p1) {
      case 0:
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Current %s PIN",
                 (G_gpg_vstate.io_p2 == 0x83) ? "Admin" : "User");
        break;
      case 1:
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "New %s PIN",
                 (G_gpg_vstate.io_p2 == 0x83) ? "Admin" : "User");
        break;
      case 2:
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Confirm %s PIN",
                 (G_gpg_vstate.io_p2 == 0x83) ? "Admin" : "User");
        break;
      default:
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "WAT %s PIN",
                 (G_gpg_vstate.io_p2 == 0x83) ? "Admin" : "User");
        break;
      }
    } else {
      snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s PIN", (G_gpg_vstate.io_p2 == 0x83) ? "Admin" : "User");
    }
  } else if (element->component.userid == 2) {
    unsigned int i;
    G_gpg_vstate.menu[0] = ' ';
#if 0
    for (i = 1; i <= G_gpg_vstate.ux_pinentry[0]; i++) {
      G_gpg_vstate.menu[i] = C_pin_digit[G_gpg_vstate.ux_pinentry[i]];
    }
#else
    for (i = 1; i < G_gpg_vstate.ux_pinentry[0]; i++) {
      G_gpg_vstate.menu[i] = '*';
    }
    G_gpg_vstate.menu[i] = C_pin_digit[G_gpg_vstate.ux_pinentry[i]];
    i++;
#endif
    for (; i <= GPG_MAX_PW_LENGTH; i++) {
      G_gpg_vstate.menu[i] = '-';
    }
    G_gpg_vstate.menu[i] = 0;
  }

  return 1;
}

unsigned int ui_pinentry_nanos_button(unsigned int button_mask, unsigned int button_mask_counter) {
  unsigned int offset = G_gpg_vstate.ux_pinentry[0];
  unsigned     m_pinentry;
  char         digit;

  m_pinentry = 1;

  switch (button_mask) {
  case BUTTON_EVT_RELEASED | BUTTON_LEFT: // Down
    if (G_gpg_vstate.ux_pinentry[offset]) {
      G_gpg_vstate.ux_pinentry[offset]--;
    } else {
      G_gpg_vstate.ux_pinentry[offset] = sizeof(C_pin_digit) - 1;
    }
    ui_menu_pinentry_display(1);
    break;

  case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // up
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
    else { //(digit == 'A')
      gpg_io_discard(0);
      gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
      gpg_io_do(IO_RETURN_AFTER_TX);
      ui_menu_main_display(0);
    }
    break;
  }
  return 0;
}
// >= 0
static unsigned int validate_pin() {
  unsigned int offset, len, sw;
  gpg_pin_t *  pin;

  for (offset = 1; offset <= G_gpg_vstate.ux_pinentry[0]; offset++) {
    G_gpg_vstate.menu[offset] = C_pin_digit[G_gpg_vstate.ux_pinentry[offset]];
  }

  if (G_gpg_vstate.io_ins == 0x20) {
    pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
    sw  = gpg_pin_check(pin, G_gpg_vstate.io_p2, (unsigned char *)(G_gpg_vstate.menu + 1), G_gpg_vstate.ux_pinentry[0]);
    gpg_io_discard(1);
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    if (sw != SW_OK) {
      snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %d tries remaining", pin->counter);
      ui_info(WRONG_PIN, G_gpg_vstate.menu, ui_menu_main_display, 0);
    } else {
      ui_menu_main_display(0);
    }
  }

  if (G_gpg_vstate.io_ins == 0x24) {
    if (G_gpg_vstate.io_p1 <= 2) {
      gpg_io_insert_u8(G_gpg_vstate.ux_pinentry[0]);
      gpg_io_insert((unsigned char *)(G_gpg_vstate.menu + 1), G_gpg_vstate.ux_pinentry[0]);
      G_gpg_vstate.io_p1++;
    }
    if (G_gpg_vstate.io_p1 == 3) {
      pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
      if (gpg_pin_check(pin, G_gpg_vstate.io_p2, G_gpg_vstate.work.io_buffer + 1, G_gpg_vstate.work.io_buffer[0]) !=
          SW_OK) {
        gpg_io_discard(1);
        gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
        gpg_io_do(IO_RETURN_AFTER_TX);
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), " %d tries remaining", pin->counter);
        ui_info(WRONG_PIN, NULL, ui_menu_main_display, 0);
        return 0;
      }
      offset = 1 + G_gpg_vstate.work.io_buffer[0];
      len    = G_gpg_vstate.work.io_buffer[offset];
      if ((len != G_gpg_vstate.work.io_buffer[offset + 1 + len]) ||
          (os_memcmp(G_gpg_vstate.work.io_buffer + offset + 1, G_gpg_vstate.work.io_buffer + offset + 1 + len + 1,
                     len) != 0)) {
        gpg_io_discard(1);
        gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
        gpg_io_do(IO_RETURN_AFTER_TX);
        ui_info(PIN_DIFFERS, NULL, ui_menu_main_display, 0);
      } else {
        gpg_pin_set(gpg_pin_get_pin(G_gpg_vstate.io_p2), G_gpg_vstate.work.io_buffer + offset + 1, len);
        gpg_io_discard(1);
        gpg_io_insert_u16(SW_OK);
        gpg_io_do(IO_RETURN_AFTER_TX);
        // ui_info(PIN_CHANGED, NULL, ui_menu_main_display, 0);
        ui_menu_main_display(0);
      }
      return 0;
    } else {
      ui_menu_pinentry_display(0);
    }
  }
  return 0;
}

/* ------------------------------- template UX ------------------------------- */
#define LABEL_SIG "Signature"
#define LABEL_AUT "Authentication"
#define LABEL_DEC "Decryption"

#define LABEL_RSA2048 "RSA 2048"
#define LABEL_RSA3072 "RSA 3072"
#define LABEL_RSA4096 "RSA 4096"
#define LABEL_SECP256K1 "SEPC 256K1"
#define LABEL_Ed25519 "Ed25519"

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

const char *const tmpl_type_getter_values[] = {LABEL_RSA2048, LABEL_RSA3072, LABEL_RSA4096, LABEL_SECP256K1,
                                               LABEL_Ed25519};

const unsigned int tmpl_type_getter_values_map[] = {2048, 3072, 4096, CX_CURVE_SECP256R1, CX_CURVE_Ed25519};

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

#define KEY_KEY G_gpg_vstate.ux_buff1
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

UX_STEP_CB(ux_menu_template_3_step, nnbnn, ui_menu_tmpl_set_action(0), {NULL, NULL, "Set Template", NULL, NULL});

UX_STEP_CB(ux_menu_template_4_step,
           pb,
           ui_menu_settings_display(0),
           {
               &C_icon_back,
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
  case 4096:
    snprintf(KEY_TYPE, sizeof(KEY_TYPE), " %s", LABEL_RSA4096);
    break;
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
  LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
  gpg_key_t *          dest;
  const char *         err;
  const unsigned char *oid;
  unsigned int         oid_len;
  err = NULL;

  os_memset(&attributes, 0, sizeof(attributes));
  switch (G_gpg_vstate.ux_type) {
  case 2048:
  case 3072:
  case 4096:
    attributes.value[0] = 0x01;
    attributes.value[1] = (G_gpg_vstate.ux_type >> 8) & 0xFF;
    attributes.value[2] = G_gpg_vstate.ux_type & 0xFF;
    attributes.value[3] = 0x00;
    attributes.value[4] = 0x20;
    attributes.value[5] = 0x01;
    attributes.length   = 6;
    break;

  case CX_CURVE_SECP256R1:
    if (G_gpg_vstate.ux_key == 2) {
      attributes.value[0] = 18; // ecdh
    } else {
      attributes.value[0] = 19; // ecdsa
    }
    oid = gpg_curve2oid(G_gpg_vstate.ux_type, &oid_len);
    os_memmove(attributes.value + 1, oid, sizeof(oid_len));
    attributes.length = 1 + oid_len;
    break;

  case CX_CURVE_Ed25519:
    if (G_gpg_vstate.ux_key == 2) {
      attributes.value[0] = 18; // ecdh
      os_memmove(attributes.value + 1, C_OID_cv25519, sizeof(C_OID_cv25519));
      attributes.length = 1 + sizeof(C_OID_cv25519);
    } else {
      attributes.value[0] = 22; // eddsa
      os_memmove(attributes.value + 1, C_OID_Ed25519, sizeof(C_OID_Ed25519));
      attributes.length = 1 + sizeof(C_OID_Ed25519);
    }
    break;

  default:
    err = TEMPLATE_TYPE;
    goto ERROR;
  }

  dest = NULL;
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
    err = TEMPLATE_KEY;
    goto ERROR;
  }

  gpg_nvm_write(dest, NULL, sizeof(gpg_key_t));
  gpg_nvm_write(&dest->attributes, &attributes, sizeof(attributes));
  ui_info(OK, NULL, ui_menu_template_display, 0);
  return;

ERROR:
  ui_info(INVALID_SELECTION, err, ui_menu_template_display, 0);
}

#undef KEY_KEY
#undef KEY_TYPE

#undef LABEL_SIG
#undef LABEL_AUT
#undef LABEL_DEC

#undef LABEL_RSA2048
#undef LABEL_RSA3072
#undef LABEL_RSA4096
#undef LABEL_NISTP256
#undef LABEL_SECP256K1
#undef LABEL_Ed25519

/* --------------------------------- SEED UX --------------------------------- */
#define CUR_SEED_MODE G_gpg_vstate.ux_buff1

void ui_menu_seed_action(unsigned int);
void ui_menu_seedmode_display(unsigned int);
void ui_menu_seedmode_predisplay(void);

UX_STEP_CB_INIT(ux_menu_seedmode_1_step,
                bn,
                ui_menu_seedmode_predisplay(),
                ui_menu_seed_action(0),
                {"Toggle seed mode", CUR_SEED_MODE});

UX_STEP_CB(ux_menu_seedmode_2_step,
           pb,
           ui_menu_settings_display(1),
           {
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_seedmode, &ux_menu_seedmode_1_step, &ux_menu_seedmode_2_step);

void ui_menu_seedmode_predisplay() {
  snprintf(CUR_SEED_MODE, sizeof(CUR_SEED_MODE), "%s", G_gpg_vstate.seed_mode ? "ON" : "OFF");
}

void ui_menu_seedmode_display(unsigned int value) {
  ui_flow_display(ux_flow_seedmode, value);
}

void ui_menu_seed_action(unsigned int value) {
  if (G_gpg_vstate.seed_mode) {
    G_gpg_vstate.seed_mode = 0;
  } else {
    G_gpg_vstate.seed_mode = 1;
  }
  ui_menu_seedmode_display(0);
}

#undef CUR_SEED_MODE

/* ------------------------------- PIN MODE UX ------------------------------ */
void ui_menu_pinmode_action(unsigned int value);
void ui_menu_pinmode_display(unsigned int value);
void ui_menu_pinmode_predisplay(void);

#define ONHST_BUFF G_gpg_vstate.ux_buff1
#define ONSCR_BUFF G_gpg_vstate.ux_buff2
#define CONFI_BUFF G_gpg_vstate.ux_buff3
#define TRUST_BUFF G_gpg_vstate.ux_buff4

UX_STEP_CB_INIT(ux_menu_pinmode_1_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_HOST),
                {"On Host", ONHST_BUFF, ONHST_BUFF + 5});

UX_STEP_CB_INIT(ux_menu_pinmode_2_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_SCREEN),
                {"On Screen", ONSCR_BUFF, ONSCR_BUFF + 5});

UX_STEP_CB_INIT(ux_menu_pinmode_3_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_CONFIRM),
                {"Confirm Only", CONFI_BUFF, CONFI_BUFF + 5});

UX_STEP_CB_INIT(ux_menu_pinmode_4_step,
                bnn,
                ui_menu_pinmode_predisplay(),
                ui_menu_pinmode_action(PIN_MODE_TRUST),
                {"Trust", TRUST_BUFF, TRUST_BUFF + 5});

UX_STEP_CB(ux_menu_pinmode_6_step,
           pb,
           ui_menu_pinmode_action(128),
           {
               &C_icon_validate_14,
               "Set as Default",
           });

UX_STEP_CB(ux_menu_pinmode_7_step,
           pb,
           ui_menu_settings_display(2),
           {
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_pinmode,
        &ux_menu_pinmode_1_step,
        &ux_menu_pinmode_2_step,
        &ux_menu_pinmode_3_step,
        &ux_menu_pinmode_4_step,
        &ux_menu_pinmode_6_step,
        &ux_menu_pinmode_7_step);

void ui_menu_pinmode_predisplay() {
  snprintf(ONHST_BUFF, 5, "%s", PIN_MODE_HOST == G_gpg_vstate.pinmode ? "ON" : "OFF");
  snprintf(ONSCR_BUFF, 5, "%s", PIN_MODE_SCREEN == G_gpg_vstate.pinmode ? "ON" : "OFF");
  snprintf(CONFI_BUFF, 5, "%s", PIN_MODE_CONFIRM == G_gpg_vstate.pinmode ? "ON" : "OFF");
  snprintf(TRUST_BUFF, 5, "%s", PIN_MODE_TRUST == G_gpg_vstate.pinmode ? "ON" : "OFF");

  snprintf(ONHST_BUFF + 5, sizeof(ONHST_BUFF) - 5, "%s",
           PIN_MODE_HOST == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
  snprintf(ONSCR_BUFF + 5, sizeof(ONSCR_BUFF) - 5, "%s",
           PIN_MODE_SCREEN == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
  snprintf(CONFI_BUFF + 5, sizeof(CONFI_BUFF) - 5, "%s",
           PIN_MODE_CONFIRM == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
  snprintf(TRUST_BUFF + 5, sizeof(TRUST_BUFF) - 5, "%s",
           PIN_MODE_TRUST == N_gpg_pstate->config_pin[0] ? "(Default)" : "");
}

void ui_menu_pinmode_display(unsigned int value) {
  ui_flow_display(ux_flow_pinmode, value);
}

#undef ONHST_BUFF
#undef ONSCR_BUFF
#undef CONFI_BUFF
#undef TRUST_BUFF

void ui_menu_pinmode_action(unsigned int value) {
  unsigned char s;
  if (value == 128) {
    if (G_gpg_vstate.pinmode != N_gpg_pstate->config_pin[0]) {
      if (G_gpg_vstate.pinmode == PIN_MODE_TRUST) {
        ui_info(DEFAULT_MODE, NOT_ALLOWED, ui_menu_pinmode_display, 0);
        return;
      }
      // set new mode
      s = G_gpg_vstate.pinmode;
      gpg_nvm_write((void *)(&N_gpg_pstate->config_pin[0]), &s, 1);
      // disactivate pinpad if any
      if (G_gpg_vstate.pinmode == PIN_MODE_HOST) {
        s = 0;
      } else {
        s = 3;
      }
      //#warning USBD_CCID_activate_pinpad commented
      USBD_CCID_activate_pinpad(s);
      value = G_gpg_vstate.pinmode;
    }
  } else {
    switch (value) {
    case PIN_MODE_HOST:
    case PIN_MODE_SCREEN:
    case PIN_MODE_CONFIRM:
      if (!gpg_pin_is_verified(PIN_ID_PW2)) {
        ui_info(PIN_USER, NOT_VERIFIED, ui_menu_pinmode_display, 0);
        return;
      }
      break;

    case PIN_MODE_TRUST:
      if (!gpg_pin_is_verified(PIN_ID_PW3)) {
        ui_info(PIN_ADMIN, NOT_VERIFIED, ui_menu_pinmode_display, 0);
        return;
      }
      break;
    default:
      ui_info(INVALID_SELECTION, NULL, ui_menu_pinmode_display, 0);
      return;
    }
    G_gpg_vstate.pinmode = value;
  }
  // redisplay active pin mode entry
  switch (value) {
  case PIN_MODE_HOST:
    ui_menu_pinmode_display(0);
    break;
  case PIN_MODE_SCREEN:
    ui_menu_pinmode_display(1);
    break;
  case PIN_MODE_CONFIRM:
    ui_menu_pinmode_display(2);
    break;
  case PIN_MODE_TRUST:
    ui_menu_pinmode_display(3);
    break;
  default:
    ui_menu_pinmode_display(0);
    break;
  }
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
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_uif, &ux_menu_uif_1_step, &ux_menu_uif_2_step, &ux_menu_uif_3_step, &ux_menu_uif_4_step);

void ui_menu_uifmode_predisplay() {
  snprintf(SIG_BUFF, sizeof(SIG_BUFF), "%s", G_gpg_vstate.kslot->sig.UIF[0] ? "ON" : "OFF");
  snprintf(DEC_BUFF, sizeof(DEC_BUFF), "%s", G_gpg_vstate.kslot->dec.UIF[0] ? "ON" : "OFF");
  snprintf(AUT_BUFF, sizeof(AUT_BUFF), "%s", G_gpg_vstate.kslot->aut.UIF[0] ? "ON" : "OFF");
}

void ui_menu_uifmode_display(unsigned int value) {
  ui_flow_display(ux_flow_uif, value);
}

#undef SIG_BUFF
#undef DEC_BUFF
#undef AUT_BUFF

void ui_menu_uifmode_action(unsigned int value) {
  unsigned char *uif;
  unsigned char  new_uif;
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
    ui_info(INVALID_SELECTION, NULL, ui_menu_uifmode_display, 0);
    return;
  }
  if (uif[0] == 0) {
    new_uif = 1;
    gpg_nvm_write(&uif[0], &new_uif, 1);
  } else if (uif[0] == 1) {
    new_uif = 0;
    gpg_nvm_write(&uif[0], &new_uif, 1);
  } else /*if (uif[0] == 2 )*/ {
    ui_info(UIF_LOCKED, NULL, ui_menu_uifmode_display, 0);
    return;
  }
  ui_menu_uifmode_display(value);
}

/* -------------------------------- RESET UX --------------------------------- */

void ui_menu_reset_action(unsigned int value);

UX_STEP_CB(ux_menu_reset_1_step, bnn, ui_menu_settings_display(4), {"Ooops, NO!", "Do not reset", "the application"});

UX_STEP_CB(ux_menu_reset_2_step, bn, ui_menu_reset_action(0), {"YES!", "Reset the application"});

UX_FLOW(ux_flow_reset, &ux_menu_reset_1_step, &ux_menu_reset_2_step);

void ui_menu_reset_display(unsigned int value) {
  ux_flow_init(value, ux_flow_reset, NULL);
}

void ui_menu_reset_action(unsigned int value) {
  unsigned char magic[4];
  magic[0] = 0;
  magic[1] = 0;
  magic[2] = 0;
  magic[3] = 0;
  gpg_nvm_write((void *)(N_gpg_pstate->magic), magic, 4);
  gpg_init();
  ui_CCID_reset();
  ui_menu_main_display(0);
}

/* ------------------------------ RESET SLOT UX ------------------------------ */

void ui_menu_reset_slot_action(unsigned int value);

UX_STEP_CB(ux_menu_reset_slot_1_step, bnn, ui_menu_settings_display(4), {"Ooops, NO!", "Do not reset", "the key slot"});

UX_STEP_CB(ux_menu_reset_slot_2_step, bn, ui_menu_reset_slot_action(0), {"YES!", "Reset the slot"});

UX_FLOW(ux_flow_reset_slot, &ux_menu_reset_slot_1_step, &ux_menu_reset_slot_2_step);

void ui_menu_reset_slot_display(unsigned int value) {
  ux_flow_init(value, ux_flow_reset_slot, NULL);
}

void ui_menu_reset_slot_action(unsigned int value) {
  gpg_install_slot(G_gpg_vstate.kslot);
  ui_menu_main_display(0);
}

/* ------------------------------- SETTINGS UX ------------------------------- */

const char *const settings_getter_values[] = {"Key template", "Seed mode", "PIN mode", "UIF mode", "Reset", "Back"};

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

#if GPG_MULTISLOT
#if GPG_KEYS_SLOTS != 3
#error menu definition not correct for current value of GPG_KEYS_SLOTS
#endif

void ui_menu_slot_action(unsigned int value);
void ui_menu_slot_predisplay(void);

#define SLOT1 G_gpg_vstate.ux_buff1
#define SLOT2 G_gpg_vstate.ux_buff2
#define SLOT3 G_gpg_vstate.ux_buff3

UX_STEP_CB_INIT(ux_menu_slot_1_step, bn, ui_menu_slot_predisplay(), ui_menu_slot_action(1), {"Select Slot", SLOT1});

UX_STEP_CB_INIT(ux_menu_slot_2_step, bn, ui_menu_slot_predisplay(), ui_menu_slot_action(2), {"Select Slot", SLOT2});

UX_STEP_CB_INIT(ux_menu_slot_3_step, bn, ui_menu_slot_predisplay(), ui_menu_slot_action(3), {"Select Slot", SLOT3});

UX_STEP_CB(ux_menu_slot_4_step, bn, ui_menu_slot_action(128), {"Set selected Slot", "as default slot"});

  UX_STEP_CB(ux_menu_slot_5_step,
           pn,
           ui_menu_main_display(1),
           {
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_slot,
        &ux_menu_slot_1_step,
        &ux_menu_slot_2_step,
        &ux_menu_slot_3_step,
        &ux_menu_slot_4_step,
        &ux_menu_slot_5_step);

void ui_menu_slot_predisplay() {
  snprintf(SLOT1, sizeof(SLOT1), "1 %s %s", 1 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
           1 == G_gpg_vstate.slot + 1 ? "+" : " ");
  snprintf(SLOT2, sizeof(SLOT2), "2 %s %s", 2 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
           2 == G_gpg_vstate.slot + 1 ? "+" : " ");
  snprintf(SLOT3, sizeof(SLOT3), "3 %s %s", 3 == N_gpg_pstate->config_slot[1] + 1 ? "#" : " ",
           3 == G_gpg_vstate.slot + 1 ? "+" : " ");
}

void ui_menu_slot_display(unsigned int value) {
  ui_flow_display(ux_flow_slot, value);
}

#undef SLOT1
#undef SLOT2
#undef SLOT3

void ui_menu_slot_action(unsigned int value) {
  unsigned char s;

  if (value == 128) {
    s = G_gpg_vstate.slot;
    gpg_nvm_write(&N_gpg_pstate->config_slot[1], &s, 1);
  } else {
    s = (unsigned char)(value - 1);
    if (s != G_gpg_vstate.slot) {
      G_gpg_vstate.slot  = s;
      G_gpg_vstate.kslot = &N_gpg_pstate->keys[G_gpg_vstate.slot];
      gpg_mse_reset();
      ui_CCID_reset();
    }
  }
  ui_menu_slot_display(G_gpg_vstate.slot);
}
#endif

/* --------------------------------- INFO UX --------------------------------- */

#define STR(x) #x
#define XSTR(x) STR(x)

UX_STEP_NOCB(ux_menu_info_1_step,
             bnnn,
             {
                 "OpenPGP Card",
                 "(c) Ledger SAS",
                 "Spec  " XSTR(SPEC_VERSION),
                 "App  " XSTR(OPENPGP_VERSION),
             });

UX_STEP_CB(ux_menu_info_2_step,
           pb,
           ui_menu_main_display(0),
           {
               &C_icon_back,
               "Back",
           });

UX_FLOW(ux_flow_info, &ux_menu_info_1_step, &ux_menu_info_2_step);

void ui_menu_info_display(unsigned int value) {
  ux_flow_init(0, ux_flow_info, NULL);
}

#undef STR
#undef XSTR

/* --------------------------------- MAIN UX --------------------------------- */
void ui_menu_main_predisplay(void);

UX_STEP_NOCB_INIT(ux_menu_main_1_step,
                  pnn,
                  ui_menu_main_predisplay(),
                  {
                      &C_icon_pgp,
                      G_gpg_vstate.ux_buff1,
                      G_gpg_vstate.ux_buff2,
                  });

#if GPG_MULTISLOT
UX_STEP_CB(ux_menu_main_2_step, pb, ui_menu_slot_display(0), {&C_icon_coggle, "Select Slot"});
#endif

UX_STEP_CB(ux_menu_main_3_step, pb, ui_menu_settings_display(0), {&C_icon_coggle, "Settings"});

UX_STEP_CB(ux_menu_main_4_step, pb, ui_menu_info_display(0), {&C_icon_certificate, "About"});

UX_STEP_CB(ux_menu_main_5_step, pb, os_sched_exit(0), {&C_icon_dashboard_x, "Quit app"});

UX_FLOW(ux_flow_main,
        &ux_menu_main_1_step,
#if GPG_MULTISLOT
        &ux_menu_main_2_step,
#endif
        &ux_menu_main_3_step,
        &ux_menu_main_4_step,
        &ux_menu_main_5_step);

void ui_menu_main_predisplay() {
  os_memset(G_gpg_vstate.ux_buff1, 0, sizeof(G_gpg_vstate.ux_buff1));
  os_memmove(G_gpg_vstate.ux_buff1, (void *)(N_gpg_pstate->name.value), 20);
  if (G_gpg_vstate.ux_buff1[0] == 0) {
    os_memmove(G_gpg_vstate.ux_buff1, "<No Name>", 9);
  } else {
    for (int i = 0; i < 12; i++) {
      if (G_gpg_vstate.ux_buff1[i] == 0x3c) {
        G_gpg_vstate.ux_buff1[i] = ' ';
      }
    }
  }

  unsigned int serial;
  serial = (G_gpg_vstate.kslot->serial[0] << 24) | (G_gpg_vstate.kslot->serial[1] << 16) |
           (G_gpg_vstate.kslot->serial[2] << 8) | (G_gpg_vstate.kslot->serial[3]);
  os_memset(G_gpg_vstate.ux_buff2, 0, sizeof(G_gpg_vstate.ux_buff2));
#if GPG_MULTISLOT
  snprintf(G_gpg_vstate.ux_buff2, sizeof(G_gpg_vstate.ux_buff2), "ID: %x / %d", serial, G_gpg_vstate.slot + 1);
#else
  snprintf(G_gpg_vstate.ux_buff2, sizeof(G_gpg_vstate.ux_buff2), "ID: %x", serial);
#endif
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
  io_seproxyhal_display_default((bagl_element_t *)element);
}

///-----

#endif // UI_NANOX
