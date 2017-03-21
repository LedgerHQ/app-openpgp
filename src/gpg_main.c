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

#ifndef GPG_DEBUG_MAIN

#include "os.h"
#include "cx.h"
#include "gpg_types.h"
#include "gpg_api.h"
#include "gpg_vars.h"


#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"



/* ----------------------------------------------------------------------- */
/* ---                            UI layout                            --- */
/* ----------------------------------------------------------------------- */
/* screeen size: 
  blue; 320x480 
  nanoS:  128x32
*/
#if 0
static const bagl_element_t const ui_idle_blue[] = {
  {{BAGL_RECTANGLE, 0x00, 0, 60, 320, 420, 0, 0,
    BAGL_FILL,      0xf9f9f9, 0xf9f9f9,
    0, 0},
   NULL,
   0,
   0,
   0,
   NULL,
   NULL,
   NULL},

  {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0,
    BAGL_FILL,      0x1d2028, 0x1d2028,
    0, 0},
   NULL,
   0,
   0,
   0,
   NULL,
   NULL,
   NULL},

  {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0,
    BAGL_FILL,  0xFFFFFF, 0x1d2028,
    BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
   "GPG Card",
   0,
   0,
   0,
   NULL,
   NULL,
   NULL},

  {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 190, 215, 120, 40, 0, 6,
    BAGL_FILL,                         0x41ccb4, 0xF9F9F9,
    BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE,
    0},
   "Exit",
   0,
   0x37ae99,
   0xF9F9F9,
   gpg_io_seproxyhal_touch_exit,
   NULL,
   NULL},

#ifdef GPG_DEBUG
   {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 20, 215, 120, 40, 0, 6,
    BAGL_FILL,                         0x41ccb4, 0xF9F9F9,
    BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE,
    0},
   "Init",
   0,
   0x37ae99,
   0xF9F9F9,
   gpg_io_seproxyhal_touch_debug,
   NULL,
   NULL}
#endif

};


const bagl_element_t ui_idle_nanos[] = {
  // type                              
  {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, 
    BAGL_FILL, 0x000000, 0xFFFFFF, 
    0, 
    0}, 
    NULL, 
    0, 
    0, 
    0, 
    NULL, 
    NULL, 
    NULL},

  {{BAGL_LABELINE, 0x00,   0,  12, 128,  32, 0, 0, 
    0  , 0xFFFFFF, 0x000000, 
    BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER, 
    0 }, 
    "GPGCard", 
    0, 
    0, 
    0, 
    NULL, 
    NULL, 
    NULL },
  //{{BAGL_LABELINE                       , 0x02,   0,  26, 128,  32, 0, 0, 0        , 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  }, "Waiting for requests...", 0, 0, 0, NULL, NULL, NULL },

  {{BAGL_ICON , 0x00,   3,  12,   7,   
    7, 0, 0, 
    0 , 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS  }, 
    NULL, 
    0, 
    0, 
    0, 
    NULL, 
    NULL, 
    NULL },
};

unsigned int gpg_io_seproxyhal_touch_exit(const bagl_element_t *e) {
  // Go back to the dashboard
  os_sched_exit(0);
  return 0; // do not redraw the widget
}




unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
  return 0;
}

#endif

const ux_menu_entry_t ui_idle_mainmenu[];

/* ----- Helpers  UX ----- */
void ui_info(const ux_menu_entry_t *back, const char* msg1, const char* msg2) {
  ux_menu_entry_t ui_invalid[2] = {
   {back, NULL,  0, NULL, msg1, msg2, 0, 0},
   UX_MENU_END
 };
 UX_MENU_DISPLAY(0, ui_invalid, NULL);
};

/* ----- SLOT UX ----- */
void ui_idle_sub_slot_action(unsigned int value) {
  unsigned char s;

  if (value == 0) {
    s = G_gpg_vstate.slot;
    gpg_nvm_write(&N_gpg_pstate->config_slot[1], &s,1);  
  }
  else {
     s = (unsigned char)(value-1);
     G_gpg_vstate.slot = s;
     G_gpg_vstate.kslot   = &N_gpg_pstate->keys[G_gpg_vstate.slot];
     
  }
  // redisplay first entry of the idle menu
  gpg_init_ux();
  UX_MENU_DISPLAY(0, ui_idle_mainmenu, NULL);
}

const ux_menu_entry_t ui_idle_sub_slot[] = {
  #if GPG_KEYS_SLOTS != 3
  #error menu definition not correct for current value of GPG_KEYS_SLOTS
  #endif
  {NULL,             ui_idle_sub_slot_action,   1, NULL,          "Select slot 1",  NULL, 0, 0},
  {NULL,             ui_idle_sub_slot_action,   2, NULL,          "Select slot 2",  NULL, 0, 0},
  {NULL,             ui_idle_sub_slot_action,   3, NULL,          "Select slot 3",  NULL, 0, 0},
  {NULL,             ui_idle_sub_slot_action,   0, NULL,          "Set as default", NULL, 0, 0},
  {ui_idle_mainmenu, NULL,                     1, &C_badge_back, "Back",            NULL, 61, 40},
  UX_MENU_END
};

/* ----- template UX ----- */
#define LABEL_SIG      "Signature"
#define LABEL_AUT      "Authentication"
#define LABEL_DEC      "Decryption"

#define LABEL_RSA2048  "RSA 2048"
#define LABEL_RSA3072  "RSA 3072"
#define LABEL_RSA4096  "RSA 4096"
#define LABEL_NISTP256 "NIST P256"
#define LABEL_BPOOLR1  "Brainpool R1"
#define LABEL_Ed25519  "Ed25519"

const ux_menu_entry_t ui_idle_sub_template[];
const ux_menu_entry_t ui_idle_sub_tmpl_key[];
const ux_menu_entry_t ui_idle_sub_tmpl_type[];

/*
const bagl_element_t* ui_idle_sub_tmpl_key_prepocessor(const ux_menu_entry_t* entry, bagl_element_t* element) {
  if (entry == &ui_idle_sub_tmpl_key[2]) {
    if(element->component.userid==0x20) {
      element->component.stroke = 10; // 1 second stop in each way
      element->component.icon_id = 26; // roundtrip speed in pixel/s
      UX_CALLBACK_SET_INTERVAL(MAX(3000, 2*(1000+bagl_label_roundtrip_duration_ms(element, 7))));
    }
  }
  return element;
}
*/

void ui_idle_sub_tmpl_key_action(unsigned int value) {

  switch(value) {
  case 1:
    snprintf(G_gpg_vstate.menu_template_key, 16, "%s", LABEL_SIG);
    G_gpg_vstate.ux_key = 1;
    break;
  case 2:
    snprintf(G_gpg_vstate.menu_template_key, 16, "%s", LABEL_AUT);
    G_gpg_vstate.ux_key = 2;
    break;
  case 3:
    snprintf(G_gpg_vstate.menu_template_key, 16," %s", LABEL_DEC);
    G_gpg_vstate.ux_key = 3;
    break;
  }
  UX_MENU_DISPLAY(0, ui_idle_sub_template, NULL);
}
const ux_menu_entry_t ui_idle_sub_tmpl_key[] = {
  {NULL,                 ui_idle_sub_tmpl_key_action,   1, NULL,          LABEL_SIG, NULL, 0, 0},
  {NULL,                 ui_idle_sub_tmpl_key_action,   2, NULL,          LABEL_DEC, NULL, 0, 0},
  {NULL,                 ui_idle_sub_tmpl_key_action,   3, NULL,          LABEL_AUT, NULL, 0, 0},
  {ui_idle_sub_template, NULL,                          0, &C_badge_back, "Back",    NULL, 61, 40},
  UX_MENU_END
};

void ui_idle_sub_tmpl_type_action(unsigned int value) {
  switch(value) {
  case 2048:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_RSA2048);
    break;
  case 3072:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_RSA3072);
    break;
  case 4096:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_RSA4096);
    break;
  case CX_CURVE_SECP256R1:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_NISTP256);
    break;
  case CX_CURVE_BrainPoolP256R1:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_BPOOLR1);
    break;
  case CX_CURVE_Ed25519:
    snprintf(G_gpg_vstate.menu_template_type, 16," %s", LABEL_Ed25519);
    break;
  } 
  G_gpg_vstate.ux_type = value;
  UX_MENU_DISPLAY(1, ui_idle_sub_template, NULL);
}
const ux_menu_entry_t ui_idle_sub_tmpl_type[] = {
  {NULL,             ui_idle_sub_tmpl_type_action,   2048,                     NULL,   LABEL_RSA2048,   NULL,  0,  0},
  {NULL,             ui_idle_sub_tmpl_type_action,   3072,                     NULL,   LABEL_RSA3072,   NULL,  0,  0},
  {NULL,             ui_idle_sub_tmpl_type_action,   4096,                     NULL,   LABEL_RSA4096,   NULL,  0,  0},
  {NULL,             ui_idle_sub_tmpl_type_action,   CX_CURVE_SECP256R1,       NULL,   LABEL_NISTP256,  NULL,  0,  0},
  {NULL,             ui_idle_sub_tmpl_type_action,   CX_CURVE_BrainPoolP256R1, NULL,   LABEL_BPOOLR1,   NULL,  0,  0},  
  {NULL,             ui_idle_sub_tmpl_type_action,   CX_CURVE_Ed25519,         NULL,   LABEL_Ed25519,   NULL,  0,  0},
  {ui_idle_sub_template,                    NULL,    1,               &C_badge_back,   "Back",          NULL, 61, 40},
  UX_MENU_END
};


void  ui_idle_sub_tmpl_set_action(unsigned int value) {
  LV(attributes,GPG_KEY_ATTRIBUTES_LENGTH);
  gpg_key_t* dest;
  char* err;

  err = NULL;
  if (!G_gpg_vstate.ux_key) {
    err = "key";
    goto ERROR;
  }
  if (!G_gpg_vstate.ux_type){ 
    err = "type ";
    goto ERROR;
  }

  os_memset(&attributes, 0, sizeof(attributes));
  switch (G_gpg_vstate.ux_type) {
  case 2048:
  case 3072:
  case 4096:
    attributes.value[0] = 0x01;
    attributes.value[1] = (G_gpg_vstate.ux_type>>8) &0xFF;
    attributes.value[2] = G_gpg_vstate.ux_type&0xFF;
    attributes.value[3] = 0x00;
    attributes.value[4] = 0x20;
    attributes.value[5] = 0x01;
    attributes.length = 6;
    break;

  case CX_CURVE_SECP256R1:
    if (G_gpg_vstate.ux_key == 2) {
      attributes.value[0] = 18; //ecdh
    } else {
      attributes.value[0] = 19; //ecdsa
   }
   os_memmove(attributes.value+1, C_OID_SECP256R1, sizeof(C_OID_SECP256R1));
   attributes.length = 1+sizeof(C_OID_SECP256R1);
   break;

  case CX_CURVE_BrainPoolP256R1:
    if (G_gpg_vstate.ux_key == 2) {
      attributes.value[0] = 18; //ecdh
    } else {
      attributes.value[0] = 19; //ecdsa
    }
    os_memmove(attributes.value+1, C_OID_BRAINPOOL256R1, sizeof(C_OID_BRAINPOOL256R1));
    attributes.length = 1+sizeof(C_OID_BRAINPOOL256R1);
    break;

  case CX_CURVE_Ed25519: 
    if (G_gpg_vstate.ux_key == 2) {
      attributes.value[0] = 18; //ecdh
      os_memmove(attributes.value+1, C_OID_cv25519, sizeof(C_OID_cv25519));
      attributes.length = 1+sizeof(C_OID_cv25519);
    } else {
      attributes.value[0] = 22; //eddsa
      os_memmove(attributes.value+1, C_OID_Ed25519, sizeof(C_OID_Ed25519));
      attributes.length = 1+sizeof(C_OID_Ed25519);
    }
    break;

    default:
    err = "not supported";
    goto ERROR;
  }

  dest = NULL;
  switch(G_gpg_vstate.ux_key) {
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
    err = "key not found";
    goto ERROR;
  }
 
  gpg_nvm_write(dest, NULL, sizeof(gpg_key_t));
  gpg_nvm_write(&dest->attributes, &attributes, sizeof(attributes));
  ui_info(ui_idle_sub_template, "Template set!", NULL);
  return;

ERROR:
  ui_info(ui_idle_sub_template, "Invalid selection:", err);

}
/*
void ui_idle_sub_tmpl_key_display(unsigned int value) {
  UX_MENU_DISPLAY(0,ui_idle_sub_tmpl_key,ui_idle_sub_tmpl_key_prepocessor);
}
*/
const ux_menu_entry_t ui_idle_sub_template[] = {
  {ui_idle_sub_tmpl_key,           NULL,  0, NULL,          G_gpg_vstate.menu_template_key,   NULL, 0, 0},
  {ui_idle_sub_tmpl_type,          NULL,  0, NULL,          G_gpg_vstate.menu_template_type,  NULL, 0, 0},
  {NULL,    ui_idle_sub_tmpl_set_action,  0, NULL,          "Set template",                   NULL, 0, 0},
  {ui_idle_mainmenu, NULL,                2, &C_badge_back, "Back",                           NULL, 61, 40},
  UX_MENU_END
};


/* ----- SEED UX ----- */
const ux_menu_entry_t ui_idle_sub_seed[];
void ui_idle_sub_seed_action(unsigned int value) {
  G_gpg_vstate.seed_mode = value;
  gpg_init_ux();
  UX_MENU_DISPLAY(0, ui_idle_sub_seed, NULL);
}
const ux_menu_entry_t ui_idle_sub_seed[] = {
  #if GPG_KEYS_SLOTS != 3
  #error menu definition not correct for current value of GPG_KEYS_SLOTS
  #endif
  {NULL,             NULL,                     0,    NULL,          G_gpg_vstate.menu_seed_mode, NULL, 0, 0},
  {NULL,             ui_idle_sub_seed_action,  1,    NULL,          "Set on",                    NULL, 0, 0},
  {NULL,             ui_idle_sub_seed_action,  0,    NULL,          "Set off",                   NULL, 0, 0},
  {ui_idle_mainmenu, NULL,                     2,    &C_badge_back, "Back",                      NULL, 61, 40},
  UX_MENU_END
};

/* ----- RESET UX ----- */
void ui_idle_sub_reset_action(unsigned int value) {
  unsigned char magic[4];
  magic[0] = 0; magic[1] = 0; magic[2] = 0; magic[3] = 0;
  gpg_nvm_write(N_gpg_pstate->magic, magic, 4);
  gpg_init();
  UX_MENU_DISPLAY(0, ui_idle_mainmenu, NULL);
}
const ux_menu_entry_t ui_idle_sub_reset[] = {
  #if GPG_KEYS_SLOTS != 3
  #error menu definition not correct for current value of GPG_KEYS_SLOTS
  #endif
  {NULL,             NULL,                      0,    NULL,          "Really Reset ?",  NULL, 0, 0},
  {NULL,             ui_idle_sub_reset_action,  0,    NULL,          "Yes!",            NULL, 0, 0},
  {ui_idle_mainmenu, NULL,                      0,    &C_badge_back, "Oh No!",          NULL, 61, 40},
  UX_MENU_END
};

/* ----- SETTINGS UX ----- */
const ux_menu_entry_t ui_idle_settings[] = {
  {NULL,                  NULL,          0, NULL,           G_gpg_vstate.menu_cur_slot, NULL, 0, 0},
  {ui_idle_sub_template,  NULL,          0, NULL,           "Key template",             NULL, 0, 0},
  {ui_idle_sub_seed,      NULL,          0, NULL,           "Seed mode",                NULL, 0, 0},
  {ui_idle_sub_reset,     NULL,          0, NULL,           "Reset",                    NULL, 0, 0},
  {ui_idle_mainmenu,      NULL,          2, &C_badge_back,  "Back",                     NULL, 61, 40},
  UX_MENU_END
};

/* ----- MAIN UX ----- */
const ux_menu_entry_t ui_idle_mainmenu[] = {
  {NULL,               NULL,          0, NULL,              G_gpg_vstate.menu_cur_slot, NULL, 0, 0},
  {ui_idle_sub_slot,   NULL,          0, NULL,              "Select slot",              NULL, 0, 0},
  {ui_idle_settings,   NULL,          0, NULL,              "Settings",                 NULL, 0, 0},
  {NULL,               os_sched_exit, 0, &C_icon_dashboard, "Quit app" ,                NULL, 50, 29},
  UX_MENU_END
};


void io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}
void ui_idle_init(void) {
  UX_MENU_DISPLAY(0, ui_idle_mainmenu, NULL);
  // setup the first screen changing
  UX_CALLBACK_SET_INTERVAL(1000);
}

/* ----------------------------------------------------------------------- */
/* ---                            Application Entry                    --- */
/* ----------------------------------------------------------------------- */

void gpg_main(void) {

  for (;;) {
    volatile unsigned short sw = 0;
    BEGIN_TRY {
      TRY {
        gpg_io_do();
        sw = gpg_dispatch();
      }
      CATCH_OTHER(e) {
        gpg_io_discard(1);
        if ( (e & 0xFFFF0000) ||
             ( ((e&0xF000)!=0x6000) && ((e&0xF000)!=0x9000) ) ) {
          gpg_io_insert_u32(e);
          sw = 0x6f42;
        } else {
          sw = e;
        }
      }
      FINALLY {
        gpg_io_insert_u16(sw);
      }
    }
    END_TRY;
  }

}


unsigned char io_event(unsigned char channel) {
  // nothing done with the event, throw an error on the transport layer if
  // needed
  // can't have more than one tag in the reply, not supported yet.
  switch (G_io_seproxyhal_spi_buffer[0]) {
  case SEPROXYHAL_TAG_FINGER_EVENT:
    UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
    break;
  // power off if long push, else pass to the application callback if any
  case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
    UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
    break;


  // other events are propagated to the UX just in case
  default:
    UX_DEFAULT_EVENT();
    break;

  case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
    UX_DISPLAYED_EVENT({});
    break;
  case SEPROXYHAL_TAG_TICKER_EVENT:
    UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, 
    {
       // only allow display when not locked of overlayed by an OS UX.
      if (UX_ALLOWED ) {
        UX_REDISPLAY(); 
      }
    });
    break;
  }

  // close the event if not done previously (by a display or whatever)
  if (!io_seproxyhal_spi_is_status_sent()) {
    io_seproxyhal_general_status();
  }
  // command has been processed, DO NOT reset the current APDU transport
  return 1;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
  switch (channel & ~(IO_FLAGS)) {
  case CHANNEL_KEYBOARD:
    break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
  case CHANNEL_SPI:
    if (tx_len) {
      io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

      if (channel & IO_RESET_AFTER_REPLIED) {
        reset();
      }
      return 0; // nothing received from the master so far (it's a tx
      // transaction)
    } else {
      return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                    sizeof(G_io_apdu_buffer), 0);
    }

  default:
    THROW(INVALID_PARAMETER);
  }
  return 0;
}

void app_exit(void) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(-1);
    }
    FINALLY_L(exit) {
    }
  }
  END_TRY_L(exit);
}

/* -------------------------------------------------------------- */

__attribute__((section(".boot"))) int main(void) {
  // exit critical section
  __asm volatile("cpsie i");


  // ensure exception will work as planned
  os_boot();
  UX_INIT();

  BEGIN_TRY {
    TRY {
      
      //start communication with MCU
      io_seproxyhal_init();

      USB_CCID_power(1);
   
      //set up
      gpg_init();

      //set up initial screen
      ui_idle_init();
      
   

      //start the application
      //the first exchange will:
      // - display the  initial screen
      // - send the ATR
      // - receive the first command
      gpg_main();
    }
    CATCH_OTHER(e) {
    }
    FINALLY {
    }
  }
  END_TRY;

  app_exit();
}

#endif
