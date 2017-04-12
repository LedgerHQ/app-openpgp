
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


#include "os_io_seproxyhal.h"
#include "string.h"
#include "glyphs.h"


/* ----------------------------------------------------------------------- */
/* ---                        Blue  UI layout                          --- */
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