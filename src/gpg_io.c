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

/*
 * io_buff: contains current message part
 * io_off: offset in current message part
 * io_length: length of current message part
 */

/* ----------------------------------------------------------------------- */
/* MISC                                                                    */
/* ----------------------------------------------------------------------- */

void gpg_io_set_offset(unsigned int offset) {
  if (offset == IO_OFFSET_END) {
    G_gpg_vstate.io_offset = G_gpg_vstate.io_length;
  } else if (offset == IO_OFFSET_MARK) {
    G_gpg_vstate.io_offset = G_gpg_vstate.io_mark;
  } else if (offset < G_gpg_vstate.io_length) {
    G_gpg_vstate.io_offset = G_gpg_vstate.io_length;
  } else {
    THROW(ERROR_IO_OFFSET);
    return;
  }
}

void gpg_io_mark() {
  G_gpg_vstate.io_mark = G_gpg_vstate.io_offset;
}

void gpg_io_inserted(unsigned int len) {
  G_gpg_vstate.io_offset += len;
  G_gpg_vstate.io_length += len;
}

void gpg_io_discard(int clear) {
  G_gpg_vstate.io_length = 0;
  G_gpg_vstate.io_offset = 0;
  G_gpg_vstate.io_mark   = 0;
  if (clear) {
    gpg_io_clear();
  }
}

void gpg_io_clear() {
  memset(G_gpg_vstate.work.io_buffer, 0, GPG_IO_BUFFER_LENGTH);
}

/* ----------------------------------------------------------------------- */
/* INSERT data to be sent                                                  */
/* ----------------------------------------------------------------------- */

void gpg_io_hole(unsigned int sz) {
  if ((G_gpg_vstate.io_length + sz) > GPG_IO_BUFFER_LENGTH) {
    THROW(ERROR_IO_FULL);
    return;
  }
  memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + sz,
             G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, G_gpg_vstate.io_length - G_gpg_vstate.io_offset);
  G_gpg_vstate.io_length += sz;
}

void gpg_io_insert(unsigned char const *buff, unsigned int len) {
  gpg_io_hole(len);
  memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, buff, len);
  G_gpg_vstate.io_offset += len;
}

void gpg_io_insert_u32(unsigned int v32) {
  gpg_io_hole(4);
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v32 >> 24;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] = v32 >> 16;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] = v32 >> 8;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 3] = v32 >> 0;
  G_gpg_vstate.io_offset += 4;
}

void gpg_io_insert_u24(unsigned int v24) {
  gpg_io_hole(3);
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v24 >> 16;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] = v24 >> 8;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] = v24 >> 0;
  G_gpg_vstate.io_offset += 3;
}
void gpg_io_insert_u16(unsigned int v16) {
  gpg_io_hole(2);
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v16 >> 8;
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] = v16 >> 0;
  G_gpg_vstate.io_offset += 2;
}
void gpg_io_insert_u8(unsigned int v8) {
  gpg_io_hole(1);
  G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v8;
  G_gpg_vstate.io_offset += 1;
}

void gpg_io_insert_t(unsigned int T) {
  if (T & 0xFF00) {
    gpg_io_insert_u16(T);
  } else {
    gpg_io_insert_u8(T);
  }
}

void gpg_io_insert_tl(unsigned int T, unsigned int L) {
  gpg_io_insert_t(T);
  if (L < 128) {
    gpg_io_insert_u8(L);
  } else if (L < 256) {
    gpg_io_insert_u16(0x8100 | L);
  } else {
    gpg_io_insert_u8(0x82);
    gpg_io_insert_u16(L);
  }
}

void gpg_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) {
  gpg_io_insert_tl(T, L);
  gpg_io_insert(V, L);
}

/* ----------------------------------------------------------------------- */
/* FECTH data from received buffer                                         */
/* ----------------------------------------------------------------------- */

unsigned int gpg_io_fetch_u32() {
  unsigned int v32;
  v32 = ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] << 24) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] << 16) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] << 8) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 3] << 0));
  G_gpg_vstate.io_offset += 4;
  return v32;
}

unsigned int gpg_io_fetch_u24() {
  unsigned int v24;
  v24 = ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] << 16) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] << 8) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] << 0));
  G_gpg_vstate.io_offset += 3;
  return v24;
}

unsigned int gpg_io_fetch_u16() {
  unsigned int v16;
  v16 = ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] << 8) |
         (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] << 0));
  G_gpg_vstate.io_offset += 2;
  return v16;
}

unsigned int gpg_io_fetch_u8() {
  unsigned int v8;
  v8 = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
  G_gpg_vstate.io_offset += 1;
  return v8;
}

int gpg_io_fetch_t(unsigned int *T) {
  *T = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
  G_gpg_vstate.io_offset++;
  if ((*T & 0x1F) == 0x1F) {
    *T = (*T << 8) | G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
    G_gpg_vstate.io_offset++;
  }
  return 0;
}

int gpg_io_fetch_l(unsigned int *L) {
  *L = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];

  if ((*L & 0x80) != 0) {
    *L &= 0x7F;
    if (*L == 1) {
      *L = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1];
      G_gpg_vstate.io_offset += 2;
    } else if (*L == 2) {
      *L = (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] << 8) |
           G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2];
      G_gpg_vstate.io_offset += 3;
    } else {
      *L = -1;
    }
  } else {
    G_gpg_vstate.io_offset += 1;
  }
  return 0;
}

int gpg_io_fetch_tl(unsigned int *T, unsigned int *L) {
  gpg_io_fetch_t(T);
  gpg_io_fetch_l(L);
  return 0;
}

int gpg_io_fetch_nv(unsigned char *buffer, int len) {
  gpg_nvm_write(buffer, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, len);
  G_gpg_vstate.io_offset += len;
  return len;
}
int gpg_io_fetch(unsigned char *buffer, int len) {
  if (buffer) {
    memmove(buffer, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, len);
  }
  G_gpg_vstate.io_offset += len;
  return len;
}

/* ----------------------------------------------------------------------- */
/* REAL IO                                                                 */
/* ----------------------------------------------------------------------- */

#define MAX_OUT GPG_APDU_LENGTH

int gpg_io_do(unsigned int io_flags) {
  unsigned int rx = 0;

  // if pending input chaining
  if (G_gpg_vstate.io_cla & 0x10) {
    goto in_chaining;
  }

  if (io_flags & IO_ASYNCH_REPLY) {
    // if IO_ASYNCH_REPLY has been  set,
    //  gpg_io_exchange will return when  IO_RETURN_AFTER_TX will set in ui
    rx = gpg_io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
  } else {
    // --- full out chaining ---
    G_gpg_vstate.io_offset = 0;
    while (G_gpg_vstate.io_length > MAX_OUT) {
      unsigned int tx, xx;
      // send chunk
      tx = MAX_OUT - 2;
      memmove(G_io_apdu_buffer, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, tx);
      G_gpg_vstate.io_length -= tx;
      G_gpg_vstate.io_offset += tx;
      G_io_apdu_buffer[tx] = 0x61;
      if (G_gpg_vstate.io_length > MAX_OUT - 2) {
        xx = MAX_OUT - 2;
      } else {
        xx = G_gpg_vstate.io_length - 2;
      }
      G_io_apdu_buffer[tx + 1] = xx;
      rx                       = gpg_io_exchange(CHANNEL_APDU, tx + 2);
      // check get response
      if ((G_io_apdu_buffer[0] != 0x00) || (G_io_apdu_buffer[1] != 0xc0) || (G_io_apdu_buffer[2] != 0x00) ||
          (G_io_apdu_buffer[3] != 0x00)) {
        THROW(SW_COMMAND_NOT_ALLOWED);
        return 0;
      }
    }
    memmove(G_io_apdu_buffer, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, G_gpg_vstate.io_length);

    if (io_flags & IO_RETURN_AFTER_TX) {
      rx = gpg_io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, G_gpg_vstate.io_length);
      return 0;
    } else {
      rx = gpg_io_exchange(CHANNEL_APDU, G_gpg_vstate.io_length);
    }
  }

  //--- full in chaining ---
  if (rx < 4) {
    THROW(SW_COMMAND_NOT_ALLOWED);
    return SW_COMMAND_NOT_ALLOWED;
  }
  if (rx == 4) {
    G_io_apdu_buffer[4] = 0;
    rx                  = 4;
  }
  G_gpg_vstate.io_offset = 0;
  G_gpg_vstate.io_length = 0;
  G_gpg_vstate.io_cla    = G_io_apdu_buffer[0];
  G_gpg_vstate.io_ins    = G_io_apdu_buffer[1];
  G_gpg_vstate.io_p1     = G_io_apdu_buffer[2];
  G_gpg_vstate.io_p2     = G_io_apdu_buffer[3];
  G_gpg_vstate.io_lc     = 0;
  G_gpg_vstate.io_le     = 0;

  switch (G_gpg_vstate.io_ins) {
  case INS_GET_DATA:
  case INS_GET_RESPONSE:
  case INS_TERMINATE_DF:
  case INS_ACTIVATE_FILE:
    G_gpg_vstate.io_le = G_io_apdu_buffer[4];
    break;

  case INS_GET_CHALLENGE:
    if (G_gpg_vstate.io_p1 == 0) {
      G_gpg_vstate.io_le = G_io_apdu_buffer[4];
      break;
    }

  case INS_VERIFY:
  case INS_CHANGE_REFERENCE_DATA:
    if (G_io_apdu_buffer[4] == 0) {
      break;
    }
    goto _default;

  default:
  _default:
    G_gpg_vstate.io_lc = G_io_apdu_buffer[4];
    memmove(G_gpg_vstate.work.io_buffer, G_io_apdu_buffer + 5, G_gpg_vstate.io_lc);
    G_gpg_vstate.io_length = G_gpg_vstate.io_lc;
    break;
  }

  while (G_gpg_vstate.io_cla & 0x10) {
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    rx                  = gpg_io_exchange(CHANNEL_APDU, 2);
  in_chaining:
    if ((rx < 4) || ((G_io_apdu_buffer[0] & 0xEF) != (G_gpg_vstate.io_cla & 0xEF)) ||
        (G_io_apdu_buffer[1] != G_gpg_vstate.io_ins) || (G_io_apdu_buffer[2] != G_gpg_vstate.io_p1) ||
        (G_io_apdu_buffer[3] != G_gpg_vstate.io_p2)) {
      THROW(SW_COMMAND_NOT_ALLOWED);
      return SW_COMMAND_NOT_ALLOWED;
    }
    if (rx == 4) {
      G_io_apdu_buffer[4] = 0;
      rx                  = 4;
    }
    G_gpg_vstate.io_cla = G_io_apdu_buffer[0];
    G_gpg_vstate.io_lc  = G_io_apdu_buffer[4];
    if ((G_gpg_vstate.io_length + G_gpg_vstate.io_lc) > GPG_IO_BUFFER_LENGTH) {
      return 1;
    }
    memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_length, G_io_apdu_buffer + 5, G_gpg_vstate.io_lc);
    G_gpg_vstate.io_length += G_gpg_vstate.io_lc;
  }

  return 0;
}
