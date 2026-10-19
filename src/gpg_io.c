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
#include "offsets.h"
#include "ledger_assert.h"
#include "os_utils.h"
#include "buffer.h"

/*
 * io_buffer: contains current message part
 * io_offset: offset in current message part
 * io_length: length of current message part
 */

/* ----------------------------------------------------------------------- */
/* MISC                                                                    */
/* ----------------------------------------------------------------------- */

/**
 * Set Offset in APDU buffer
 *
 * @param[in]  offset value to set
 *
 */
void gpg_io_set_offset(unsigned int offset) {
    switch (offset) {
        case IO_OFFSET_END:
            G_gpg_vstate.io_offset = G_gpg_vstate.io_length;
            break;
        case IO_OFFSET_MARK:
            G_gpg_vstate.io_offset = G_gpg_vstate.io_mark;
            break;
        default:
            LEDGER_ASSERT(offset < G_gpg_vstate.io_length, "Bad offset!");
            G_gpg_vstate.io_offset = offset;
            break;
    }
}

/**
 * Mark current offset in APDU buffer
 *
 */
void gpg_io_mark() {
    G_gpg_vstate.io_mark = G_gpg_vstate.io_offset;
}

/**
 * Shift empty space in APDU buffer
 *
 * @param[in]  len space length
 *
 */
void gpg_io_inserted(unsigned int len) {
    G_gpg_vstate.io_offset += len;
    G_gpg_vstate.io_length += len;
}

/**
 * Discard APDU buffer values
 * Set Length, Offset and Mark to 0
 *
 * @param[in]  clear request to fully zeroed the buffer
 *
 */
void gpg_io_discard(int clear) {
    G_gpg_vstate.io_length = 0;
    G_gpg_vstate.io_offset = 0;
    G_gpg_vstate.io_mark = 0;
    if (clear) {
        gpg_io_clear();
    }
}

/**
 * Clear (zeroed) the APDU buffer
 *
 */
void gpg_io_clear() {
    explicit_bzero(G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
}

/* ----------------------------------------------------------------------- */
/* INSERT data to be sent                                                  */
/* ----------------------------------------------------------------------- */

/**
 * Move APDU buffer content after a hole
 *
 * @param[in]  sz hole length
 *
 */
static void gpg_io_hole(unsigned int sz) {
    LEDGER_ASSERT((G_gpg_vstate.io_length + sz) <= GPG_IO_BUFFER_LENGTH, "Bad hole!");
    LEDGER_ASSERT(G_gpg_vstate.io_offset <= G_gpg_vstate.io_length, "Bad offset in hole!");
    memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + sz,
            G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
            G_gpg_vstate.io_length - G_gpg_vstate.io_offset);
    G_gpg_vstate.io_length += sz;
}

/**
 * Insert a data buffer into the APDU buffer
 *
 * @param[in]  buff data buffer
 * @param[in]  len buffer length
 *
 */
void gpg_io_insert(unsigned char const *buff, unsigned int len) {
    gpg_io_hole(len);
    memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, buff, len);
    G_gpg_vstate.io_offset += len;
}

/**
 * Insert a u32 value into the APDU buffer
 *
 * @param[in]  v32 value to insert
 *
 */
void gpg_io_insert_u32(unsigned int v32) {
    gpg_io_hole(4);
    U4BE_ENCODE(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_offset, v32);
    G_gpg_vstate.io_offset += 4;
}

/**
 * Insert a u24 value into the APDU buffer
 *
 * @param[in]  v24 value to insert
 *
 */
void gpg_io_insert_u24(unsigned int v24) {
    gpg_io_hole(3);
    G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v24 >> 16;
    G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] = v24 >> 8;
    G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] = v24 >> 0;
    G_gpg_vstate.io_offset += 3;
}

/**
 * Insert a u16 value into the APDU buffer
 *
 * @param[in]  v16 value to insert
 *
 */
void gpg_io_insert_u16(unsigned int v16) {
    gpg_io_hole(2);
    U2BE_ENCODE(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_offset, v16);
    G_gpg_vstate.io_offset += 2;
}

/**
 * Insert a u8 value into the APDU buffer
 *
 * @param[in]  v8 value to insert
 *
 */
void gpg_io_insert_u8(unsigned int v8) {
    gpg_io_hole(1);
    G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] = v8;
    G_gpg_vstate.io_offset += 1;
}

/**
 * Insert a TAG into the APDU buffer
 * (To handle TLV)
 *
 * @param[in]  T tag to insert
 *
 */
void gpg_io_insert_t(unsigned int T) {
    if (T & 0xFF00) {
        gpg_io_insert_u16(T);
    } else {
        gpg_io_insert_u8(T);
    }
}

/**
 * Insert a TAG/LENGTH into the APDU buffer
 * (To handle TLV)
 *
 * @param[in]  T tag to insert
 * @param[in]  L length to insert
 *
 */
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

/**
 * Insert a TAG/LENGTH/VALUE into the APDU buffer
 * (To handle TLV)
 *
 * @param[in]  T tag to insert
 * @param[in]  L length to insert
 * @param[in]  V data to insert
 *
 */
void gpg_io_insert_tlv(unsigned int T, unsigned int L, unsigned char const *V) {
    gpg_io_insert_tl(T, L);
    gpg_io_insert(V, L);
}

/* ----------------------------------------------------------------------- */
/* FECTH data from received buffer                                         */
/* ----------------------------------------------------------------------- */

/**
 * Reader on the received data, positioned at the current offset
 *
 */
static buffer_t gpg_io_reader(void) {
    buffer_t in = buffer_create(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);

    LEDGER_ASSERT(G_gpg_vstate.io_offset <= G_gpg_vstate.io_length, "Bad offset in reader!");
    in.offset = G_gpg_vstate.io_offset;
    return in;
}

/**
 * Read a u32 value from the APDU buffer
 *
 * @param[out]  v32 value retrieved
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch_u32(unsigned int *v32) {
    buffer_t in = gpg_io_reader();
    uint32_t v;

    if (!buffer_read_u32(&in, &v, BE)) {
        return false;
    }
    *v32 = v;
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a u24 value from the APDU buffer
 *
 * @param[out]  v24 value retrieved
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch_u24(unsigned int *v24) {
    buffer_t in = gpg_io_reader();
    uint8_t hi;
    uint16_t lo;

    if (!buffer_can_read(&in, 3) || !buffer_read_u8(&in, &hi) || !buffer_read_u16(&in, &lo, BE)) {
        return false;
    }
    *v24 = (hi << 16) | lo;
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a u16 value from the APDU buffer
 *
 * @param[out]  v16 value retrieved
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch_u16(unsigned int *v16) {
    buffer_t in = gpg_io_reader();
    uint16_t v;

    if (!buffer_read_u16(&in, &v, BE)) {
        return false;
    }
    *v16 = v;
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a u8 value from the APDU buffer
 *
 * @param[out]  v8 value retrieved
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch_u8(unsigned int *v8) {
    buffer_t in = gpg_io_reader();
    uint8_t v;

    if (!buffer_read_u8(&in, &v)) {
        return false;
    }
    *v8 = v;
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a TAG from the APDU buffer
 * (To handle TLV)
 *
 * @param[out]  T read tag
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch_t(unsigned int *T) {
    buffer_t in = gpg_io_reader();
    uint8_t b;
    unsigned int tag;

    if (!buffer_read_u8(&in, &b)) {
        return false;
    }
    tag = b;
    if ((tag & 0x1F) == 0x1F) {
        if (!buffer_read_u8(&in, &b)) {
            return false;
        }
        tag = (tag << 8) | b;
    }
    *T = tag;
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a LENGTH from the APDU buffer, in short form or on 1 or 2 bytes
 * (To handle TLV)
 *
 * @param[out]  L read length
 *
 * @return  false if the buffer is too short or the encoding unsupported,
 *          the offset being left unchanged
 *
 */
bool gpg_io_fetch_l(unsigned int *L) {
    buffer_t in = gpg_io_reader();
    uint8_t b;
    uint16_t v;

    if (!buffer_read_u8(&in, &b)) {
        return false;
    }
    if (b < 0x80) {
        *L = b;
    } else if (b == 0x81) {
        if (!buffer_read_u8(&in, &b)) {
            return false;
        }
        *L = b;
    } else if (b == 0x82) {
        if (!buffer_read_u16(&in, &v, BE)) {
            return false;
        }
        *L = v;
    } else {
        return false;
    }
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Read a TAG/LENGTH from the APDU buffer
 * (To handle TLV)
 *
 * @param[out]  T read tag
 * @param[out]  L read length
 *
 * @return  false if the buffer is too short or the length encoding unsupported,
 *          the offset being left unchanged
 *
 */
bool gpg_io_fetch_tl(unsigned int *T, unsigned int *L) {
    unsigned int offset = G_gpg_vstate.io_offset;

    if (gpg_io_fetch_t(T) && gpg_io_fetch_l(L)) {
        return true;
    }
    G_gpg_vstate.io_offset = offset;
    return false;
}

/**
 * Read a buffer from the APDU buffer and write it in NVRam
 * (To handle TLV)
 *
 * @param[in]  buffer NVRAM address
 * @param[in]  len buffer length
 *
 * @return  false if the buffer is too short, nothing being written
 *
 */
bool gpg_io_fetch_nv(unsigned char *buffer, unsigned int len) {
    buffer_t in = gpg_io_reader();

    if (!buffer_can_read(&in, len)) {
        return false;
    }
    nvm_write(buffer, G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset, len);
    G_gpg_vstate.io_offset += len;
    return true;
}

/**
 * Read a buffer from the APDU buffer
 * (To handle TLV)
 *
 * @param[out]  buffer data buffer
 * @param[in]  len buffer length
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_fetch(unsigned char *buffer, unsigned int len) {
    buffer_t in = gpg_io_reader();

    if (!buffer_read_bytes(&in, buffer, len)) {
        return false;
    }
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/**
 * Skip bytes in the APDU buffer
 *
 * @param[in]  len number of bytes to skip
 *
 * @return  false if the buffer is too short, the offset being left unchanged
 *
 */
bool gpg_io_skip(unsigned int len) {
    buffer_t in = gpg_io_reader();

    if (!buffer_seek_cur(&in, len)) {
        return false;
    }
    G_gpg_vstate.io_offset = in.offset;
    return true;
}

/* ----------------------------------------------------------------------- */
/* REAL IO                                                                 */
/* ----------------------------------------------------------------------- */

#define MAX_OUT GPG_APDU_LENGTH

/**
 * Drop the command being received so that it is not dispatched
 *
 * @param[in]  sw status word to return to the host
 *
 * @return  sw
 *
 */
static unsigned int gpg_io_reject(unsigned int sw) {
    gpg_io_discard(1);
    G_gpg_vstate.io_cla = CLA_APP_DEF;
    G_gpg_vstate.io_ins = 0;
    G_gpg_vstate.io_p1 = 0;
    G_gpg_vstate.io_p2 = 0;
    G_gpg_vstate.io_p1p2 = 0;
    G_gpg_vstate.io_lc = 0;
    G_gpg_vstate.io_le = 0;
    return sw;
}

/**
 * Check that a received frame carries exactly the Lc bytes it announces,
 * optionally followed by a Le byte, or is a bare header without body
 *
 * @param[in]  rx received frame length
 *
 * @return  true if the frame length is consistent with Lc
 *
 */
static bool gpg_io_check_lc(unsigned int rx) {
    unsigned int expected = OFFSET_CDATA + G_io_apdu_buffer[OFFSET_LC];
    return (rx == OFFSET_LC) || (rx == expected) || (rx == expected + 1);
}

/**
 * APDU Receive/transmit
 *
 * @param[in]  flag io buffer flag
 *
 * @return  SWO_SUCCESS if a command is ready to be dispatched,
 *          otherwise the status word to return to the host
 *
 */
unsigned int gpg_io_do(unsigned int io_flags) {
    unsigned int rx = 0;

    if (io_flags & IO_ASYNCH_REPLY) {
        // if IO_ASYNCH_REPLY has been set,
        //  io_exchange will return when IO_RETURN_AFTER_TX will set in ui
        rx = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
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
            G_io_apdu_buffer[tx] = (SWO_RESPONSE_BYTES_AVAILABLE >> 8) & 0xFF;
            if (G_gpg_vstate.io_length > MAX_OUT) {
                xx = MAX_OUT - 2;
            } else {
                xx = G_gpg_vstate.io_length - 2;
            }
            G_io_apdu_buffer[tx + 1] = xx;
            rx = io_exchange(CHANNEL_APDU, tx + 2);
            // Any command other than GET RESPONSE drops the pending response
            if ((rx < 4) || (G_io_apdu_buffer[OFFSET_CLA] != CLA_APP_DEF) ||
                (G_io_apdu_buffer[OFFSET_INS] != INS_GET_RESPONSE) ||
                (G_io_apdu_buffer[OFFSET_P1] != GET_RESPONSE) ||
                (G_io_apdu_buffer[OFFSET_P2] != GET_RESPONSE)) {
                gpg_io_discard(1);
                break;
            }
            rx = 0;
        }
        if (rx == 0) {
            memmove(G_io_apdu_buffer,
                    G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                    G_gpg_vstate.io_length);

            if (io_flags & IO_RETURN_AFTER_TX) {
                io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, G_gpg_vstate.io_length);
                return SWO_SUCCESS;
            }
            rx = io_exchange(CHANNEL_APDU, G_gpg_vstate.io_length);
        } else if (io_flags & IO_RETURN_AFTER_TX) {
            return SWO_SUCCESS;
        }
    }

    //--- full in chaining ---
    if (rx < 4) {
        return gpg_io_reject(SWO_WRONG_LENGTH);
    }
    if (rx == 4) {
        G_io_apdu_buffer[OFFSET_LC] = 0;
    }
    G_gpg_vstate.io_offset = 0;
    G_gpg_vstate.io_length = 0;
    G_gpg_vstate.io_cla = G_io_apdu_buffer[OFFSET_CLA];
    G_gpg_vstate.io_ins = G_io_apdu_buffer[OFFSET_INS];
    G_gpg_vstate.io_p1 = G_io_apdu_buffer[OFFSET_P1];
    G_gpg_vstate.io_p2 = G_io_apdu_buffer[OFFSET_P2];
    G_gpg_vstate.io_lc = 0;
    G_gpg_vstate.io_le = 0;
    G_gpg_vstate.io_p1p2 = U2(G_gpg_vstate.io_p1, G_gpg_vstate.io_p2);

    switch (G_gpg_vstate.io_ins) {
        case INS_GET_DATA:
        case INS_GET_RESPONSE:
        case INS_TERMINATE_DF:
        case INS_ACTIVATE_FILE:
            G_gpg_vstate.io_le = G_io_apdu_buffer[OFFSET_LC];
            break;

        case INS_GET_CHALLENGE:
            if (G_gpg_vstate.io_p1 == CHALLENGE_NOMINAL) {
                G_gpg_vstate.io_le = G_io_apdu_buffer[OFFSET_LC];
                break;
            }

            __attribute__((fallthrough));
        case INS_VERIFY:
        case INS_CHANGE_REFERENCE_DATA:
            if (G_io_apdu_buffer[OFFSET_LC] == 0) {
                break;
            }
            if (!gpg_io_check_lc(rx)) {
                return gpg_io_reject(SWO_WRONG_LENGTH);
            }

            __attribute__((fallthrough));
        default:
            if (rx == OFFSET_CDATA) {
                // Case 2: the byte following the header is Le
                G_gpg_vstate.io_le = G_io_apdu_buffer[OFFSET_LC];
                break;
            }
            if (!gpg_io_check_lc(rx)) {
                return gpg_io_reject(SWO_WRONG_LENGTH);
            }
            G_gpg_vstate.io_lc = G_io_apdu_buffer[OFFSET_LC];
            memmove(G_gpg_vstate.work.io_buffer,
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_gpg_vstate.io_lc);
            G_gpg_vstate.io_length = G_gpg_vstate.io_lc;
            break;
    }

    PRINTF("[IO] - io_do: 1st APDU=0x %02x.%02x.%02x.%02x - %d (0x%x)\n",
           G_gpg_vstate.io_cla,
           G_gpg_vstate.io_ins,
           G_gpg_vstate.io_p1,
           G_gpg_vstate.io_p2,
           G_gpg_vstate.io_lc,
           G_gpg_vstate.io_lc);
    while (G_gpg_vstate.io_cla & CLA_APP_CHAIN) {
        G_io_apdu_buffer[0] = ((SWO_SUCCESS >> 8) & 0xFF);
        G_io_apdu_buffer[1] = (SWO_SUCCESS & 0xFF);
        rx = io_exchange(CHANNEL_APDU, 2);
        if (rx < 4) {
            return gpg_io_reject(SWO_WRONG_LENGTH);
        }
        if (((G_io_apdu_buffer[OFFSET_CLA] & CLA_APP_APDU_PIN) !=
             (G_gpg_vstate.io_cla & CLA_APP_APDU_PIN)) ||
            (G_io_apdu_buffer[OFFSET_INS] != G_gpg_vstate.io_ins) ||
            (G_io_apdu_buffer[OFFSET_P1] != G_gpg_vstate.io_p1) ||
            (G_io_apdu_buffer[OFFSET_P2] != G_gpg_vstate.io_p2)) {
            return gpg_io_reject(SWO_LAST_COMMAND_OF_CHAIN_EXPECTED);
        }
        if (rx == 4) {
            G_io_apdu_buffer[OFFSET_LC] = 0;
        } else if (!gpg_io_check_lc(rx)) {
            return gpg_io_reject(SWO_WRONG_LENGTH);
        }
        G_gpg_vstate.io_cla = G_io_apdu_buffer[OFFSET_CLA];
        G_gpg_vstate.io_lc = G_io_apdu_buffer[OFFSET_LC];
        if ((G_gpg_vstate.io_length + G_gpg_vstate.io_lc) > GPG_IO_BUFFER_LENGTH) {
            return gpg_io_reject(SWO_WRONG_LENGTH);
        }
        PRINTF("[IO] - io_do: Next APDU=0x %02x.%02x.%02x.%02x - %d (0x%x)\n",
               G_gpg_vstate.io_cla,
               G_gpg_vstate.io_ins,
               G_gpg_vstate.io_p1,
               G_gpg_vstate.io_p2,
               G_gpg_vstate.io_lc,
               G_gpg_vstate.io_lc);
        memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_length,
                G_io_apdu_buffer + OFFSET_CDATA,
                G_gpg_vstate.io_lc);
        G_gpg_vstate.io_length += G_gpg_vstate.io_lc;
    }
    return SWO_SUCCESS;
}
