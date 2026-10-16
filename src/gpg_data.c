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
#include "cx_errors.h"
#include "bip32.h"

/* Backup blob format version written by GET KEY DATA and expected by PUT KEY
 * DATA for the authenticated-encryption path.  Old blobs start with the
 * first byte of TARGET_ID (0x31 or 0x33 on Ledger devices), which is never
 * a version number, so the first byte alone is an unambiguous version discriminant. */
#define BACKUP_FORMAT_V1     ((unsigned char) 0x01)
#define BACKUP_FORMAT_V2     ((unsigned char) 0x02)
#define BACKUP_FORMAT_V3     ((unsigned char) 0x03)
#define GPG_BACKUP_TAG_LEN   16
#define GPG_BACKUP_NONCE_LEN 12

/* Largest cardholder certificate that can be read back with its status word */
#define GPG_CARD_HOLDER_CERT_MAX_LENGTH \
    MIN(GPG_EXT_CARD_HOLDER_CERT_LENTH, GPG_IO_BUFFER_LENGTH - 2)

/**
 * Select a DO (Data Object) in the current template
 *
 * @param[in] ref DO tag
 * @param[in] record Offset of the record
 *
 */
void gpg_apdu_select_data(unsigned int ref, int record) {
    G_gpg_vstate.DO_current = ref;
    G_gpg_vstate.DO_reccord = record;
    G_gpg_vstate.DO_offset = 0;
}

/**
 * Number of received bytes not yet fetched
 *
 */
static unsigned int gpg_key_data_left() {
    return G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
}

/**
 * Store the received data length as the length of a DO
 *
 * @param[out] length DO length in NVRAM
 *
 */
static void gpg_write_do_length(volatile unsigned int *length) {
    unsigned int len = G_gpg_vstate.io_length;

    nvm_write((void *) length, &len, sizeof(len));
}

static int gpg_put_key_data_v1_rsa(gpg_key_t *keygpg,
                                   cx_aes_gcm_context_t *gcm_ctx,
                                   unsigned char *nonce) {
    cx_err_t error = CX_INTERNAL_ERROR;
    unsigned int aad_len = 0;
    unsigned int enc_len = 0;
    unsigned int ct_len = 0;
    unsigned int ct_offset = 0;
    unsigned int len = 0;
    unsigned int ksz = 0;
    cx_rsa_private_key_t *key = NULL;
    unsigned char pub_e[sizeof(keygpg->pub_key.rsa)];

    if (gpg_key_data_left() < 4) {
        return SWO_WRONG_LENGTH;
    }
    len = gpg_io_fetch_u32();
    if (len != sizeof(pub_e)) {
        return SWO_INCORRECT_DATA;
    }
    // public key, then encrypted key length
    if (gpg_key_data_left() < len + 4) {
        return SWO_WRONG_LENGTH;
    }
    gpg_io_fetch(pub_e, len);
    aad_len = G_gpg_vstate.io_offset;

    enc_len = gpg_io_fetch_u32();
    if (enc_len <= GPG_BACKUP_TAG_LEN ||
        enc_len > G_gpg_vstate.io_length - G_gpg_vstate.io_offset) {
        return SWO_INCORRECT_DATA;
    }
    ct_len = enc_len - GPG_BACKUP_TAG_LEN;
    ct_offset = G_gpg_vstate.io_offset;

    ksz = U2BE(keygpg->attributes.value, 1) >> 3;
    switch (ksz) {
        case 2048 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa2048;
            len = sizeof(cx_rsa_2048_private_key_t);
            break;
        case 3072 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa3072;
            len = sizeof(cx_rsa_3072_private_key_t);
            break;
        case 4096 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa4096;
            len = sizeof(cx_rsa_4096_private_key_t);
            break;
        default:
            return SWO_INCORRECT_DATA;
    }

    if ((key == NULL) || (ct_len != len)) {
        return SWO_INCORRECT_DATA;
    }

    // Decrypt in-place: output to buffer[0], ciphertext at buffer[ct_offset].
    // GCM processes AAD (buffer[0..aad_len)) as a separate phase before
    // producing output, so overwriting the AAD region is safe.
    CX_CHECK(cx_aes_gcm_decrypt_and_auth(gcm_ctx,
                                         G_gpg_vstate.work.io_buffer + ct_offset,
                                         ct_len,
                                         nonce,
                                         GPG_BACKUP_NONCE_LEN,
                                         G_gpg_vstate.work.io_buffer,
                                         aad_len,
                                         G_gpg_vstate.work.io_buffer,
                                         G_gpg_vstate.work.io_buffer + ct_offset + ct_len,
                                         GPG_BACKUP_TAG_LEN));
    // the restored key must have the size of the key attributes
    if (((cx_rsa_private_key_t *) G_gpg_vstate.work.io_buffer)->size != ksz) {
        error = SWO_INCORRECT_DATA;
        goto end;
    }

    nvm_write((unsigned char *) key, G_gpg_vstate.work.io_buffer, len);
    nvm_write(keygpg->pub_key.rsa, pub_e, sizeof(pub_e));
    error = SWO_SUCCESS;
end:
    explicit_bzero(G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    return error;
}

static int gpg_put_key_data_v1_ec(gpg_key_t *keygpg,
                                  cx_aes_gcm_context_t *gcm_ctx,
                                  unsigned char *nonce) {
    cx_err_t error = CX_INTERNAL_ERROR;
    unsigned int aad_len = 0;
    unsigned int enc_len = 0;
    unsigned int ct_len = 0;
    unsigned int ct_offset = 0;
    unsigned int pub_offset = 0;
    unsigned int len = 0;
    unsigned char *priv = NULL;

    if (gpg_key_data_left() < 4) {
        return SWO_WRONG_LENGTH;
    }
    len = gpg_io_fetch_u32();
    if (len != sizeof(cx_ecfp_640_public_key_t)) {
        return SWO_INCORRECT_DATA;
    }
    // public key, then encrypted key length
    if (gpg_key_data_left() < len + 4) {
        return SWO_WRONG_LENGTH;
    }
    pub_offset = G_gpg_vstate.io_offset;
    gpg_io_fetch(NULL, len);
    G_gpg_vstate.io_offset += len;
    aad_len = G_gpg_vstate.io_offset;

    enc_len = gpg_io_fetch_u32();
    if (enc_len <= GPG_BACKUP_TAG_LEN ||
        enc_len > G_gpg_vstate.io_length - G_gpg_vstate.io_offset) {
        return SWO_INCORRECT_DATA;
    }
    ct_len = enc_len - GPG_BACKUP_TAG_LEN;
    ct_offset = G_gpg_vstate.io_offset;

    if (ct_len != sizeof(cx_ecfp_640_private_key_t)) {
        return SWO_INCORRECT_DATA;
    }
    // Decrypt past the blob so that the authenticated public key stays in place
    if ((ct_offset + enc_len + ct_len) > GPG_IO_BUFFER_LENGTH) {
        return SWO_WRONG_LENGTH;
    }
    priv = G_gpg_vstate.work.io_buffer + ct_offset + enc_len;

    CX_CHECK(cx_aes_gcm_decrypt_and_auth(gcm_ctx,
                                         G_gpg_vstate.work.io_buffer + ct_offset,
                                         ct_len,
                                         nonce,
                                         GPG_BACKUP_NONCE_LEN,
                                         G_gpg_vstate.work.io_buffer,
                                         aad_len,
                                         priv,
                                         G_gpg_vstate.work.io_buffer + ct_offset + ct_len,
                                         GPG_BACKUP_TAG_LEN));

    nvm_write((unsigned char *) &keygpg->priv_key.ecfp640, priv, ct_len);
    nvm_write((unsigned char *) &keygpg->pub_key.ecfp640,
              G_gpg_vstate.work.io_buffer + pub_offset,
              sizeof(cx_ecfp_640_public_key_t));
    error = SWO_SUCCESS;
end:
    explicit_bzero(G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    return error;
}

/**
 * Read a DO (Data Object) from the card
 *
 * @param[in] ref DO tag
 *
 * @return Status Word
 *
 */
int gpg_apdu_get_data(unsigned int ref) {
    int sw = SWO_UNKNOWN;

    if (G_gpg_vstate.DO_current != ref) {
        G_gpg_vstate.DO_current = ref;
        G_gpg_vstate.DO_reccord = 0;
        G_gpg_vstate.DO_offset = 0;
    }
    sw = SWO_SUCCESS;

    gpg_io_discard(1);
    switch (ref) {
            /* ----------------- Optional DO for private use ----------------- */
        case 0x0101:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->private_DO1.value,
                          N_gpg_pstate->private_DO1.length);
            break;
        case 0x0102:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->private_DO2.value,
                          N_gpg_pstate->private_DO2.length);
            break;
        case 0x0103:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->private_DO3.value,
                          N_gpg_pstate->private_DO3.length);
            break;
        case 0x0104:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->private_DO4.value,
                          N_gpg_pstate->private_DO4.length);
            break;

            /* ----------------- Config key slot ----------------- */
        case 0x01F0:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->config_slot, 3);
            gpg_io_insert_u8(G_gpg_vstate.slot);
            break;
        case 0x01F1:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->config_slot, 3);
            break;
        case 0x01F2:
            gpg_io_insert_u8(G_gpg_vstate.slot);
            break;
            /* ----------------- Config RSA exponent ----------------- */
        case 0x01F8:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->default_RSA_exponent, 4);
            break;

            /* ----------------- Application ----------------- */
        case 0x004F:
            /*  Full Application identifier */
            gpg_io_insert((const unsigned char *) N_gpg_pstate->AID, 10);
            gpg_io_insert(G_gpg_vstate.kslot->serial, 4);
            gpg_io_insert_u16(0x0000);
            break;
        case 0x5F52:
            /* Historical bytes */
            gpg_io_insert((const unsigned char *) N_gpg_pstate->histo, HISTO_LENGTH);
            break;
        case 0x7F66:
            /* Extended length information */
            gpg_io_insert(C_ext_length, sizeof(C_ext_length));
            break;

            /* ----------------- User -----------------*/
        case 0x005E:
            /* Login data */
            gpg_io_insert((const unsigned char *) N_gpg_pstate->login.value,
                          N_gpg_pstate->login.length);
            break;
        case 0x5F50:
            /* Uniform resource locator */
            gpg_io_insert((const unsigned char *) N_gpg_pstate->keys[G_gpg_vstate.slot].url.value,
                          N_gpg_pstate->keys[G_gpg_vstate.slot].url.length);
            break;
        case 0x65:
            /* Name, Language, salutation */
            gpg_io_insert_tlv(0x5B,
                              N_gpg_pstate->name.length,
                              (const unsigned char *) N_gpg_pstate->name.value);
            gpg_io_insert_tlv(0x5F2D,
                              N_gpg_pstate->lang.length,
                              (const unsigned char *) N_gpg_pstate->lang.value);
            gpg_io_insert_tlv(0x5F35, 1, (const unsigned char *) N_gpg_pstate->salutation);
            break;

            /* ----------------- aid, histo, ext_length, ... ----------------- */
        case 0x6E:
            gpg_io_insert_tlv(0x4F, AID_LENGTH, (const unsigned char *) N_gpg_pstate->AID);
            memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset - 6,
                    G_gpg_vstate.kslot->serial,
                    4);
#ifdef WITH_HISTO_BYTES_IN_ARD
            gpg_io_insert_tlv(0x5F52, HISTO_LENGTH, (const unsigned char *) N_gpg_pstate->histo);
#endif
            gpg_io_insert_tlv(0x7F66, sizeof(C_ext_length), C_ext_length);

            gpg_io_mark();

            gpg_io_insert_tlv(0xC0, sizeof(C_ext_capabilities), C_ext_capabilities);
            gpg_io_insert_tlv(0xC1,
                              G_gpg_vstate.kslot->sig.attributes.length,
                              G_gpg_vstate.kslot->sig.attributes.value);
            gpg_io_insert_tlv(0xC2,
                              G_gpg_vstate.kslot->dec.attributes.length,
                              G_gpg_vstate.kslot->dec.attributes.value);
            gpg_io_insert_tlv(0xC3,
                              G_gpg_vstate.kslot->aut.attributes.length,
                              G_gpg_vstate.kslot->aut.attributes.value);
            gpg_io_insert_tl(0xC4, 7);
            gpg_io_insert((const unsigned char *) N_gpg_pstate->PW_status, 4);
            gpg_io_insert_u8(N_gpg_pstate->PW1.counter);
            gpg_io_insert_u8(N_gpg_pstate->RC.counter);
            gpg_io_insert_u8(N_gpg_pstate->PW3.counter);
            gpg_io_insert_tl(0xC5, 60);
            gpg_io_insert(G_gpg_vstate.kslot->sig.fingerprints, 20);
            gpg_io_insert(G_gpg_vstate.kslot->dec.fingerprints, 20);
            gpg_io_insert(G_gpg_vstate.kslot->aut.fingerprints, 20);
            gpg_io_insert_tl(0xC6, 60);
            gpg_io_insert(G_gpg_vstate.kslot->sig.CA_fingerprints, 20);
            gpg_io_insert(G_gpg_vstate.kslot->dec.CA_fingerprints, 20);
            gpg_io_insert(G_gpg_vstate.kslot->aut.CA_fingerprints, 20);
            gpg_io_insert_tl(0xCD, 12);
            gpg_io_insert(G_gpg_vstate.kslot->sig.date, 4);
            gpg_io_insert(G_gpg_vstate.kslot->dec.date, 4);
            gpg_io_insert(G_gpg_vstate.kslot->aut.date, 4);
            gpg_io_set_offset(IO_OFFSET_MARK);
            gpg_io_insert_tl(0x73, G_gpg_vstate.io_length - G_gpg_vstate.io_offset);
            gpg_io_set_offset(IO_OFFSET_END);
            break;

            /* ----------------- User Interaction Flag (UIF) for PSO:CDS ----------------- */
        case 0x00D6:
            gpg_io_insert(G_gpg_vstate.kslot->sig.UIF, 2);
            break;
        case 0x00D7:
            gpg_io_insert(G_gpg_vstate.kslot->dec.UIF, 2);
            break;
        case 0x00D8:
            gpg_io_insert(G_gpg_vstate.kslot->aut.UIF, 2);
            break;

            /* ----------------- Security support template ----------------- */
        case 0x7A:
            gpg_io_insert_tl(0x93, 3);
            gpg_io_insert_u24(G_gpg_vstate.kslot->sig_count);
            break;

            /* ----------------- Cardholder certificate ----------------- */
        case 0x7F21:
            switch (G_gpg_vstate.DO_reccord) {
                case 0:
                    gpg_io_insert(G_gpg_vstate.kslot->aut.CA.value,
                                  G_gpg_vstate.kslot->aut.CA.length);
                    break;
                case 1:
                    gpg_io_insert(G_gpg_vstate.kslot->dec.CA.value,
                                  G_gpg_vstate.kslot->dec.CA.length);
                    break;
                case 2:
                    gpg_io_insert(G_gpg_vstate.kslot->sig.CA.value,
                                  G_gpg_vstate.kslot->sig.CA.length);
                    break;
                default:
                    sw = SWO_FILE_NOT_FOUND;
            }
            break;

            /* ----------------- PW Status Bytes ----------------- */
        case 0x00C4:
            gpg_io_insert((const unsigned char *) N_gpg_pstate->PW_status, 4);
            gpg_io_insert_u8(N_gpg_pstate->PW1.counter);
            gpg_io_insert_u8(N_gpg_pstate->RC.counter);
            gpg_io_insert_u8(N_gpg_pstate->PW3.counter);
            break;

            /* ----------------- General Feature management ----------------- */
        case 0x7F74:
            gpg_io_insert_u8(C_gen_feature);
            break;

        default:
            /* WAT */
            sw = SWO_REFERENCED_DATA_NOT_FOUND;
            break;
    }

    return sw;
}

/**
 * Read the next instance of the same DO (Data Object) from the card
 *
 * @param[in] ref DO tag
 *
 * @return Status Word
 *
 */
int gpg_apdu_get_next_data(unsigned int ref) {
    int sw = SWO_UNKNOWN;

    if ((ref != 0x7F21) || (G_gpg_vstate.DO_current != 0x7F21)) {
        return SWO_CONDITIONS_NOT_SATISFIED;
    }
    // read the occurrence following the current one, and stay on it only if it exists
    G_gpg_vstate.DO_reccord++;
    sw = gpg_apdu_get_data(ref);
    if (sw != SWO_SUCCESS) {
        G_gpg_vstate.DO_reccord--;
    }
    return sw;
}

/**
 * Make a slot the active one, with its default security environment
 *
 * @param[in] slot slot index
 *
 * @return Status Word
 *
 */
int gpg_select_slot(unsigned int slot) {
    if (slot >= GPG_KEYS_SLOTS) {
        return SWO_INCORRECT_DATA;
    }
    G_gpg_vstate.slot = slot;
    G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[G_gpg_vstate.slot];
    gpg_mse_reset();
    return SWO_SUCCESS;
}

/**
 * Write a DO (Data Object) to the card
 *
 * @param[in] ref DO tag
 *
 * @return Status Word
 *
 */
int gpg_apdu_put_data(unsigned int ref) {
    unsigned int t, l, sw;
    unsigned int *ptr_l = NULL;
    unsigned char *ptr_v = NULL;
    gpg_key_t *ptr_key = NULL;
    void *pkey = NULL;
    cx_aes_key_t aes_key = {0};
    cx_err_t error = CX_INTERNAL_ERROR;
    unsigned int pkey_size = 0;
    unsigned int ksz, curve;

    G_gpg_vstate.DO_current = ref;

    switch (ref) {
            /*  ----------------- Optional DO for private use ----------------- */
        case 0x0101:
            ptr_l = (unsigned int *) &N_gpg_pstate->private_DO1.length;
            ptr_v = (unsigned char *) N_gpg_pstate->private_DO1.value;
            goto WRITE_PRIVATE_DO;
        case 0x0102:
            ptr_l = (unsigned int *) &N_gpg_pstate->private_DO2.length;
            ptr_v = (unsigned char *) N_gpg_pstate->private_DO2.value;
            goto WRITE_PRIVATE_DO;
        case 0x0103:
            ptr_l = (unsigned int *) &N_gpg_pstate->private_DO3.length;
            ptr_v = (unsigned char *) N_gpg_pstate->private_DO3.value;
            goto WRITE_PRIVATE_DO;
        case 0x0104:
            ptr_l = (unsigned int *) &N_gpg_pstate->private_DO4.length;
            ptr_v = (unsigned char *) N_gpg_pstate->private_DO4.value;
            goto WRITE_PRIVATE_DO;
        WRITE_PRIVATE_DO:
            if (G_gpg_vstate.io_length > GPG_EXT_PRIVATE_DO_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v,
                      G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                      G_gpg_vstate.io_length);
            gpg_write_do_length(ptr_l);
            sw = SWO_SUCCESS;
            break;
            /*  ----------------- Config key slot ----------------- */
        case 0x01F1:
            if (G_gpg_vstate.io_length != 3) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            if ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] != GPG_KEYS_SLOTS) ||
                (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] >= GPG_KEYS_SLOTS) ||
                (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] > 3)) {
                sw = SWO_INCORRECT_DATA;
                break;
            }
            nvm_write((void *) N_gpg_pstate->config_slot,
                      G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                      3);
            sw = SWO_SUCCESS;
            // show or hide the slot selection of the home screen
            ui_init();
            break;

        case 0x01F2:
            if ((N_gpg_pstate->config_slot[2] & SLOT_SELECT_APDU) == 0) {
                sw = SWO_CONDITIONS_NOT_SATISFIED;
                break;
            }
            if (G_gpg_vstate.io_length != 1) {
                sw = SWO_INCORRECT_DATA;
                break;
            }
            sw = gpg_select_slot(G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset]);
            if (sw == SWO_SUCCESS) {
                // leave any settings page bound to the previous slot, and show the new one
                ui_init();
            }
            break;

        /* ----------------- Config RSA exponent ----------------- */
        case 0x01F8: {
            unsigned int e;
            if (G_gpg_vstate.io_length != 4) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            // stored in native byte order, then read back big-endian by key generation
            e = gpg_io_fetch_u32();
            if (!gpg_rsa_exponent_is_valid((const unsigned char *) &e)) {
                sw = SWO_INCORRECT_DATA;
                break;
            }
            nvm_write((void *) &N_gpg_pstate->default_RSA_exponent, &e, sizeof(unsigned int));
            sw = SWO_SUCCESS;
            break;
        }

            /* ----------------- Serial -----------------*/
        case 0x4f:
            if (G_gpg_vstate.io_length != 4) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write(G_gpg_vstate.kslot->serial,
                      &G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset],
                      4);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- Extended Header list -----------------*/
        case 0x3FFF: {
            unsigned int len_e, len_p, len_q;
            unsigned int endof, reset_cnt;
            gpg_key_t *keygpg = NULL;
            // fecth 4D
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x4D) {
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            // fecth B8/B6/A4
            gpg_io_fetch_tl(&t, &l);
            reset_cnt = 0;
            switch (t) {
                case KEY_SIG:
                    keygpg = &G_gpg_vstate.kslot->sig;
                    reset_cnt = 0x11111111;
                    break;
                case KEY_AUT:
                    keygpg = &G_gpg_vstate.kslot->aut;
                    break;
                case KEY_DEC:
                    keygpg = &G_gpg_vstate.kslot->dec;
                    break;
                default:
                    break;
            }
            if (keygpg == NULL) {
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            // fecth 7f78
            gpg_io_fetch_tl(&t, &l);
            if ((t != 0x7f48) || (l > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset))) {
                sw = SWO_INCORRECT_DATA;
                break;
            }
            len_e = 0;
            len_p = 0;
            len_q = 0;
            endof = G_gpg_vstate.io_offset + l;
            while (G_gpg_vstate.io_offset < endof) {
                gpg_io_fetch_tl(&t, &l);
                if (G_gpg_vstate.io_offset > endof) {
                    return SWO_INCORRECT_DATA;
                }
                switch (t) {
                    case 0x91:
                        len_e = l;
                        break;
                    case 0x92:
                        len_p = l;
                        break;
                    case 0x93:
                        len_q = l;
                        break;
                    case 0x94:
                    case 0x95:
                    case 0x96:
                    case 0x97:
                    case 0x99:
                        break;
                    default:
                        return SWO_REFERENCED_DATA_NOT_FOUND;
                }
            }
            // fecth 5f78
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x5f48) {
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            if (l > (unsigned int) (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
                sw = SWO_INCORRECT_DATA;
                break;
            }

            if (keygpg->attributes.value[0] == KEY_ID_RSA) {
                unsigned int e = 0;
                unsigned char *p, *q, *pq;
                cx_rsa_public_key_t *rsa_pub;
                cx_rsa_private_key_t *rsa_priv;
                // check length
                ksz = U2BE(keygpg->attributes.value, 1) >> 3;
                rsa_pub = (cx_rsa_public_key_t *) &G_gpg_vstate.work.rsa.public;
                rsa_priv = (cx_rsa_private_key_t *) &G_gpg_vstate.work.rsa.private;
                switch (ksz) {
                    case 2048 / 8:
                        pkey_size = sizeof(cx_rsa_2048_private_key_t);
                        pq = G_gpg_vstate.work.rsa.public2048.n;
                        break;
                    case 3072 / 8:
                        pkey_size = sizeof(cx_rsa_3072_private_key_t);
                        pq = G_gpg_vstate.work.rsa.public3072.n;
                        break;
                    case 4096 / 8:
                        pkey_size = sizeof(cx_rsa_4096_private_key_t);
                        pq = G_gpg_vstate.work.rsa.public4096.n;
                        break;
                    default:
                        break;
                }
                if (pkey_size == 0) {
                    sw = SWO_INCORRECT_DATA;
                    break;
                }
                ksz = ksz >> 1;

                // fetch e
                switch (len_e) {
                    case 4:
                        e = gpg_io_fetch_u32();
                        break;
                    case 3:
                        e = gpg_io_fetch_u24();
                        break;
                    case 2:
                        e = gpg_io_fetch_u16();
                        break;
                    case 1:
                        e = gpg_io_fetch_u8();
                        break;
                    default:
                        break;
                }
                if (e == 0) {
                    sw = SWO_INCORRECT_DATA;
                    break;
                }

                // move p,q over pub key, this only work because adr<rsa_pub> < adr<p>
                if ((len_p > ksz) || (len_q > ksz) || ((len_e + len_p + len_q) > l)) {
                    sw = SWO_INCORRECT_DATA;
                    break;
                }
                p = G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset;
                q = p + len_p;
                memmove(pq + ksz - len_p, p, len_p);
                explicit_bzero(pq, ksz - len_p);
                memmove(pq + 2 * ksz - len_q, q, len_q);
                explicit_bzero(pq + ksz, ksz - len_q);

                // regenerate RSA private key
                unsigned char _e[4];
                U4BE_ENCODE(_e, 0, e);
                CX_CHECK(cx_rsa_generate_pair_no_throw(ksz << 1, rsa_pub, rsa_priv, _e, 4, pq));

                // write keys
                nvm_write(&keygpg->pub_key.rsa, rsa_pub->e, 4);
                nvm_write(&keygpg->priv_key.rsa, rsa_priv, pkey_size);
                if (reset_cnt) {
                    reset_cnt = 0;
                    nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
                }
                sw = SWO_SUCCESS;
            } else if ((keygpg->attributes.value[0] == KEY_ID_ECDH) ||
                       (keygpg->attributes.value[0] == KEY_ID_ECDSA) ||
                       (keygpg->attributes.value[0] == KEY_ID_EDDSA)) {
                curve = gpg_attributes2curve(keygpg->attributes.value, keygpg->attributes.length);
                if (curve == CX_CURVE_NONE) {
                    sw = SWO_INCORRECT_DATA;
                    break;
                }
                ksz = gpg_curve2domainlen(curve);
                if ((len_p == 0) || (len_p > ksz) || (len_p > l)) {
                    sw = SWO_INCORRECT_DATA;
                    break;
                }
                // The private key may come without its leading zero bytes
                G_gpg_vstate.work.ecfp.private.curve = curve;
                G_gpg_vstate.work.ecfp.private.d_len = ksz;
                explicit_bzero(G_gpg_vstate.work.ecfp.private.d, ksz - len_p);
                memmove(G_gpg_vstate.work.ecfp.private.d + ksz - len_p,
                        G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                        len_p);
                CX_CHECK(cx_ecfp_generate_pair_no_throw(curve,
                                                        &G_gpg_vstate.work.ecfp.public,
                                                        &G_gpg_vstate.work.ecfp.private,
                                                        1));
                nvm_write(&keygpg->pub_key.ecfp,
                          &G_gpg_vstate.work.ecfp.public,
                          sizeof(cx_ecfp_public_key_t));
                nvm_write(&keygpg->priv_key.ecfp,
                          &G_gpg_vstate.work.ecfp.private,
                          sizeof(cx_ecfp_private_key_t));
                if (reset_cnt) {
                    reset_cnt = 0;
                    nvm_write(&G_gpg_vstate.kslot->sig_count, &reset_cnt, sizeof(unsigned int));
                }
                sw = SWO_SUCCESS;
            }
            // --- UNSUPPORTED KEY ---
            else {
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
            }
            break;
        }  // endof of 3fff

            /* ----------------- User -----------------*/
            /* Name */
        case 0x5B:
            if (G_gpg_vstate.io_length > GPG_NAME_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->name.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            gpg_write_do_length(&N_gpg_pstate->name.length);
            sw = SWO_SUCCESS;
            break;
            /* Login data */
        case 0x5E:
            if (G_gpg_vstate.io_length > GPG_EXT_PRIVATE_DO_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->login.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            gpg_write_do_length(&N_gpg_pstate->login.length);
            sw = SWO_SUCCESS;
            break;
            /* Language preferences */
        case 0x5F2D:
            if (G_gpg_vstate.io_length > GPG_LANG_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->lang.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            gpg_write_do_length(&N_gpg_pstate->lang.length);
            sw = SWO_SUCCESS;
            break;
            /* salutation */
        case 0x5F35:
            if (G_gpg_vstate.io_length != GPG_SALUTATION_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->salutation,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            sw = SWO_SUCCESS;
            break;
            /* Uniform resource locator */
        case 0x5F50:
            if (G_gpg_vstate.io_length > GPG_EXT_PRIVATE_DO_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->keys[G_gpg_vstate.slot].url.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            gpg_write_do_length(&N_gpg_pstate->keys[G_gpg_vstate.slot].url.length);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- Cardholder certificate ----------------- */
        case 0x7F21:
            ptr_v = NULL;
            switch (G_gpg_vstate.DO_reccord) {
                case 0:
                    ptr_l = &G_gpg_vstate.kslot->aut.CA.length;
                    ptr_v = G_gpg_vstate.kslot->aut.CA.value;
                    break;
                case 1:
                    ptr_l = &G_gpg_vstate.kslot->dec.CA.length;
                    ptr_v = G_gpg_vstate.kslot->dec.CA.value;
                    break;
                case 2:
                    ptr_l = &G_gpg_vstate.kslot->sig.CA.length;
                    ptr_v = G_gpg_vstate.kslot->sig.CA.value;
                    break;
                default:
                    break;
            }
            if (ptr_v == NULL) {
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            if (G_gpg_vstate.io_length > GPG_CARD_HOLDER_CERT_MAX_LENGTH) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
            gpg_write_do_length(ptr_l);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- Algorithm attributes ----------------- */
        case 0xC1:
            ptr_l = &G_gpg_vstate.kslot->sig.attributes.length;
            ptr_v = G_gpg_vstate.kslot->sig.attributes.value;
            ptr_key = &G_gpg_vstate.kslot->sig;
            goto WRITE_ATTRIBUTES;
        case 0xC2:
            ptr_l = &G_gpg_vstate.kslot->dec.attributes.length;
            ptr_v = G_gpg_vstate.kslot->dec.attributes.value;
            ptr_key = &G_gpg_vstate.kslot->dec;
            goto WRITE_ATTRIBUTES;
        case 0xC3:
            ptr_l = &G_gpg_vstate.kslot->aut.attributes.length;
            ptr_v = G_gpg_vstate.kslot->aut.attributes.value;
            ptr_key = &G_gpg_vstate.kslot->aut;
            goto WRITE_ATTRIBUTES;
        WRITE_ATTRIBUTES:
            if ((G_gpg_vstate.io_length < 1) ||
                (G_gpg_vstate.io_length > GPG_KEY_ATTRIBUTES_LENGTH)) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            switch (G_gpg_vstate.work.io_buffer[0]) {
                case KEY_ID_RSA:
                    // Algorithm id, then the modulus size
                    if (G_gpg_vstate.io_length < 3) {
                        sw = SWO_WRONG_LENGTH;
                        break;
                    }
                    ksz = U2BE(G_gpg_vstate.work.io_buffer, 1);
                    if ((ksz != 2048) && (ksz != 3072) && (ksz != 4096)) {
                        sw = SWO_INCORRECT_DATA;
                    } else {
                        sw = SWO_SUCCESS;
                    }
                    break;
                case KEY_ID_ECDH:
                case KEY_ID_ECDSA:
                case KEY_ID_EDDSA:
                    curve =
                        gpg_attributes2curve(G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
                    if (curve == CX_CURVE_NONE) {
                        sw = SWO_INCORRECT_DATA;
                    } else {
                        sw = SWO_SUCCESS;
                    }
                    break;
                default:
                    sw = SWO_INCORRECT_DATA;
                    break;
            }

            if (sw == SWO_SUCCESS) {
                gpg_key_erase(ptr_key);
                nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
                gpg_write_do_length(ptr_l);
            }
            break;

            /* ----------------- PWS status ----------------- */
        case 0xC4:
            if (G_gpg_vstate.io_length < 1) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            gpg_io_fetch_nv((unsigned char *) N_gpg_pstate->PW_status, 1);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- Fingerprints ----------------- */
        case 0xC7:
            ptr_v = G_gpg_vstate.kslot->sig.fingerprints;
            goto WRITE_FINGERPRINTS;
        case 0xC8:
            ptr_v = G_gpg_vstate.kslot->dec.fingerprints;
            goto WRITE_FINGERPRINTS;
        case 0xC9:
            ptr_v = G_gpg_vstate.kslot->aut.fingerprints;
            goto WRITE_FINGERPRINTS;
        case 0xCA:
            ptr_v = G_gpg_vstate.kslot->sig.CA_fingerprints;
            goto WRITE_FINGERPRINTS;
        case 0xCB:
            ptr_v = G_gpg_vstate.kslot->dec.CA_fingerprints;
            goto WRITE_FINGERPRINTS;
        case 0xCC:
            ptr_v = G_gpg_vstate.kslot->aut.CA_fingerprints;
            goto WRITE_FINGERPRINTS;
        WRITE_FINGERPRINTS:
            if (G_gpg_vstate.io_length != 20) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 20);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- Generation date/time ----------------- */
        case 0xCE:
            ptr_v = G_gpg_vstate.kslot->sig.date;
            goto WRITE_DATE;
        case 0xCF:
            ptr_v = G_gpg_vstate.kslot->dec.date;
            goto WRITE_DATE;
        case 0xD0:
            ptr_v = G_gpg_vstate.kslot->aut.date;
            goto WRITE_DATE;
        WRITE_DATE:
            if (G_gpg_vstate.io_length != 4) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 4);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- AES key ----------------- */
        case 0xD1:
            pkey = (void *) &N_gpg_pstate->SM_enc;
            goto init_aes_key;
        case 0xD2:
            pkey = (void *) &N_gpg_pstate->SM_mac;
            goto init_aes_key;
        case 0xD5:
            pkey = &G_gpg_vstate.kslot->AES_dec;
            goto init_aes_key;
        init_aes_key:
            CX_CHECK(cx_aes_init_key_no_throw(G_gpg_vstate.work.io_buffer,
                                              G_gpg_vstate.io_length,
                                              &aes_key));
            nvm_write(pkey, &aes_key, sizeof(cx_aes_key_t));
            sw = SWO_SUCCESS;
            break;

            /* AES key: one shot */
        case 0xF4:
            if (G_gpg_vstate.io_length != 2 * CX_AES_128_KEY_LEN) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            CX_CHECK(cx_aes_init_key_no_throw(G_gpg_vstate.work.io_buffer,
                                              CX_AES_128_KEY_LEN,
                                              &aes_key));
            nvm_write((void *) &N_gpg_pstate->SM_enc, &aes_key, sizeof(cx_aes_key_t));
            CX_CHECK(cx_aes_init_key_no_throw(G_gpg_vstate.work.io_buffer + CX_AES_128_KEY_LEN,
                                              CX_AES_128_KEY_LEN,
                                              &aes_key));
            nvm_write((void *) &N_gpg_pstate->SM_mac, &aes_key, sizeof(cx_aes_key_t));
            sw = SWO_SUCCESS;
            break;

            /* ----------------- RC ----------------- */
        case 0xD3: {
            gpg_pin_t *pin;

            pin = gpg_pin_get_pin(PIN_ID_RC);
            if (G_gpg_vstate.io_length == 0) {
                nvm_write(pin, NULL, sizeof(gpg_pin_t));
                sw = SWO_SUCCESS;
            } else if ((G_gpg_vstate.io_length > GPG_MAX_PW_LENGTH) ||
                       (G_gpg_vstate.io_length < 8)) {
                sw = SWO_INCORRECT_DATA;
            } else {
                sw = gpg_pin_set(pin,
                                 G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                 G_gpg_vstate.io_length);
            }
            break;
        }

            /* ----------------- UIF ----------------- */
        case 0xD6:
            ptr_v = G_gpg_vstate.kslot->sig.UIF;
            goto WRITE_UIF;
        case 0xD7:
            ptr_v = G_gpg_vstate.kslot->dec.UIF;
            goto WRITE_UIF;
        case 0xD8:
            ptr_v = G_gpg_vstate.kslot->aut.UIF;
            goto WRITE_UIF;
        WRITE_UIF:
            if (G_gpg_vstate.io_length != 2) {
                sw = SWO_WRONG_LENGTH;
                break;
            }
            // a permanently enabled UIF can only be cleared by a card reset
            if ((ptr_v[0] == 2) && (G_gpg_vstate.work.io_buffer[0] != 2)) {
                sw = SWO_CONDITIONS_NOT_SATISFIED;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 2);
            sw = SWO_SUCCESS;
            break;

            /* ----------------- WAT ----------------- */
        default:
            sw = SWO_REFERENCED_DATA_NOT_FOUND;
            break;
    }

    gpg_io_discard(1);
    return sw;
end:
    return error;
}

/**
 * Init an encryption key to protect Private Key
 * Used for Backup/Restore
 *
 * @param[out] keyenc aes encryption key
 *
 * @return Status Word
 *
 */
static int gpg_init_keyenc(cx_aes_key_t *keyenc) {
    int sw = SWO_UNKNOWN;
    unsigned char seed[32];
    cx_err_t error = CX_INTERNAL_ERROR;

    sw = gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
    if (sw != SWO_SUCCESS) {
        error = sw;
        goto end;
    }
    sw = gpg_pso_derive_key_seed(seed, (unsigned char *) PIC("key "), 1, seed, CX_AES_BLOCK_SIZE);
    if (sw != SWO_SUCCESS) {
        error = sw;
        goto end;
    }
    CX_CHECK(cx_aes_init_key_no_throw(seed, CX_AES_BLOCK_SIZE, keyenc));
    error = SWO_SUCCESS;
end:
    explicit_bzero(seed, sizeof(seed));
    return error;
}

/* Initialise an AES-GCM context with the slot-derived backup key of the given format.
 * From v3, the key comes from the hardened slot seed of the v2 seeded keys.
 * The raw key bytes are wiped from the stack before returning. */
static int gpg_init_gcm(cx_aes_gcm_context_t *ctx, unsigned char version) {
    unsigned char seed[32];
    cx_err_t error = CX_INTERNAL_ERROR;
    unsigned int slot = G_gpg_vstate.slot;
    int sw;

    if (version == BACKUP_FORMAT_V3) {
        slot |= BIP32_HARDENED_MASK;
    }
    sw = gpg_pso_derive_slot_seed(slot, seed);
    if (sw != SWO_SUCCESS) {
        error = sw;
        goto end;
    }
    if (version == BACKUP_FORMAT_V1) {
        sw = gpg_pso_derive_key_seed(seed,
                                     (unsigned char *) PIC("key "),
                                     1,
                                     seed,
                                     CX_AES_BLOCK_SIZE);
    } else {
        sw = gpg_pso_derive_key_seed_full(seed,
                                          (unsigned char *) PIC("key "),
                                          1,
                                          seed,
                                          CX_AES_BLOCK_SIZE);
    }
    if (sw != SWO_SUCCESS) {
        error = sw;
        goto end;
    }
    cx_aes_gcm_init(ctx);
    CX_CHECK(cx_aes_gcm_set_key(ctx, seed, CX_AES_BLOCK_SIZE));
    error = SWO_SUCCESS;
end:
    explicit_bzero(seed, sizeof(seed));
    return error;
}

/* Rebuild the 12-byte GCM nonce of v1 backups from slot and key reference. */
static void gpg_backup_nonce(unsigned int ref, unsigned char nonce[GPG_BACKUP_NONCE_LEN]) {
    explicit_bzero(nonce, GPG_BACKUP_NONCE_LEN);
    nonce[0] = (unsigned char) G_gpg_vstate.slot;
    nonce[1] = (unsigned char) (ref >> 8);
    nonce[2] = (unsigned char) (ref & 0xFF);
}

/**
 * Encrypt a Key DO (Data Object) for Backup
 *
 * @param[in] ref DO tag
 * @param[in] gcm_ctx AES-GCM context initialised with the backup key
 *
 * @return Status Word
 *
 */
static int gpg_get_key_data(unsigned int ref, cx_aes_gcm_context_t *gcm_ctx) {
    gpg_key_t *keygpg = NULL;
    cx_rsa_private_key_t *key = NULL;
    unsigned int k_len = 0;
    cx_err_t error = CX_INTERNAL_ERROR;
    int sw = SWO_UNKNOWN;
    unsigned int ksz = 0;
    unsigned int aad_len = 0;
    unsigned char nonce[GPG_BACKUP_NONCE_LEN];

    switch (ref) {
        case 0x00B6:
            keygpg = &G_gpg_vstate.kslot->sig;
            break;
        case 0x00B8:
            keygpg = &G_gpg_vstate.kslot->dec;
            break;
        case 0x00A4:
            keygpg = &G_gpg_vstate.kslot->aut;
            break;
        default:
            return SWO_INCORRECT_DATA;
    }

    gpg_io_discard(1);
    CX_CHECK(cx_get_random_bytes(nonce, sizeof(nonce)));
    // header authenticated by GCM tag (not encrypted), binding the key role and attributes
    gpg_io_insert_u8(BACKUP_FORMAT_V3);
    gpg_io_insert(nonce, sizeof(nonce));
    gpg_io_insert_u16(ref);
    gpg_io_insert_u8(keygpg->attributes.length);
    gpg_io_insert(keygpg->attributes.value, keygpg->attributes.length);

    switch (keygpg->attributes.value[0]) {
        case KEY_ID_RSA:
            ksz = U2BE(keygpg->attributes.value, 1) >> 3;
            switch (ksz) {
                case 2048 / 8:
                    key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa2048;
                    k_len = sizeof(cx_rsa_2048_private_key_t);
                    break;
                case 3072 / 8:
                    key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa3072;
                    k_len = sizeof(cx_rsa_3072_private_key_t);
                    break;
                case 4096 / 8:
                    key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa4096;
                    k_len = sizeof(cx_rsa_4096_private_key_t);
                    break;
            }

            if ((key == NULL) || (key->size != ksz)) {
                return SWO_CONDITIONS_NOT_SATISFIED;
            }

            gpg_io_insert_u32(4);
            gpg_io_insert(keygpg->pub_key.rsa, 4);
            aad_len = G_gpg_vstate.io_offset;

            // GCM produces no padding: ciphertext length == plaintext length
            gpg_io_insert_u32(k_len + GPG_BACKUP_TAG_LEN);
            CX_CHECK(cx_aes_gcm_encrypt_and_tag(
                gcm_ctx,
                (unsigned char *) key,
                k_len,
                nonce,
                GPG_BACKUP_NONCE_LEN,
                G_gpg_vstate.work.io_buffer,
                aad_len,
                G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + k_len,
                GPG_BACKUP_TAG_LEN));
            gpg_io_inserted(k_len + GPG_BACKUP_TAG_LEN);
            sw = SWO_SUCCESS;
            break;

        case KEY_ID_ECDH:
        case KEY_ID_ECDSA:
        case KEY_ID_EDDSA:
            k_len = sizeof(cx_ecfp_640_private_key_t);

            gpg_io_insert_u32(sizeof(cx_ecfp_640_public_key_t));
            gpg_io_insert((unsigned char *) &keygpg->pub_key.ecfp640,
                          sizeof(cx_ecfp_640_public_key_t));
            aad_len = G_gpg_vstate.io_offset;

            gpg_io_insert_u32(k_len + GPG_BACKUP_TAG_LEN);
            CX_CHECK(cx_aes_gcm_encrypt_and_tag(
                gcm_ctx,
                (unsigned char *) &keygpg->priv_key.ecfp640,
                k_len,
                nonce,
                GPG_BACKUP_NONCE_LEN,
                G_gpg_vstate.work.io_buffer,
                aad_len,
                G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset + k_len,
                GPG_BACKUP_TAG_LEN));
            gpg_io_inserted(k_len + GPG_BACKUP_TAG_LEN);
            sw = SWO_SUCCESS;
            break;

        default:
            sw = SWO_REFERENCED_DATA_NOT_FOUND;
            break;
    }
    return sw;
end:
    return error;
}

/**
 * Read a Key DO (Data Object) from the card
 * for Backup
 *
 * @param[in] ref DO tag
 *
 * @return Status Word
 *
 */
int gpg_apdu_get_key_data(unsigned int ref) {
    cx_aes_gcm_context_t gcm_ctx;
    int sw;

    sw = gpg_init_gcm(&gcm_ctx, BACKUP_FORMAT_V3);
    if (sw == SWO_SUCCESS) {
        sw = gpg_get_key_data(ref, &gcm_ctx);
    }
    explicit_bzero(&gcm_ctx, sizeof(gcm_ctx));
    return sw;
}

/**
 * Write a key DO (Data Object) to the card
 * For Restore
 *
 * @param[in] ref DO tag
 *
 * @return Status Word
 *
 */
static int gpg_put_key_data_legacy_rsa(gpg_key_t *keygpg, cx_aes_key_t *keyenc) {
    unsigned int len = 0;
    unsigned int enc_len = 0;
    unsigned int offset = 0;
    unsigned int ksz = 0;
    size_t dec_len = 0;
    unsigned char pub_e[4];
    cx_rsa_private_key_t *key = NULL;
    int sw = SWO_INCORRECT_DATA;

    if (gpg_key_data_left() < 4) {
        return SWO_WRONG_LENGTH;
    }
    len = gpg_io_fetch_u32();
    if (len != sizeof(pub_e)) {
        return SWO_INCORRECT_DATA;
    }
    // public key, then encrypted key length
    if (gpg_key_data_left() < len + 4) {
        return SWO_WRONG_LENGTH;
    }
    gpg_io_fetch(pub_e, sizeof(pub_e));

    enc_len = gpg_io_fetch_u32();
    if (enc_len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
        return SWO_INCORRECT_DATA;
    }
    offset = G_gpg_vstate.io_offset;
    ksz = U2BE(keygpg->attributes.value, 1) >> 3;
    switch (ksz) {
        case 2048 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa2048;
            len = sizeof(cx_rsa_2048_private_key_t);
            break;
        case 3072 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa3072;
            len = sizeof(cx_rsa_3072_private_key_t);
            break;
        case 4096 / 8:
            key = (cx_rsa_private_key_t *) &keygpg->priv_key.rsa4096;
            len = sizeof(cx_rsa_4096_private_key_t);
            break;
        default:
            return SWO_INCORRECT_DATA;
    }

    // Decrypted ahead of the ciphertext; any failure gives the same status, and writes nothing
    gpg_io_discard(0);
    dec_len = enc_len;
    if ((cx_aes_no_throw(keyenc,
                         CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                         G_gpg_vstate.work.io_buffer + offset,
                         enc_len,
                         G_gpg_vstate.work.io_buffer,
                         &dec_len) == CX_OK) &&
        (dec_len == len) && (((cx_rsa_private_key_t *) G_gpg_vstate.work.io_buffer)->size == ksz)) {
        nvm_write((unsigned char *) key, G_gpg_vstate.work.io_buffer, len);
        nvm_write(keygpg->pub_key.rsa, pub_e, sizeof(pub_e));
        sw = SWO_SUCCESS;
    }
    explicit_bzero(G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    return sw;
}

static int gpg_put_key_data_legacy_ec(gpg_key_t *keygpg, cx_aes_key_t *keyenc) {
    unsigned int len = 0;
    unsigned int enc_len = 0;
    unsigned int offset = 0;
    unsigned int pub_offset = 0;
    size_t dec_len = 0;
    unsigned char *priv = NULL;
    int sw = SWO_INCORRECT_DATA;

    if (gpg_key_data_left() < 4) {
        return SWO_WRONG_LENGTH;
    }
    len = gpg_io_fetch_u32();
    if (len != sizeof(cx_ecfp_640_public_key_t)) {
        return SWO_INCORRECT_DATA;
    }
    // public key, then encrypted key length
    if (gpg_key_data_left() < len + 4) {
        return SWO_WRONG_LENGTH;
    }
    pub_offset = G_gpg_vstate.io_offset;
    G_gpg_vstate.io_offset += len;

    enc_len = gpg_io_fetch_u32();
    if (enc_len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
        return SWO_INCORRECT_DATA;
    }
    offset = G_gpg_vstate.io_offset;
    // Decrypt past the blob so that the public key stays in place
    if ((offset + 2 * enc_len) > GPG_IO_BUFFER_LENGTH) {
        return SWO_INCORRECT_DATA;
    }
    priv = G_gpg_vstate.work.io_buffer + offset + enc_len;

    // Any failure gives the same status, and writes nothing
    dec_len = enc_len;
    if ((cx_aes_no_throw(keyenc,
                         CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                         G_gpg_vstate.work.io_buffer + offset,
                         enc_len,
                         priv,
                         &dec_len) == CX_OK) &&
        (dec_len == sizeof(cx_ecfp_640_private_key_t))) {
        nvm_write((unsigned char *) &keygpg->priv_key.ecfp640, priv, dec_len);
        nvm_write((unsigned char *) &keygpg->pub_key.ecfp640,
                  G_gpg_vstate.work.io_buffer + pub_offset,
                  sizeof(cx_ecfp_640_public_key_t));
        sw = SWO_SUCCESS;
    }
    explicit_bzero(G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
    return sw;
}

/**
 * Check that a v3 blob holds a key of the given role and of the current key attributes
 *
 * @param[in] ref destination key reference
 * @param[in] keygpg destination key
 *
 * @return Status Word
 *
 */
static int gpg_check_key_role(unsigned int ref, const gpg_key_t *keygpg) {
    unsigned char attributes[GPG_KEY_ATTRIBUTES_LENGTH];
    unsigned int blob_ref;
    unsigned int len;

    if (gpg_key_data_left() < 2 + 1) {
        return SWO_WRONG_LENGTH;
    }
    blob_ref = gpg_io_fetch_u16();
    len = gpg_io_fetch_u8();
    if ((len > sizeof(attributes)) || (gpg_key_data_left() < len)) {
        return SWO_WRONG_LENGTH;
    }
    gpg_io_fetch(attributes, len);
    if ((blob_ref != ref) || (len != keygpg->attributes.length) ||
        (memcmp(attributes, keygpg->attributes.value, len) != 0)) {
        return SWO_INCORRECT_DATA;
    }
    return SWO_SUCCESS;
}

int gpg_apdu_put_key_data(unsigned int ref) {
    gpg_key_t *keygpg = NULL;
    int sw = SWO_UNKNOWN;
    unsigned char version;

    switch (ref) {
        case KEY_SIG:
            keygpg = &G_gpg_vstate.kslot->sig;
            break;
        case KEY_DEC:
            keygpg = &G_gpg_vstate.kslot->dec;
            break;
        case KEY_AUT:
            keygpg = &G_gpg_vstate.kslot->aut;
            break;
        default:
            return SWO_INCORRECT_DATA;
    }

    if (gpg_key_data_left() < 1) {
        return SWO_WRONG_LENGTH;
    }
    version = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
    if ((version == BACKUP_FORMAT_V1) || (version == BACKUP_FORMAT_V2) ||
        (version == BACKUP_FORMAT_V3)) {
        // AES-GCM authenticated blob, with the nonce stored in the header from v2
        cx_aes_gcm_context_t gcm_ctx;
        unsigned char nonce[GPG_BACKUP_NONCE_LEN];

        // version, TARGET_ID and api_level (not checked) up to v2, then the nonce from v2
        if (gpg_key_data_left() < 1 + ((version == BACKUP_FORMAT_V3) ? 0 : 4 + 4) +
                                      ((version == BACKUP_FORMAT_V1) ? 0 : GPG_BACKUP_NONCE_LEN)) {
            return SWO_WRONG_LENGTH;
        }
        gpg_io_fetch_u8();  // version
        if (version != BACKUP_FORMAT_V3) {
            gpg_io_fetch_u32();  // TARGET_ID
            gpg_io_fetch_u32();  // api_level
        }
        if (version == BACKUP_FORMAT_V1) {
            gpg_backup_nonce(ref, nonce);
        } else {
            gpg_io_fetch(nonce, sizeof(nonce));
        }
        if (version == BACKUP_FORMAT_V3) {
            sw = gpg_check_key_role(ref, keygpg);
            if (sw != SWO_SUCCESS) {
                return sw;
            }
        }
        sw = gpg_init_gcm(&gcm_ctx, version);
        if (sw != SWO_SUCCESS) {
            explicit_bzero(&gcm_ctx, sizeof(gcm_ctx));
            return sw;
        }

        switch (keygpg->attributes.value[0]) {
            case KEY_ID_RSA:
                sw = gpg_put_key_data_v1_rsa(keygpg, &gcm_ctx, nonce);
                break;

            case KEY_ID_ECDH:
            case KEY_ID_ECDSA:
            case KEY_ID_EDDSA:
                sw = gpg_put_key_data_v1_ec(keygpg, &gcm_ctx, nonce);
                break;

            default:
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
        }
        explicit_bzero(&gcm_ctx, sizeof(gcm_ctx));
    } else {
        // legacy: AES-CBC blob (first byte is high byte of TARGET_ID, never a version number)
        cx_aes_key_t keyenc = {0};

        // TARGET_ID and api_level
        if (gpg_key_data_left() < 4 + 4) {
            return SWO_WRONG_LENGTH;
        }
        sw = gpg_init_keyenc(&keyenc);
        if (sw != SWO_SUCCESS) {
            explicit_bzero(&keyenc, sizeof(keyenc));
            return sw;
        }

        gpg_io_fetch_u32();  // TARGET_ID
        gpg_io_fetch_u32();  // api_level

        switch (keygpg->attributes.value[0]) {
            case KEY_ID_RSA:
                sw = gpg_put_key_data_legacy_rsa(keygpg, &keyenc);
                break;

            case KEY_ID_ECDH:
            case KEY_ID_ECDSA:
            case KEY_ID_EDDSA:
                sw = gpg_put_key_data_legacy_ec(keygpg, &keyenc);
                break;

            default:
                sw = SWO_REFERENCED_DATA_NOT_FOUND;
                break;
        }
        explicit_bzero(&keyenc, sizeof(keyenc));
    }
    gpg_io_discard(1);
    return sw;
}
