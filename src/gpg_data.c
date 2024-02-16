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

void gpg_apdu_select_data(unsigned int ref, int record) {
    G_gpg_vstate.DO_current = ref;
    G_gpg_vstate.DO_reccord = record;
    G_gpg_vstate.DO_offset = 0;
}

int gpg_apdu_get_data(unsigned int ref) {
    int sw = SW_UNKNOWN;

    if (G_gpg_vstate.DO_current != ref) {
        G_gpg_vstate.DO_current = ref;
        G_gpg_vstate.DO_reccord = 0;
        G_gpg_vstate.DO_offset = 0;
    }
    sw = SW_OK;

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
            gpg_io_insert((const unsigned char *) N_gpg_pstate->histo, 15);
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
            gpg_io_insert((const unsigned char *) N_gpg_pstate->url.value,
                          N_gpg_pstate->url.length);
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
            gpg_io_insert_tlv(0x4F, 16, (const unsigned char *) N_gpg_pstate->AID);
            memmove(G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset - 6,
                    G_gpg_vstate.kslot->serial,
                    4);
            gpg_io_insert_tlv(0x5F52, 15, (const unsigned char *) N_gpg_pstate->histo);
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
                    sw = SW_FILE_NOT_FOUND;
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
            sw = SW_REFERENCED_DATA_NOT_FOUND;
            break;
    }

    return sw;
}

int gpg_apdu_get_next_data(unsigned int ref) {
    int sw = SW_UNKNOWN;

    if ((ref != 0x7F21) || (G_gpg_vstate.DO_current != 0x7F21)) {
        return SW_CONDITIONS_NOT_SATISFIED;
    }
    sw = gpg_apdu_get_data(ref);
    if (sw == SW_OK) {
        G_gpg_vstate.DO_reccord++;
    }
    return sw;
}

int gpg_apdu_put_data(unsigned int ref) {
    unsigned int t, l, sw;
    unsigned int *ptr_l = NULL;
    unsigned char *ptr_v = NULL;
    void *pkey = NULL;
    cx_aes_key_t aes_key = {0};
    cx_err_t error = CX_INTERNAL_ERROR;

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
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v,
                      G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                      G_gpg_vstate.io_length);
            nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
            sw = SW_OK;
            break;
            /*  ----------------- Config key slot ----------------- */
        case 0x01F1:
            if (G_gpg_vstate.io_length != 3) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            if ((G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 0] != GPG_KEYS_SLOTS) ||
                (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 1] >= GPG_KEYS_SLOTS) ||
                (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset + 2] > 3)) {
                sw = SW_WRONG_DATA;
                break;
            }
            nvm_write((void *) N_gpg_pstate->config_slot,
                      G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                      3);
            sw = SW_OK;
            break;

        case 0x01F2:
            if ((N_gpg_pstate->config_slot[2] & 1) == 0) {
                sw = SW_CONDITIONS_NOT_SATISFIED;
                break;
            }
            if ((G_gpg_vstate.io_length != 1) ||
                (G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset] >= GPG_KEYS_SLOTS)) {
                sw = SW_WRONG_DATA;
                break;
            }
            G_gpg_vstate.slot = G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset];
            G_gpg_vstate.kslot = (gpg_key_slot_t *) &N_gpg_pstate->keys[G_gpg_vstate.slot];
            gpg_mse_reset();
            ui_CCID_reset();
            sw = SW_OK;
            break;

        /* ----------------- Config RSA exponent ----------------- */
        case 0x01F8: {
            unsigned int e;
            if (G_gpg_vstate.io_length != 4) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            e = gpg_io_fetch_u32();
            nvm_write((void *) &N_gpg_pstate->default_RSA_exponent, &e, sizeof(unsigned int));
            sw = SW_OK;
            break;
        }

            /* ----------------- Serial -----------------*/
        case 0x4f:
            if (G_gpg_vstate.io_length != 4) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(G_gpg_vstate.kslot->serial,
                      &G_gpg_vstate.work.io_buffer[G_gpg_vstate.io_offset],
                      4);
            sw = SW_OK;
            break;

            /* ----------------- Extended Header list -----------------*/
        case 0x3FFF: {
            unsigned int len_e, len_p, len_q;
            unsigned int endof, ksz, reset_cnt;
            gpg_key_t *keygpg = NULL;
            // fecth 4D
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x4D) {
                sw = SW_REFERENCED_DATA_NOT_FOUND;
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
                sw = SW_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            // fecth 7f78
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x7f48) {
                sw = SW_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            len_e = 0;
            len_p = 0;
            len_q = 0;
            endof = G_gpg_vstate.io_offset + l;
            while (G_gpg_vstate.io_offset < endof) {
                gpg_io_fetch_tl(&t, &l);
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
                        break;
                    case 0x94:
                    case 0x95:
                    case 0x96:
                    case 0x97:
                    case 0x99:
                        break;
                    default:
                        return SW_REFERENCED_DATA_NOT_FOUND;
                }
            }
            // fecth 5f78
            gpg_io_fetch_tl(&t, &l);
            if (t != 0x5f48) {
                sw = SW_REFERENCED_DATA_NOT_FOUND;
                break;
            }

            // --- RSA KEY ---
            if (keygpg->attributes.value[0] == KEY_ID_RSA) {
                unsigned int e = 0;
                unsigned char *p, *q, *pq;
                cx_rsa_public_key_t *rsa_pub;
                cx_rsa_private_key_t *rsa_priv;
                unsigned int pkey_size = 0;
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
                    sw = SW_WRONG_DATA;
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
                    sw = SW_WRONG_DATA;
                    break;
                }

                // move p,q over pub key, this only work because adr<rsa_pub> < adr<p>
                if ((len_p > ksz) || (len_q > ksz)) {
                    sw = SW_WRONG_DATA;
                    break;
                }
                p = G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset;
                q = p + len_p;
                memmove(pq + ksz - len_p, p, len_p);
                memset(pq, 0, ksz - len_p);
                memmove(pq + 2 * ksz - len_q, q, len_q);
                memset(pq + ksz, 0, ksz - len_q);

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
                sw = SW_OK;
            }
            // --- ECC KEY ---
            else if ((keygpg->attributes.value[0] == KEY_ID_ECDH) ||
                     (keygpg->attributes.value[0] == KEY_ID_ECDSA) ||
                     (keygpg->attributes.value[0] == KEY_ID_EDDSA)) {
                unsigned int curve;

                curve = gpg_oid2curve(&keygpg->attributes.value[1], keygpg->attributes.length - 1);
                if (curve == 0) {
                    sw = SW_WRONG_DATA;
                    break;
                }
                ksz = gpg_curve2domainlen(curve);
                if (ksz == len_p) {
                    G_gpg_vstate.work.ecfp.private.curve = curve;
                    G_gpg_vstate.work.ecfp.private.d_len = ksz;
                    memmove(G_gpg_vstate.work.ecfp.private.d,
                            G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                            ksz);
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
                }
                sw = SW_OK;
            }
            // --- UNSUPPORTED KEY ---
            else {
                sw = SW_REFERENCED_DATA_NOT_FOUND;
            }
            break;
        }  // endof of 3fff

            /* ----------------- User -----------------*/
            /* Name */
        case 0x5B:
            if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->name.value)) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->name.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            nvm_write((void *) &N_gpg_pstate->name.length,
                      &G_gpg_vstate.io_length,
                      sizeof(unsigned int));
            sw = SW_OK;
            break;
            /* Login data */
        case 0x5E:
            if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->login.value)) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->login.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            nvm_write((void *) &N_gpg_pstate->login.length,
                      &G_gpg_vstate.io_length,
                      sizeof(unsigned int));
            sw = SW_OK;
            break;
            /* Language preferences */
        case 0x5F2D:
            if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->lang.value)) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->lang.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            nvm_write((void *) &N_gpg_pstate->lang.length,
                      &G_gpg_vstate.io_length,
                      sizeof(unsigned int));
            sw = SW_OK;
            break;
            /* salutation */
        case 0x5F35:
            if (G_gpg_vstate.io_length != sizeof(N_gpg_pstate->salutation)) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->salutation,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            sw = SW_OK;
            break;
            /* Uniform resource locator */
        case 0x5F50:
            if (G_gpg_vstate.io_length > sizeof(N_gpg_pstate->url.value)) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write((void *) N_gpg_pstate->url.value,
                      G_gpg_vstate.work.io_buffer,
                      G_gpg_vstate.io_length);
            nvm_write((void *) &N_gpg_pstate->url.length,
                      &G_gpg_vstate.io_length,
                      sizeof(unsigned int));
            sw = SW_OK;
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
                    ptr_l = &G_gpg_vstate.kslot->sig.CA.length;
                    ptr_v = G_gpg_vstate.kslot->sig.CA.value;
                    break;
                case 2:
                    ptr_l = &G_gpg_vstate.kslot->dec.CA.length;
                    ptr_v = G_gpg_vstate.kslot->dec.CA.value;
                    break;
                default:
                    break;
            }
            if (ptr_v == NULL) {
                sw = SW_REFERENCED_DATA_NOT_FOUND;
                break;
            }
            if (G_gpg_vstate.io_length > GPG_EXT_CARD_HOLDER_CERT_LENTH) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
            nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
            sw = SW_OK;
            break;

            /* ----------------- Algorithm attributes ----------------- */
        case 0xC1:
            ptr_l = &G_gpg_vstate.kslot->sig.attributes.length;
            ptr_v = G_gpg_vstate.kslot->sig.attributes.value;
            goto WRITE_ATTRIBUTES;
        case 0xC2:
            ptr_l = &G_gpg_vstate.kslot->dec.attributes.length;
            ptr_v = G_gpg_vstate.kslot->dec.attributes.value;
            goto WRITE_ATTRIBUTES;
        case 0xC3:
            ptr_l = &G_gpg_vstate.kslot->aut.attributes.length;
            ptr_v = G_gpg_vstate.kslot->aut.attributes.value;
            goto WRITE_ATTRIBUTES;
        WRITE_ATTRIBUTES:
            if (G_gpg_vstate.io_length > 12) {
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, G_gpg_vstate.io_length);
            nvm_write(ptr_l, &G_gpg_vstate.io_length, sizeof(unsigned int));
            sw = SW_OK;
            break;

            /* ----------------- PWS status ----------------- */
        case 0xC4:
            gpg_io_fetch_nv((unsigned char *) N_gpg_pstate->PW_status, 1);
            sw = SW_OK;
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
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 20);
            sw = SW_OK;
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
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 4);
            sw = SW_OK;
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
            sw = SW_OK;
            break;

            /* AES key: one shot */
        case 0xF4:
            CX_CHECK(cx_aes_init_key_no_throw(G_gpg_vstate.work.io_buffer,
                                              G_gpg_vstate.io_length,
                                              &aes_key));
            nvm_write((void *) &N_gpg_pstate->SM_enc, &aes_key, sizeof(cx_aes_key_t));
            CX_CHECK(cx_aes_init_key_no_throw(G_gpg_vstate.work.io_buffer + 16,
                                              G_gpg_vstate.io_length,
                                              &aes_key));
            nvm_write((void *) &N_gpg_pstate->SM_mac, &aes_key, sizeof(cx_aes_key_t));
            sw = SW_OK;
            break;

            /* ----------------- RC ----------------- */
        case 0xD3: {
            gpg_pin_t *pin;

            pin = gpg_pin_get_pin(PIN_ID_RC);
            if (G_gpg_vstate.io_length == 0) {
                nvm_write(pin, NULL, sizeof(gpg_pin_t));
                sw = SW_OK;
            } else if ((G_gpg_vstate.io_length > GPG_MAX_PW_LENGTH) ||
                       (G_gpg_vstate.io_length < 8)) {
                sw = SW_WRONG_DATA;
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
                sw = SW_WRONG_LENGTH;
                break;
            }
            nvm_write(ptr_v, G_gpg_vstate.work.io_buffer, 2);
            sw = SW_OK;
            break;

            /* ----------------- WAT ----------------- */
        default:
            sw = SW_REFERENCED_DATA_NOT_FOUND;
            break;
    }

    gpg_io_discard(1);
    return sw;
end:
    return error;
}

static int gpg_init_keyenc(cx_aes_key_t *keyenc) {
    int sw = SW_UNKNOWN;
    unsigned char seed[32];
    cx_err_t error = CX_INTERNAL_ERROR;

    sw = gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed);
    if (sw != SW_OK) {
        return sw;
    }
    sw = gpg_pso_derive_key_seed(seed, (unsigned char *) PIC("key "), 1, seed, 16);
    if (sw != SW_OK) {
        return sw;
    }
    CX_CHECK(cx_aes_init_key_no_throw(seed, 16, keyenc));

end:
    if (error != CX_OK) {
        return error;
    }
    return SW_OK;
}

// cmd
// resp  TID API COMPAT len_pub len_priv priv
int gpg_apdu_get_key_data(unsigned int ref) {
    cx_aes_key_t keyenc;
    gpg_key_t *keygpg;
    unsigned int len = 0;
    cx_err_t error = CX_INTERNAL_ERROR;
    int sw = SW_UNKNOWN;

    sw = gpg_init_keyenc(&keyenc);
    if (sw != SW_OK) {
        return sw;
    }
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
            return SW_WRONG_DATA;
    }

    gpg_io_discard(1);
    // clear part
    gpg_io_insert_u32(TARGET_ID);
    gpg_io_insert_u32(get_api_level());

    // encrypted part
    switch (keygpg->attributes.value[0]) {
        case KEY_ID_RSA:  // RSA
            // insert pubkey
            gpg_io_insert_u32(4);
            gpg_io_insert(keygpg->pub_key.rsa, 4);

            // insert privkey
            gpg_io_mark();
            len = GPG_IO_BUFFER_LENGTH - G_gpg_vstate.io_offset;
            CX_CHECK(cx_aes_no_throw(&keyenc,
                                     CX_ENCRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                                     (unsigned char *) &keygpg->priv_key.rsa4096,
                                     sizeof(cx_rsa_4096_private_key_t),
                                     G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                     &len));
            gpg_io_inserted(len);
            gpg_io_set_offset(IO_OFFSET_MARK);
            gpg_io_insert_u32(len);
            gpg_io_set_offset(IO_OFFSET_END);
            sw = SW_OK;
            break;

        case KEY_ID_ECDH:  // ECC
        case KEY_ID_ECDSA:
        case KEY_ID_EDDSA:
            // insert pubkey
            gpg_io_insert_u32(sizeof(cx_ecfp_640_public_key_t));
            gpg_io_insert((unsigned char *) &keygpg->pub_key.ecfp640,
                          sizeof(cx_ecfp_640_public_key_t));

            // insert privkey
            gpg_io_mark();
            len = GPG_IO_BUFFER_LENGTH - G_gpg_vstate.io_offset;
            CX_CHECK(cx_aes_no_throw(&keyenc,
                                     CX_ENCRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                                     (unsigned char *) &keygpg->priv_key.ecfp640,
                                     sizeof(cx_ecfp_640_private_key_t),
                                     G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                     &len));
            gpg_io_inserted(len);
            gpg_io_set_offset(IO_OFFSET_MARK);
            gpg_io_insert_u32(len);
            gpg_io_set_offset(IO_OFFSET_END);
            sw = SW_OK;
            break;

        default:
            sw = SW_REFERENCED_DATA_NOT_FOUND;
            break;
    }
    return sw;
end:
    return error;
}

// cmd   TID API COMPAT len_pub len_priv priv
// resp  -
int gpg_apdu_put_key_data(unsigned int ref) {
    cx_aes_key_t keyenc;
    gpg_key_t *keygpg;
    unsigned int len;
    unsigned int offset;
    cx_err_t error = CX_INTERNAL_ERROR;
    int sw = SW_UNKNOWN;

    sw = gpg_init_keyenc(&keyenc);
    if (sw != SW_OK) {
        return sw;
    }
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
            return SW_WRONG_DATA;
    }

    /* unsigned int target_id = */
    gpg_io_fetch_u32();
    /* unsigned int cx_apilevel = */
    gpg_io_fetch_u32();

    switch (keygpg->attributes.value[0]) {
        // RSA
        case KEY_ID_RSA:
            // insert pubkey
            len = gpg_io_fetch_u32();
            if (len != 4) {
                sw = SW_WRONG_DATA;
                break;
            }
            gpg_io_fetch_nv(keygpg->pub_key.rsa, len);

            // insert privkey
            len = gpg_io_fetch_u32();
            if (len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
                sw = SW_WRONG_DATA;
                break;
            }
            offset = G_gpg_vstate.io_offset;
            gpg_io_discard(0);
            len = GPG_IO_BUFFER_LENGTH;
            CX_CHECK(cx_aes_no_throw(&keyenc,
                                     CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                                     G_gpg_vstate.work.io_buffer + offset,
                                     len,
                                     G_gpg_vstate.work.io_buffer,
                                     &len));
            if (len != sizeof(cx_rsa_4096_private_key_t)) {
                sw = SW_WRONG_DATA;
                break;
            }
            nvm_write((unsigned char *) &keygpg->priv_key.rsa4096,
                      G_gpg_vstate.work.io_buffer,
                      len);
            sw = SW_OK;
            break;

        // ECC
        case KEY_ID_ECDH:  // ECC
        case KEY_ID_ECDSA:
        case KEY_ID_EDDSA:
            // insert pubkey
            len = gpg_io_fetch_u32();
            if (len != sizeof(cx_ecfp_640_public_key_t)) {
                sw = SW_WRONG_DATA;
                break;
            }
            gpg_io_fetch_nv((unsigned char *) &keygpg->pub_key.ecfp640, len);

            // insert privkey
            len = gpg_io_fetch_u32();
            if (len > (G_gpg_vstate.io_length - G_gpg_vstate.io_offset)) {
                sw = SW_WRONG_DATA;
                break;
            }
            offset = G_gpg_vstate.io_offset;
            gpg_io_discard(0);

            len = GPG_IO_BUFFER_LENGTH;
            CX_CHECK(cx_aes_no_throw(&keyenc,
                                     CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST,
                                     G_gpg_vstate.work.io_buffer + offset,
                                     len,
                                     G_gpg_vstate.work.io_buffer,
                                     &len));
            if (len != sizeof(cx_ecfp_640_private_key_t)) {
                sw = SW_WRONG_DATA;
                break;
            }
            nvm_write((unsigned char *) &keygpg->priv_key.ecfp640,
                      G_gpg_vstate.work.io_buffer,
                      len);
            sw = SW_OK;
            break;

        default:
            sw = SW_REFERENCED_DATA_NOT_FOUND;
            break;
    }
    gpg_io_discard(1);
    return sw;
end:
    return error;
}
