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

const unsigned char gpg_oid_sha256[] = {0x30,
                                        0x31,
                                        0x30,
                                        0x0d,
                                        0x06,
                                        0x09,
                                        0x60,
                                        0x86,
                                        0x48,
                                        0x01,
                                        0x65,
                                        0x03,
                                        0x04,
                                        0x02,
                                        0x01,
                                        0x05,
                                        0x00,
                                        0x04,
                                        0x20};
const unsigned char gpg_oid_sha512[] = {0x30,
                                        0x51,
                                        0x30,
                                        0x0d,
                                        0x06,
                                        0x09,
                                        0x60,
                                        0x86,
                                        0x48,
                                        0x01,
                                        0x65,
                                        0x03,
                                        0x04,
                                        0x02,
                                        0x03,
                                        0x05,
                                        0x00,
                                        0x04,
                                        0x40};

static void gpg_pso_reset_PW1() {
    if (N_gpg_pstate->PW_status[0] == 0) {
        gpg_pin_set_verified(PIN_ID_PW1, 0);
    }
}

static int gpg_sign(gpg_key_t *sigkey) {
    // --- RSA
    cx_err_t error = CX_INTERNAL_ERROR;
    if (sigkey->attributes.value[0] == KEY_ID_RSA) {
        cx_rsa_private_key_t *key = NULL;
        unsigned int ksz, l;
        ksz = U2BE(sigkey->attributes.value, 1) >> 3;
        switch (ksz) {
            case 1024 / 8:
                key = (cx_rsa_private_key_t *) &sigkey->priv_key.rsa1024;
                break;
            case 2048 / 8:
                key = (cx_rsa_private_key_t *) &sigkey->priv_key.rsa2048;
                break;
            case 3072 / 8:
                key = (cx_rsa_private_key_t *) &sigkey->priv_key.rsa3072;
                break;
            case 4096 / 8:
                key = (cx_rsa_private_key_t *) &sigkey->priv_key.rsa4096;
                break;
            default:
                break;
        }
        if ((key == NULL) || (key->size != ksz)) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        // sign
        if (ksz < G_gpg_vstate.io_length) {
            return SW_WRONG_LENGTH;
        }
        l = ksz - G_gpg_vstate.io_length;
        memmove(G_gpg_vstate.work.io_buffer + l,
                G_gpg_vstate.work.io_buffer,
                G_gpg_vstate.io_length);
        memset(G_gpg_vstate.work.io_buffer, 0xFF, l);
        G_gpg_vstate.work.io_buffer[0] = 0;
        G_gpg_vstate.work.io_buffer[1] = 1;
        G_gpg_vstate.work.io_buffer[l - 1] = 0;
        CX_CHECK(cx_rsa_decrypt_no_throw(key,
                                         CX_PAD_NONE,
                                         CX_NONE,
                                         G_gpg_vstate.work.io_buffer,
                                         ksz,
                                         G_gpg_vstate.work.io_buffer,
                                         &ksz));
        // send
        gpg_io_discard(0);
        gpg_io_inserted(ksz);
        gpg_pso_reset_PW1();
        return SW_OK;
    }
    // --- ECDSA/EdDSA
    if ((sigkey->attributes.value[0] == KEY_ID_ECDSA) ||
        (sigkey->attributes.value[0] == KEY_ID_EDDSA)) {
        cx_ecfp_private_key_t *key;
        size_t ksz;
        unsigned int s_len, i, rs_len, info;
        unsigned char *rs;

        key = &sigkey->priv_key.ecfp;

// sign
#define RS (G_gpg_vstate.work.io_buffer + (GPG_IO_BUFFER_LENGTH - 256))
        if (sigkey->attributes.value[0] == KEY_ID_ECDSA) {
            ksz = (unsigned int) gpg_curve2domainlen(key->curve);
            if ((ksz == 0) || (key->d_len != ksz)) {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            s_len = 256;
            CX_CHECK(cx_ecdsa_sign_no_throw(key,
                                            CX_RND_TRNG,
                                            CX_NONE,
                                            G_gpg_vstate.work.io_buffer,
                                            ksz,
                                            RS,
                                            &s_len,
                                            &info));
            // re-encode r,s in MPI format
            gpg_io_discard(0);

            rs_len = RS[3];
            rs = &RS[4];

            for (i = 0; i < 2; i++) {
                if (*rs == 0) {
                    rs++;
                    rs_len--;
                }
                gpg_io_insert_u8(0);
                gpg_io_insert(rs, rs_len);
                rs = rs + rs_len;
                rs_len = rs[1];
                rs += 2;
            }
        } else {
            ksz = 256;
            CX_CHECK(cx_eddsa_sign_no_throw(key,
                                            CX_SHA512,
                                            G_gpg_vstate.work.io_buffer,
                                            G_gpg_vstate.io_length,
                                            RS,
                                            ksz));
            CX_CHECK(cx_ecdomain_parameters_length(key->curve, &ksz));
            ksz *= 2;
            gpg_io_discard(0);
            gpg_io_insert(RS, ksz);
        }

        // send
        gpg_pso_reset_PW1();
        return SW_OK;
    }
    // --- PSO:CDS NOT SUPPORTED
    return SW_REFERENCED_DATA_NOT_FOUND;
end:
    return error;
}

int gpg_apdu_pso() {
    unsigned int t, l, ksz;
    cx_err_t error = CX_INTERNAL_ERROR;

    // UIF HANDLE
    switch (G_gpg_vstate.io_p1p2) {
        // --- PSO:CDS ---
        case PSO_CDS:
            if (G_gpg_vstate.kslot->sig.UIF[0]) {
                if ((G_gpg_vstate.UIF_flags) == 0) {
                    ui_menu_uifconfirm_display(0);
                    return 0;
                }
                G_gpg_vstate.UIF_flags = 0;
            }
            break;
        // --- PSO:DEC ---
        case PSO_DEC:
        case PSO_ENC:
            if (G_gpg_vstate.kslot->dec.UIF[0]) {
                if ((G_gpg_vstate.UIF_flags) == 0) {
                    ui_menu_uifconfirm_display(0);
                    return 0;
                }
                G_gpg_vstate.UIF_flags = 0;
            }
            break;
    }

    // --- PSO:ENC ---
    switch (G_gpg_vstate.io_p1p2) {
        // --- PSO:CDS ---
        case PSO_CDS: {
            unsigned int cnt;
            int sw = SW_UNKNOWN;
            sw = gpg_sign(&G_gpg_vstate.kslot->sig);
            cnt = G_gpg_vstate.kslot->sig_count + 1;
            nvm_write(&G_gpg_vstate.kslot->sig_count, &cnt, sizeof(unsigned int));
            return sw;
        }
        // --- PSO:ENC ---
        case PSO_ENC: {
            unsigned int msg_len;
            cx_aes_key_t *key;
            key = &G_gpg_vstate.kslot->AES_dec;
            if (!(key->size != 16)) {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
            ksz = GPG_IO_BUFFER_LENGTH - 1;
            CX_CHECK(cx_aes_no_throw(key,
                                     CX_ENCRYPT | CX_CHAIN_CBC | CX_LAST,
                                     G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                     msg_len,
                                     G_gpg_vstate.work.io_buffer + 1,
                                     &ksz));
            // send
            gpg_io_discard(0);
            G_gpg_vstate.work.io_buffer[0] = 0x02;
            gpg_io_inserted(1 + ksz);
            return SW_OK;
        }

        // --- PSO:DEC ---
        case PSO_DEC: {
            unsigned int msg_len;
            unsigned int pad_byte;
            pad_byte = gpg_io_fetch_u8();

            switch (pad_byte) {
                // --- PSO:DEC:RSA
                case 0x00: {
                    cx_rsa_private_key_t *key;
                    if (G_gpg_vstate.mse_dec->attributes.value[0] != KEY_ID_RSA) {
                        return SW_CONDITIONS_NOT_SATISFIED;
                    }
                    ksz = U2BE(G_gpg_vstate.mse_dec->attributes.value, 1) >> 3;
                    key = NULL;
                    switch (ksz) {
                        case 1024 / 8:
                            key = (cx_rsa_private_key_t *) &G_gpg_vstate.mse_dec->priv_key.rsa1024;
                            break;
                        case 2048 / 8:
                            key = (cx_rsa_private_key_t *) &G_gpg_vstate.mse_dec->priv_key.rsa2048;
                            break;
                        case 3072 / 8:
                            key = (cx_rsa_private_key_t *) &G_gpg_vstate.mse_dec->priv_key.rsa3072;
                            break;
                        case 4096 / 8:
                            key = (cx_rsa_private_key_t *) &G_gpg_vstate.mse_dec->priv_key.rsa4096;
                            break;
                    }

                    if ((key == NULL) || (key->size != ksz)) {
                        return SW_CONDITIONS_NOT_SATISFIED;
                    }
                    msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
                    CX_CHECK(cx_rsa_decrypt_no_throw(
                        key,
                        CX_PAD_PKCS1_1o5,
                        CX_NONE,
                        G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                        msg_len,
                        G_gpg_vstate.work.io_buffer,
                        &ksz));
                    // send
                    gpg_io_discard(0);
                    gpg_io_inserted(ksz);
                    return SW_OK;
                }

                // --- PSO:DEC:AES
                case 0x02: {
                    cx_aes_key_t *key;
                    key = &G_gpg_vstate.kslot->AES_dec;
                    if (!(key->size != 16)) {
                        return SW_CONDITIONS_NOT_SATISFIED;
                    }
                    msg_len = G_gpg_vstate.io_length - G_gpg_vstate.io_offset;
                    ksz = GPG_IO_BUFFER_LENGTH;
                    CX_CHECK(cx_aes_no_throw(key,
                                             CX_DECRYPT | CX_CHAIN_CBC | CX_LAST,
                                             G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                             msg_len,
                                             G_gpg_vstate.work.io_buffer,
                                             &ksz));
                    // send
                    gpg_io_discard(0);
                    gpg_io_inserted(ksz);
                    return SW_OK;
                }

                // --- PSO:DEC:ECDH
                case 0xA6: {
                    cx_ecfp_private_key_t *key;
                    unsigned int curve;

                    if (G_gpg_vstate.mse_dec->attributes.value[0] != KEY_ID_ECDH) {
                        return SW_CONDITIONS_NOT_SATISFIED;
                    }
                    key = &G_gpg_vstate.mse_dec->priv_key.ecfp;
                    gpg_io_fetch_l(&l);
                    gpg_io_fetch_tl(&t, &l);
                    if (t != 0x7f49) {
                        return SW_WRONG_DATA;
                    }
                    gpg_io_fetch_tl(&t, &l);
                    if (t != 0x86) {
                        return SW_WRONG_DATA;
                    }

                    curve = gpg_oid2curve(G_gpg_vstate.mse_dec->attributes.value + 1,
                                          G_gpg_vstate.mse_dec->attributes.length - 1);
                    if (key->curve != curve) {
                        return SW_CONDITIONS_NOT_SATISFIED;
                    }
                    if (curve == CX_CURVE_Curve25519) {
                        unsigned int i;

                        for (i = 0; i <= 31; i++) {
                            G_gpg_vstate.work.io_buffer[512 + i] =
                                (G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset)[31 - i];
                        }
                        G_gpg_vstate.work.io_buffer[511] = 0x02;
                        CX_CHECK(cx_ecdh_no_throw(key,
                                                  CX_ECDH_X,
                                                  G_gpg_vstate.work.io_buffer + 511,
                                                  65,
                                                  G_gpg_vstate.work.io_buffer + 256,
                                                  160));
                        CX_CHECK(cx_ecdomain_parameters_length(key->curve, &ksz));

                        for (i = 0; i <= 31; i++) {
                            G_gpg_vstate.work.io_buffer[128 + i] =
                                G_gpg_vstate.work.io_buffer[287 - i];
                        }
                        ksz = 32;
                    } else {
                        CX_CHECK(
                            cx_ecdh_no_throw(key,
                                             CX_ECDH_X,
                                             G_gpg_vstate.work.io_buffer + G_gpg_vstate.io_offset,
                                             65,
                                             G_gpg_vstate.work.io_buffer + 128,
                                             160));
                        CX_CHECK(cx_ecdomain_parameters_length(key->curve, &ksz));
                    }
                    // send
                    gpg_io_discard(0);
                    gpg_io_insert(G_gpg_vstate.work.io_buffer + 128, ksz);
                    return SW_OK;
                }

                // --- PSO:DEC:xx NOT SUPPORTED
                default:
                    return SW_REFERENCED_DATA_NOT_FOUND;
            }
        }

        //--- PSO:yy NOT SUPPORTED ---
        default:
            return SW_REFERENCED_DATA_NOT_FOUND;
    }
    return SW_REFERENCED_DATA_NOT_FOUND;
end:
    return error;
}

int gpg_apdu_internal_authenticate() {
    // --- PSO:AUTH ---
    if (G_gpg_vstate.kslot->aut.UIF[0]) {
        if ((G_gpg_vstate.UIF_flags) == 0) {
            ui_menu_uifconfirm_display(0);
            return 0;
        }
        G_gpg_vstate.UIF_flags = 0;
    }

    if (G_gpg_vstate.mse_aut->attributes.value[0] == KEY_ID_RSA) {
        if (G_gpg_vstate.io_length > U2BE(G_gpg_vstate.mse_aut->attributes.value, 1) * 40 / 100) {
            return SW_WRONG_LENGTH;
        }
    }
    return gpg_sign(G_gpg_vstate.mse_aut);
}
