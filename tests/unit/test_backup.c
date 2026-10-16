#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "gpg_vars.h"
#include "fake_assert.h"
#include "fake_digest.h"
#include "Mockgpg_ux.h"
#include "Mocklcx_aes.h"
#include "Mocklcx_aes_gcm.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_sha256.h"
#include "Mocklcx_sha3.h"
#include "Mockos_random.h"

#define TAG_LEN   16
#define NONCE_LEN 12
#define RSA2048   (2048 / 8)

static const uint8_t ATTR_RSA2048[] = {KEY_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};

/* ----------------------------------------------------------------------- */
/* Crypto stand-ins                                                        */
/* ----------------------------------------------------------------------- */

static cx_err_t fake_random(void *buffer, size_t len, int num_calls) {
    (void) num_calls;
    memset(buffer, 0x6E, len);
    return CX_OK;
}

// Toy AES-GCM: XOR with a key and nonce stream, tag over key, nonce, AAD and ciphertext
static uint8_t gcm_key[32];
static size_t gcm_key_len;

static cx_err_t fake_gcm_set_key(cx_aes_gcm_context_t *ctx,
                                 const uint8_t *raw_key,
                                 size_t key_len,
                                 int num_calls) {
    (void) ctx;
    (void) num_calls;
    TEST_ASSERT_TRUE(key_len <= sizeof(gcm_key));
    memcpy(gcm_key, raw_key, key_len);
    gcm_key_len = key_len;
    return CX_OK;
}

static uint8_t stream(const uint8_t *iv, size_t iv_len, size_t i) {
    return gcm_key[i % gcm_key_len] ^ iv[i % iv_len] ^ (uint8_t) (i * 13);
}

static void gcm_tag(const uint8_t *iv,
                    size_t iv_len,
                    const uint8_t *aad,
                    size_t aad_len,
                    const uint8_t *ct,
                    size_t len,
                    uint8_t *tag,
                    size_t tag_len) {
    uint32_t t = 2166136261u;

    for (size_t i = 0; i < gcm_key_len; i++) {
        t = (t ^ gcm_key[i]) * 16777619u;
    }
    for (size_t i = 0; i < iv_len; i++) {
        t = (t ^ iv[i]) * 16777619u;
    }
    for (size_t i = 0; i < aad_len; i++) {
        t = (t ^ aad[i]) * 16777619u;
    }
    for (size_t i = 0; i < len; i++) {
        t = (t ^ ct[i]) * 16777619u;
    }
    for (size_t i = 0; i < tag_len; i++) {
        t = (t ^ (uint8_t) i) * 16777619u;
        tag[i] = (uint8_t) (t >> 24);
    }
}

static uint8_t gcm_tmp[GPG_IO_BUFFER_LENGTH];

static void gcm_encrypt(const uint8_t *in,
                        size_t len,
                        const uint8_t *iv,
                        size_t iv_len,
                        const uint8_t *aad,
                        size_t aad_len,
                        uint8_t *out,
                        uint8_t *tag,
                        size_t tag_len) {
    for (size_t i = 0; i < len; i++) {
        gcm_tmp[i] = in[i] ^ stream(iv, iv_len, i);
    }
    memmove(out, gcm_tmp, len);
    gcm_tag(iv, iv_len, aad, aad_len, out, len, tag, tag_len);
}

static cx_err_t fake_gcm_encrypt(cx_aes_gcm_context_t *ctx,
                                 uint8_t *in,
                                 size_t len,
                                 const uint8_t *iv,
                                 size_t iv_len,
                                 const uint8_t *aad,
                                 size_t aad_len,
                                 uint8_t *out,
                                 uint8_t *tag,
                                 size_t tag_len,
                                 int num_calls) {
    (void) ctx;
    (void) num_calls;
    gcm_encrypt(in, len, iv, iv_len, aad, aad_len, out, tag, tag_len);
    return CX_OK;
}

static cx_err_t fake_gcm_decrypt(cx_aes_gcm_context_t *ctx,
                                 uint8_t *in,
                                 size_t len,
                                 const uint8_t *iv,
                                 size_t iv_len,
                                 const uint8_t *aad,
                                 size_t aad_len,
                                 uint8_t *out,
                                 const uint8_t *tag,
                                 size_t tag_len,
                                 int num_calls) {
    uint8_t expected[TAG_LEN];

    (void) ctx;
    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT(TAG_LEN, tag_len);
    // The AAD is authenticated before any output is written
    gcm_tag(iv, iv_len, aad, aad_len, in, len, expected, tag_len);
    if (memcmp(expected, tag, tag_len) != 0) {
        return CX_INVALID_PARAMETER;
    }
    for (size_t i = 0; i < len; i++) {
        gcm_tmp[i] = in[i] ^ stream(iv, iv_len, i);
    }
    memmove(out, gcm_tmp, len);
    return CX_OK;
}

// Toy AES-CBC for legacy blobs: XOR with the key, ISO 9797 method 2 padding
static cx_err_t fake_aes_init_key(const uint8_t *raw_key,
                                  size_t key_len,
                                  cx_aes_key_t *key,
                                  int num_calls) {
    (void) num_calls;
    key->size = key_len;
    memcpy(key->keys, raw_key, key_len);
    return CX_OK;
}

static size_t legacy_encrypt(const cx_aes_key_t *key, const uint8_t *in, size_t len, uint8_t *out) {
    size_t padded = (len / 16 + 1) * 16;

    memset(out, 0, padded);
    memcpy(out, in, len);
    out[len] = 0x80;
    for (size_t i = 0; i < padded; i++) {
        out[i] ^= key->keys[i % key->size];
    }
    return padded;
}

static cx_err_t fake_aes(const cx_aes_key_t *key,
                         uint32_t mode,
                         const uint8_t *in,
                         size_t in_len,
                         uint8_t *out,
                         size_t *out_len,
                         int num_calls) {
    size_t len = in_len;

    (void) num_calls;
    TEST_ASSERT_EQUAL_UINT32(CX_DECRYPT | CX_CHAIN_CBC | CX_PAD_ISO9797M2 | CX_LAST, mode);
    if ((in_len == 0) || (in_len % 16) || (in_len > *out_len)) {
        return CX_INVALID_PARAMETER;
    }
    for (size_t i = 0; i < in_len; i++) {
        gcm_tmp[i] = in[i] ^ key->keys[i % key->size];
    }
    while ((len > 0) && (gcm_tmp[len - 1] == 0)) {
        len--;
    }
    if ((len == 0) || (gcm_tmp[len - 1] != 0x80)) {
        return CX_INVALID_PARAMETER;
    }
    memmove(out, gcm_tmp, len - 1);
    *out_len = len - 1;
    return CX_OK;
}

/* ----------------------------------------------------------------------- */
/* Setup                                                                   */
/* ----------------------------------------------------------------------- */

void setUp(void) {
    memset(&G_gpg_vstate, 0, sizeof(G_gpg_vstate));
    memset((void *) N_gpg_pstate, 0, sizeof(gpg_nv_state_t));
    gcm_key_len = 0;

    Mockgpg_ux_Init();
    Mocklcx_aes_Init();
    Mocklcx_aes_gcm_Init();
    Mocklcx_hash_Init();
    Mocklcx_sha256_Init();
    Mocklcx_sha3_Init();
    Mockos_random_Init();
    fake_digest_install();
    cx_get_random_bytes_StubWithCallback(fake_random);
    cx_aes_gcm_init_Ignore();
    cx_aes_gcm_set_key_StubWithCallback(fake_gcm_set_key);
    cx_aes_gcm_encrypt_and_tag_StubWithCallback(fake_gcm_encrypt);
    cx_aes_gcm_decrypt_and_auth_StubWithCallback(fake_gcm_decrypt);
    cx_aes_init_key_no_throw_StubWithCallback(fake_aes_init_key);
    cx_aes_no_throw_StubWithCallback(fake_aes);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(0));
}

void tearDown(void) {
    Mockgpg_ux_Verify();
    Mockgpg_ux_Destroy();
    Mocklcx_aes_Destroy();
    Mocklcx_aes_gcm_Destroy();
    Mocklcx_hash_Destroy();
    Mocklcx_sha256_Destroy();
    Mocklcx_sha3_Destroy();
    Mockos_random_Destroy();
}

/* ----------------------------------------------------------------------- */
/* Keys and commands                                                       */
/* ----------------------------------------------------------------------- */

static void set_rsa2048(gpg_key_t *key) {
    memcpy((void *) key->attributes.value, ATTR_RSA2048, sizeof(ATTR_RSA2048));
    key->attributes.length = sizeof(ATTR_RSA2048);
    memset((void *) &key->priv_key.rsa2048, 0xC5, sizeof(key->priv_key.rsa2048));
    key->priv_key.rsa2048.size = RSA2048;
    key->pub_key.rsa[0] = 0x00;
    key->pub_key.rsa[1] = 0x01;
    key->pub_key.rsa[2] = 0x00;
    key->pub_key.rsa[3] = 0x01;
}

static void set_ed25519(gpg_key_t *key) {
    key->attributes.value[0] = KEY_ID_EDDSA;
    memcpy((void *) (key->attributes.value + 1), C_OID_Ed25519, sizeof(C_OID_Ed25519));
    key->attributes.length = 1 + sizeof(C_OID_Ed25519);
    memset((void *) &key->priv_key.ecfp640, 0xE5, sizeof(key->priv_key.ecfp640));
    memset((void *) &key->pub_key.ecfp640, 0x9B, sizeof(key->pub_key.ecfp640));
}

// Erase the key material, keeping the attributes
static void erase_key(gpg_key_t *key) {
    memset((void *) &key->priv_key, 0, sizeof(key->priv_key));
    memset((void *) &key->pub_key, 0, sizeof(key->pub_key));
}

static uint8_t blob[GPG_IO_BUFFER_LENGTH];
static size_t blob_len;

static int backup(unsigned int ref) {
    int sw = gpg_apdu_get_key_data(ref);

    blob_len = G_gpg_vstate.io_length;
    memcpy(blob, G_gpg_vstate.work.io_buffer, blob_len);
    return sw;
}

static int restore(unsigned int ref, const uint8_t *data, size_t len) {
    gpg_io_discard(1);
    if (len != 0) {
        gpg_io_insert(data, len);
        gpg_io_set_offset(0);
    }
    return gpg_apdu_put_key_data(ref);
}

/* ----------------------------------------------------------------------- */
/* Backup and restore with the current format                              */
/* ----------------------------------------------------------------------- */

static void test_restore_rsa(void) {
    gpg_key_t saved;

    set_rsa2048(&G_gpg_vstate.kslot->sig);
    memcpy(&saved, (const void *) &G_gpg_vstate.kslot->sig, sizeof(saved));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_SIG));
    erase_key(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, restore(KEY_SIG, blob, blob_len));

    TEST_ASSERT_EQUAL_MEMORY(&saved.priv_key.rsa2048,
                             &G_gpg_vstate.kslot->sig.priv_key.rsa2048,
                             sizeof(saved.priv_key.rsa2048));
    TEST_ASSERT_EQUAL_MEMORY(saved.pub_key.rsa, G_gpg_vstate.kslot->sig.pub_key.rsa, 4);
    // The decrypted key does not stay in the IO buffer
    TEST_ASSERT_EQUAL_UINT(0, G_gpg_vstate.io_length);
    TEST_ASSERT_EACH_EQUAL_UINT8(0, G_gpg_vstate.work.io_buffer, GPG_IO_BUFFER_LENGTH);
}

static void test_restore_ecc(void) {
    gpg_key_t saved;

    set_ed25519(&G_gpg_vstate.kslot->aut);
    memcpy(&saved, (const void *) &G_gpg_vstate.kslot->aut, sizeof(saved));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_AUT));
    erase_key(&G_gpg_vstate.kslot->aut);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, restore(KEY_AUT, blob, blob_len));

    TEST_ASSERT_EQUAL_MEMORY(&saved.priv_key.ecfp640,
                             &G_gpg_vstate.kslot->aut.priv_key.ecfp640,
                             sizeof(saved.priv_key.ecfp640));
    TEST_ASSERT_EQUAL_MEMORY(&saved.pub_key.ecfp640,
                             &G_gpg_vstate.kslot->aut.pub_key.ecfp640,
                             sizeof(saved.pub_key.ecfp640));
}

static void test_backup_format(void) {
    size_t n = 0;

    set_ed25519(&G_gpg_vstate.kslot->dec);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_DEC));

    // Version 3, random nonce, key role and attributes, all authenticated
    TEST_ASSERT_EQUAL_HEX8(0x03, blob[n++]);
    TEST_ASSERT_EACH_EQUAL_HEX8(0x6E, blob + n, NONCE_LEN);
    n += NONCE_LEN;
    TEST_ASSERT_EQUAL_HEX8(0x00, blob[n++]);
    TEST_ASSERT_EQUAL_HEX8(KEY_DEC, blob[n++]);
    TEST_ASSERT_EQUAL_UINT8(G_gpg_vstate.kslot->dec.attributes.length, blob[n++]);
    n += G_gpg_vstate.kslot->dec.attributes.length;
    // Public key, then the encrypted private key with its tag
    TEST_ASSERT_EQUAL_UINT32(sizeof(cx_ecfp_640_public_key_t), U4BE(blob, n));
    n += 4 + sizeof(cx_ecfp_640_public_key_t);
    TEST_ASSERT_EQUAL_UINT32(sizeof(cx_ecfp_640_private_key_t) + TAG_LEN, U4BE(blob, n));
    n += 4 + sizeof(cx_ecfp_640_private_key_t) + TAG_LEN;
    TEST_ASSERT_EQUAL_UINT(n, blob_len);
}

static void test_backup_full_key_derivation(void) {
    // The backup key is derived on its full 128 bits
    set_ed25519(&G_gpg_vstate.kslot->dec);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_DEC));
    TEST_ASSERT_EQUAL_UINT(128, fake_shake_bits);
    TEST_ASSERT_EQUAL_UINT(16, gcm_key_len);
}

static void test_backup_no_key(void) {
    // RSA attributes without a key of that size
    set_rsa2048(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.priv_key.rsa2048.size = 0;
    TEST_ASSERT_EQUAL_HEX16(SWO_CONDITIONS_NOT_SATISFIED, backup(KEY_SIG));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, backup(0x00B7));
}

static void test_restore_other_role(void) {
    // A backup of the signature key cannot be restored as the decryption key
    set_ed25519(&G_gpg_vstate.kslot->sig);
    set_ed25519(&G_gpg_vstate.kslot->dec);
    erase_key(&G_gpg_vstate.kslot->dec);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_SIG));

    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, restore(KEY_DEC, blob, blob_len));
    TEST_ASSERT_EACH_EQUAL_HEX8(0,
                                (const uint8_t *) &G_gpg_vstate.kslot->dec.priv_key,
                                sizeof(G_gpg_vstate.kslot->dec.priv_key));
}

static void test_restore_other_attributes(void) {
    set_ed25519(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_SIG));

    set_rsa2048(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, restore(KEY_SIG, blob, blob_len));
}

static void test_restore_other_slot(void) {
    // The backup key depends on the slot
    set_ed25519(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_SIG));

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_select_slot(1));
    set_ed25519(&G_gpg_vstate.kslot->sig);
    erase_key(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_NOT_EQUAL_HEX16(SWO_SUCCESS, restore(KEY_SIG, blob, blob_len));
    TEST_ASSERT_EACH_EQUAL_HEX8(0,
                                (const uint8_t *) &G_gpg_vstate.kslot->sig.priv_key,
                                sizeof(G_gpg_vstate.kslot->sig.priv_key));
}

static void check_restore_refused(unsigned int ref,
                                  gpg_key_t *key,
                                  const uint8_t *data,
                                  size_t len) {
    gpg_key_t saved;

    memcpy(&saved, (const void *) key, sizeof(saved));
    TEST_ASSERT_NOT_EQUAL_HEX16(SWO_SUCCESS, restore(ref, data, len));
    TEST_ASSERT_EQUAL_MEMORY(&saved, (const void *) key, sizeof(saved));
}

static void test_restore_tampered(void) {
    static uint8_t tampered[GPG_IO_BUFFER_LENGTH];

    set_rsa2048(&G_gpg_vstate.kslot->sig);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_SIG));
    erase_key(&G_gpg_vstate.kslot->sig);
    G_gpg_vstate.kslot->sig.priv_key.rsa2048.size = 0x5A5A;

    // Any modified byte is refused, and the key left as it is
    for (size_t i = 0; i < blob_len; i++) {
        memcpy(tampered, blob, blob_len);
        tampered[i] ^= 0x01;
        check_restore_refused(KEY_SIG, &G_gpg_vstate.kslot->sig, tampered, blob_len);
    }
}

static void test_restore_truncated(void) {
    set_ed25519(&G_gpg_vstate.kslot->aut);
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, backup(KEY_AUT));
    erase_key(&G_gpg_vstate.kslot->aut);

    // Every truncation is refused without asserting, and the key left as it is
    for (size_t len = 0; len < blob_len; len++) {
        check_restore_refused(KEY_AUT, &G_gpg_vstate.kslot->aut, blob, len);
    }
}

static void test_restore_bad_reference(void) {
    TEST_ASSERT_EQUAL_HEX16(SWO_INCORRECT_DATA, restore(0xB7, blob, 1));
}

/* ----------------------------------------------------------------------- */
/* Older formats                                                           */
/* ----------------------------------------------------------------------- */

// Build a v1 or v2 GCM blob of an Ed25519 key, as written by older versions
static size_t build_gcm_blob(unsigned char version, unsigned int ref, const gpg_key_t *key) {
    unsigned char seed[32];
    uint8_t nonce[NONCE_LEN] = {0};
    size_t n = 0;
    size_t aad_len;

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed));
    if (version == 1) {
        TEST_ASSERT_EQUAL_HEX16(
            SWO_SUCCESS,
            gpg_pso_derive_key_seed(seed, (unsigned char *) "key ", 1, seed, 16));
        nonce[0] = G_gpg_vstate.slot;
        nonce[1] = (uint8_t) (ref >> 8);
        nonce[2] = (uint8_t) ref;
    } else {
        TEST_ASSERT_EQUAL_HEX16(
            SWO_SUCCESS,
            gpg_pso_derive_key_seed_full(seed, (unsigned char *) "key ", 1, seed, 16));
        memset(nonce, 0x4E, sizeof(nonce));
    }
    memcpy(gcm_key, seed, 16);
    gcm_key_len = 16;

    blob[n++] = version;
    U4BE_ENCODE(blob, n, 0x33000004);  // TARGET_ID
    n += 4;
    U4BE_ENCODE(blob, n, 25);  // API level
    n += 4;
    if (version == 2) {
        memcpy(blob + n, nonce, sizeof(nonce));
        n += sizeof(nonce);
    }
    U4BE_ENCODE(blob, n, sizeof(cx_ecfp_640_public_key_t));
    n += 4;
    memcpy(blob + n, (const void *) &key->pub_key.ecfp640, sizeof(cx_ecfp_640_public_key_t));
    n += sizeof(cx_ecfp_640_public_key_t);
    aad_len = n;
    U4BE_ENCODE(blob, n, sizeof(cx_ecfp_640_private_key_t) + TAG_LEN);
    n += 4;
    gcm_encrypt((const uint8_t *) &key->priv_key.ecfp640,
                sizeof(cx_ecfp_640_private_key_t),
                nonce,
                sizeof(nonce),
                blob,
                aad_len,
                blob + n,
                blob + n + sizeof(cx_ecfp_640_private_key_t),
                TAG_LEN);
    n += sizeof(cx_ecfp_640_private_key_t) + TAG_LEN;
    return n;
}

static void check_older_format(unsigned char version) {
    gpg_key_t saved;

    set_ed25519(&G_gpg_vstate.kslot->sig);
    memcpy(&saved, (const void *) &G_gpg_vstate.kslot->sig, sizeof(saved));
    blob_len = build_gcm_blob(version, KEY_SIG, &saved);
    erase_key(&G_gpg_vstate.kslot->sig);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, restore(KEY_SIG, blob, blob_len));
    TEST_ASSERT_EQUAL_MEMORY(&saved.priv_key.ecfp640,
                             &G_gpg_vstate.kslot->sig.priv_key.ecfp640,
                             sizeof(saved.priv_key.ecfp640));
}

static void test_restore_v1(void) {
    check_older_format(1);
}

static void test_restore_v2(void) {
    check_older_format(2);
}

static void test_restore_v1_tampered(void) {
    static uint8_t tampered[GPG_IO_BUFFER_LENGTH];

    set_ed25519(&G_gpg_vstate.kslot->sig);
    blob_len = build_gcm_blob(1, KEY_SIG, (const gpg_key_t *) &G_gpg_vstate.kslot->sig);
    erase_key(&G_gpg_vstate.kslot->sig);

    // TARGET_ID and API level are not checked, everything else is authenticated
    for (size_t i = 9; i < blob_len; i++) {
        memcpy(tampered, blob, blob_len);
        tampered[i] ^= 0x01;
        check_restore_refused(KEY_SIG, &G_gpg_vstate.kslot->sig, tampered, blob_len);
    }
}

// Build a legacy AES-CBC blob of an Ed25519 key
static size_t build_legacy_blob(const gpg_key_t *key) {
    unsigned char seed[32];
    cx_aes_key_t keyenc;
    size_t n = 0;

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, gpg_pso_derive_slot_seed(G_gpg_vstate.slot, seed));
    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS,
                            gpg_pso_derive_key_seed(seed, (unsigned char *) "key ", 1, seed, 16));
    keyenc.size = 16;
    memcpy(keyenc.keys, seed, 16);

    U4BE_ENCODE(blob, n, 0x33000004);  // TARGET_ID, never a version number
    n += 4;
    U4BE_ENCODE(blob, n, 25);  // API level
    n += 4;
    U4BE_ENCODE(blob, n, sizeof(cx_ecfp_640_public_key_t));
    n += 4;
    memcpy(blob + n, (const void *) &key->pub_key.ecfp640, sizeof(cx_ecfp_640_public_key_t));
    n += sizeof(cx_ecfp_640_public_key_t);
    size_t enc_len = legacy_encrypt(&keyenc,
                                    (const uint8_t *) &key->priv_key.ecfp640,
                                    sizeof(cx_ecfp_640_private_key_t),
                                    blob + n + 4);
    U4BE_ENCODE(blob, n, enc_len);
    return n + 4 + enc_len;
}

static void test_restore_legacy(void) {
    gpg_key_t saved;

    set_ed25519(&G_gpg_vstate.kslot->dec);
    memcpy(&saved, (const void *) &G_gpg_vstate.kslot->dec, sizeof(saved));
    blob_len = build_legacy_blob(&saved);
    erase_key(&G_gpg_vstate.kslot->dec);

    TEST_ASSERT_EQUAL_HEX16(SWO_SUCCESS, restore(KEY_DEC, blob, blob_len));
    TEST_ASSERT_EQUAL_MEMORY(&saved.priv_key.ecfp640,
                             &G_gpg_vstate.kslot->dec.priv_key.ecfp640,
                             sizeof(saved.priv_key.ecfp640));
}

static void test_restore_legacy_truncated(void) {
    set_ed25519(&G_gpg_vstate.kslot->dec);
    blob_len = build_legacy_blob((const gpg_key_t *) &G_gpg_vstate.kslot->dec);
    erase_key(&G_gpg_vstate.kslot->dec);

    for (size_t len = 0; len < blob_len; len++) {
        check_restore_refused(KEY_DEC, &G_gpg_vstate.kslot->dec, blob, len);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_restore_rsa);
    RUN_TEST(test_restore_ecc);
    RUN_TEST(test_backup_format);
    RUN_TEST(test_backup_full_key_derivation);
    RUN_TEST(test_backup_no_key);
    RUN_TEST(test_restore_other_role);
    RUN_TEST(test_restore_other_attributes);
    RUN_TEST(test_restore_other_slot);
    RUN_TEST(test_restore_tampered);
    RUN_TEST(test_restore_truncated);
    RUN_TEST(test_restore_bad_reference);
    RUN_TEST(test_restore_v1);
    RUN_TEST(test_restore_v2);
    RUN_TEST(test_restore_v1_tampered);
    RUN_TEST(test_restore_legacy);
    RUN_TEST(test_restore_legacy_truncated);
    return UNITY_END();
}
