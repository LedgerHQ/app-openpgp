
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
#if defined(HAVE_NBGL) && defined(TARGET_STAX)

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "gpg_vars.h"
#include "gpg_ux_msg.h"
#include "gpg_ux.h"
#include "usbd_ccid_if.h"

/* ----------------------------------------------------------------------- */
/* ---                        NBGL  UI layout                          --- */
/* ----------------------------------------------------------------------- */
static void ui_menu_slot_action();
static void ui_settings_template(void);
static void ui_settings_seed(void);
static void ui_settings_pin(void);
static void ui_settings_uif(void);
static void ui_reset(void);

// context for background and modal pages
static nbgl_layout_t layoutCtx = {0};
static uint8_t setting_initPage;

/* ------------------------------- Helpers  UX ------------------------------- */

/**
 * Display popup message on screen
 *
 * @param[in] msg1 1st part of the message
 * @param[in] msg2 2nd part of the message
 *
 */
static void ui_info(const char* msg1, const char* msg2, nbgl_callback_t cb, bool isSuccess) {
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s\n%s", msg1, msg2);

    nbgl_useCaseStatus((const char*) G_gpg_vstate.menu, isSuccess, cb);
};

/**
 * Display Setting page header
 *
 * @param[in] title page title
 * @param[in] back_token token for back button
 * @param[in] touch_cb action callback
 *
 */
static void ui_setting_header(const char* title,
                              uint8_t back_token,
                              nbgl_layoutTouchCallback_t touch_cb) {
    nbgl_layoutDescription_t layoutDescription = {0};
    nbgl_layoutBar_t bar = {0};

    layoutDescription.onActionCallback = touch_cb;
    layoutDescription.modal = false;
    layoutCtx = nbgl_layoutGet(&layoutDescription);

    explicit_bzero(&bar, sizeof(nbgl_layoutBar_t));
    bar.text = PIC(title);
    bar.iconLeft = &LEFT_ARROW_ICON;
    bar.token = back_token;
    bar.centered = true;
    bar.inactive = false;
    bar.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddTouchableBar(layoutCtx, &bar);
    nbgl_layoutAddSeparationLine(layoutCtx);
}

//  -----------------------------------------------------------
//  ----------------------- HOME PAGE -------------------------
//  -----------------------------------------------------------

enum {
    TOKEN_SETTINGS_TEMPLATE = FIRST_USER_TOKEN,
    TOKEN_SETTINGS_SEED,
    TOKEN_SETTINGS_PIN,
    TOKEN_SETTINGS_UIF,
    TOKEN_SETTINGS_RESET,
};

/**
 * Settings callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void controlsCallback(int token, uint8_t index, int page) {
    UNUSED(index);
    setting_initPage = page;
    switch (token) {
        case TOKEN_SETTINGS_TEMPLATE:
            ui_settings_template();
            break;
        case TOKEN_SETTINGS_SEED:
            ui_settings_seed();
            break;
        case TOKEN_SETTINGS_PIN:
            ui_settings_pin();
            break;
        case TOKEN_SETTINGS_UIF:
            ui_settings_uif();
            break;
        case TOKEN_SETTINGS_RESET:
            ui_reset();
            break;
    }
}

/**
 * home page display
 *
 */
static void ui_home_init(void) {
    char name[32];
    unsigned int serial = U4BE(G_gpg_vstate.kslot->serial, 0);

    explicit_bzero(name, sizeof(name));
    memmove(name, (void*) (N_gpg_pstate->name.value), 20);
    if (name[0] != 0) {
        for (int i = 0; i < 12; i++) {
            if ((name[i] == '<') || (name[i] == '>')) {
                name[i] = ' ';
            }
        }
    }
    explicit_bzero(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu));
    snprintf(G_gpg_vstate.menu,
             sizeof(G_gpg_vstate.menu),
             "%s\nID: %x / %d",
             name,
             serial,
             G_gpg_vstate.slot + 1);

    static nbgl_contentInfoList_t infosList = {0};

    static const char* const infoTypes[] = {"Version", "Specifications", "Developer"};
    static const char* const infoContents[] = {APPVERSION, XSTR(SPEC_VERSION), "(c) 2024 Ledger"};

    infosList.nbInfos = ARRAYLEN(infoTypes);
    infosList.infoTypes = (const char**) infoTypes;
    infosList.infoContents = (const char**) infoContents;

    static nbgl_content_t contents = {0};
    static nbgl_genericContents_t settingContents = {0};

    static const char* const barTexts[] = {"Key Template",
                                           "Seed mode",
                                           "Pin mode",
                                           "UIF mode",
                                           "Reset"};
    static const uint8_t barTokens[] = {TOKEN_SETTINGS_TEMPLATE,
                                        TOKEN_SETTINGS_SEED,
                                        TOKEN_SETTINGS_PIN,
                                        TOKEN_SETTINGS_UIF,
                                        TOKEN_SETTINGS_RESET};
    contents.type = BARS_LIST;
    contents.content.barsList.barTexts = barTexts;
    contents.content.barsList.tokens = barTokens;
    contents.content.barsList.nbBars = ARRAYLEN(barTexts);
    contents.content.barsList.tuneId = TUNE_TAP_CASUAL;
    contents.contentActionCallback = controlsCallback;

    settingContents.callbackCallNeeded = false;
    settingContents.contentsList = &contents;
    settingContents.nbContents = 1;

    static nbgl_homeAction_t actionContent = {0};
    actionContent.text = "Select Slot";
    actionContent.callback = ui_menu_slot_action;

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_gpg_64px,
                                G_gpg_vstate.menu,
                                setting_initPage,
                                &settingContents,
                                &infosList,
                                &actionContent,
                                app_quit);
}

/**
 * home page init
 *
 */
void ui_init(void) {
    setting_initPage = INIT_HOME_PAGE;
    ui_home_init();
}

//  -----------------------------------------------------------
//  ------------------------ SLOT UX --------------------------
//  -----------------------------------------------------------

enum {
    TOKEN_SLOT_SELECT = FIRST_USER_TOKEN,
    TOKEN_SLOT_DEF,
    TOKEN_SLOT_BACK,
};

/**
 * Slot Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void slot_cb(int token, uint8_t index) {
    switch (token) {
        case TOKEN_SLOT_BACK:
            ui_init();
            break;
        case TOKEN_SLOT_SELECT:
            if (index != G_gpg_vstate.slot) {
                G_gpg_vstate.slot = index;
                G_gpg_vstate.kslot = (gpg_key_slot_t*) &N_gpg_pstate->keys[G_gpg_vstate.slot];
                gpg_mse_reset();
                ui_CCID_reset();
            }
            break;
        case TOKEN_SLOT_DEF:
            nvm_write((void*) (&N_gpg_pstate->config_slot[1]), &G_gpg_vstate.slot, 1);
            ui_menu_slot_action();
            break;
        default:
            break;
    }
}

/**
 * Slot Navigation callback
 *
 */
static void ui_menu_slot_action(void) {
    nbgl_layoutRadioChoice_t choices = {0};
    nbgl_layoutButton_t buttonInfo = {0};
    static char* names[GPG_KEYS_SLOTS] = {0};
    static char text[GPG_KEYS_SLOTS][32];
    uint32_t slot;

    ui_setting_header("Slots configuration", TOKEN_SLOT_BACK, slot_cb);

    for (slot = 0; slot < GPG_KEYS_SLOTS; slot++) {
        snprintf(text[slot],
                 sizeof(text[slot]),
                 "Slot %d %s",
                 (slot + 1),
                 (N_gpg_pstate->config_slot[1] == slot) ? "[default]" : "");
        names[slot] = text[slot];
    }
    choices.names = (const char* const*) names;
    choices.localized = false;
    choices.nbChoices = GPG_KEYS_SLOTS;
    choices.initChoice = G_gpg_vstate.slot;
    choices.token = TOKEN_SLOT_SELECT;
    nbgl_layoutAddRadioChoice(layoutCtx, &choices);

    buttonInfo.fittingContent = false;
    buttonInfo.onBottom = true;
    buttonInfo.style = BLACK_BACKGROUND;
    buttonInfo.text = "Set default";
    buttonInfo.token = TOKEN_SLOT_DEF;
    buttonInfo.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddButton(layoutCtx, &buttonInfo);

    nbgl_layoutDraw(layoutCtx);
}

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------

/* ------------------------------- TEMPLATE UX ------------------------------- */

enum {
    TOKEN_TEMPLATE_SIG = FIRST_USER_TOKEN,
    TOKEN_TEMPLATE_DEC,
    TOKEN_TEMPLATE_AUT,
    TOKEN_TEMPLATE_SET,
    TOKEN_TEMPLATE_BACK
};

static const char* const keyNameTexts[] = {LABEL_SIG, LABEL_DEC, LABEL_AUT};

enum {
    TOKEN_TYPE_RSA2048 = FIRST_USER_TOKEN,
    TOKEN_TYPE_RSA3072,
#ifdef WITH_SUPPORT_RSA4096
    TOKEN_TYPE_RSA4096,
#endif
    TOKEN_TYPE_SECP256K1,
    TOKEN_TYPE_SECP256R1,
    TOKEN_TYPE_Ed25519,
    TOKEN_TYPE_BACK
};

static const char* const keyTypeTexts[] = {LABEL_RSA2048,
                                           LABEL_RSA3072,
#ifdef WITH_SUPPORT_RSA4096
                                           LABEL_RSA4096,
#endif
                                           LABEL_SECP256K1,
                                           LABEL_SECP256R1,
                                           LABEL_Ed25519};

/**
 * Determine the selected key type from its attributes
 *
 * @param[in] key token describing the selected key
 *
 * @return token describing the selected key type
 *
 */
static uint32_t _getKeyType(const uint8_t key) {
    uint8_t* attributes = NULL;
    uint32_t token = 0;

    switch (key) {
        case TOKEN_TEMPLATE_SIG:
            attributes = G_gpg_vstate.kslot->sig.attributes.value;
            break;
        case TOKEN_TEMPLATE_DEC:
            attributes = G_gpg_vstate.kslot->dec.attributes.value;
            break;
        case TOKEN_TEMPLATE_AUT:
            attributes = G_gpg_vstate.kslot->aut.attributes.value;
            break;
    }
    if (attributes == NULL) {
        return 0;
    }
    switch (attributes[0]) {
        case KEY_ID_RSA:
            switch (U2BE(attributes, 1)) {
                case 2048:
                    token = TOKEN_TYPE_RSA2048;
                    break;
                case 3072:
                    token = TOKEN_TYPE_RSA3072;
                    break;
#ifdef WITH_SUPPORT_RSA4096
                case 4096:
                    token = TOKEN_TYPE_RSA4096;
                    break;
#endif
            }
            break;
        case KEY_ID_ECDH:
            switch (attributes[1]) {
                case 0x2A:
                    token = TOKEN_TYPE_SECP256R1;
                    break;
                case 0x2B:
                    switch (attributes[2]) {
                        case 0x06:
                            token = TOKEN_TYPE_Ed25519;
                            break;
                        case 0x81:
                            token = TOKEN_TYPE_SECP256K1;
                            break;
                    }
                    break;
            }
            break;
        case KEY_ID_ECDSA:
            switch (attributes[1]) {
                case 0x2A:
                    token = TOKEN_TYPE_SECP256R1;
                    break;
                case 0x2B:
                    token = TOKEN_TYPE_SECP256K1;
                    break;
            }
            break;
        case KEY_ID_EDDSA:
            token = TOKEN_TYPE_Ed25519;
            break;
    }
    return token;
}

/**
 * Key Template Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void template_key_cb(int token, uint8_t index) {
    LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
    gpg_key_t* dest = NULL;
    static uint8_t* oid = NULL;
    uint32_t oid_len = 0;
    uint32_t size = 0;
    uint8_t key_type = index + FIRST_USER_TOKEN;

    if (token != TOKEN_TYPE_BACK) {
        explicit_bzero(&attributes, sizeof(attributes));
        switch (key_type) {
            case TOKEN_TYPE_RSA2048:
            case TOKEN_TYPE_RSA3072:
#ifdef WITH_SUPPORT_RSA4096
            case TOKEN_TYPE_RSA4096:
#endif
                switch (key_type) {
                    case TOKEN_TYPE_RSA2048:
                        size = 2048;
                        break;
                    case TOKEN_TYPE_RSA3072:
                        size = 3072;
                        break;
#ifdef WITH_SUPPORT_RSA4096
                    case TOKEN_TYPE_RSA4096:
                        size = 4096;
                        break;
#endif
                }
                attributes.value[0] = KEY_ID_RSA;
                U2BE_ENCODE(attributes.value, 1, size);
                attributes.value[3] = 0x00;
                attributes.value[4] = 0x20;
                attributes.value[5] = 0x01;
                attributes.length = 6;
                oid_len = 6;
                break;

            case TOKEN_TYPE_SECP256K1:
                if (G_gpg_vstate.ux_key == TOKEN_TEMPLATE_DEC) {
                    attributes.value[0] = KEY_ID_ECDH;
                } else {
                    attributes.value[0] = KEY_ID_ECDSA;
                }
                oid = gpg_curve2oid(CX_CURVE_SECP256K1, &oid_len);
                memmove(attributes.value + 1, oid, oid_len);
                attributes.length = 1 + oid_len;
                break;

            case TOKEN_TYPE_SECP256R1:
                if (G_gpg_vstate.ux_key == TOKEN_TEMPLATE_DEC) {
                    attributes.value[0] = KEY_ID_ECDH;
                } else {
                    attributes.value[0] = KEY_ID_ECDSA;
                }
                oid = gpg_curve2oid(CX_CURVE_SECP256R1, &oid_len);
                memmove(attributes.value + 1, oid, oid_len);
                attributes.length = 1 + oid_len;
                break;

            case TOKEN_TYPE_Ed25519:
                if (G_gpg_vstate.ux_key == TOKEN_TEMPLATE_DEC) {
                    attributes.value[0] = KEY_ID_ECDH;
                    oid = gpg_curve2oid(CX_CURVE_Curve25519, &oid_len);
                } else {
                    attributes.value[0] = KEY_ID_EDDSA;
                    oid = gpg_curve2oid(CX_CURVE_Ed25519, &oid_len);
                }
                memmove(attributes.value + 1, oid, oid_len);
                attributes.length = 1 + oid_len;
                break;
        }

        switch (G_gpg_vstate.ux_key) {
            case TOKEN_TEMPLATE_SIG:
                dest = &G_gpg_vstate.kslot->sig;
                break;
            case TOKEN_TEMPLATE_DEC:
                dest = &G_gpg_vstate.kslot->dec;
                break;
            case TOKEN_TEMPLATE_AUT:
                dest = &G_gpg_vstate.kslot->aut;
                break;
        }

        if (dest && attributes.value[0] &&
            memcmp(&dest->attributes, &attributes, sizeof(attributes)) != 0) {
            nvm_write(dest, NULL, sizeof(gpg_key_t));
            nvm_write(&dest->attributes, &attributes, sizeof(attributes));
        }
    }
    ui_settings_template();
}

/**
 * Template Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void template_cb(int token, uint8_t index) {
    UNUSED(index);
    static nbgl_layoutRadioChoice_t choices = {0};

    switch (token) {
        case TOKEN_TEMPLATE_BACK:
            ui_home_init();
            break;
        case TOKEN_TEMPLATE_SIG:
        case TOKEN_TEMPLATE_DEC:
        case TOKEN_TEMPLATE_AUT:
            G_gpg_vstate.ux_key = token;
            ui_setting_header(keyNameTexts[token - FIRST_USER_TOKEN],
                              TOKEN_TYPE_BACK,
                              template_key_cb);

            choices.names = (const char* const*) keyTypeTexts;
            choices.nbChoices = ARRAYLEN(keyTypeTexts);
            choices.initChoice = _getKeyType(token) - FIRST_USER_TOKEN;
            choices.token = token;
            nbgl_layoutAddRadioChoice(layoutCtx, &choices);

            nbgl_layoutDraw(layoutCtx);
            break;
    }
}

/**
 * Template Settings menu
 *
 */
static void ui_settings_template(void) {
    nbgl_layoutBar_t bar = {0};
    uint32_t i;

    G_gpg_vstate.ux_key = 0;

    ui_setting_header("Keys templates", TOKEN_TEMPLATE_BACK, template_cb);

    for (i = 0; i < KEY_NB; i++) {
        explicit_bzero(&bar, sizeof(nbgl_layoutBar_t));
        switch (_getKeyType(TOKEN_TEMPLATE_SIG + i)) {
            case TOKEN_TYPE_RSA2048:
                bar.subText = PIC(LABEL_RSA2048);
                break;
            case TOKEN_TYPE_RSA3072:
                bar.subText = PIC(LABEL_RSA3072);
                break;
#ifdef WITH_SUPPORT_RSA4096
            case TOKEN_TYPE_RSA4096:
                bar.subText = PIC(LABEL_RSA4096);
                break;
#endif
            case TOKEN_TYPE_SECP256K1:
                bar.subText = PIC(LABEL_SECP256K1);
                break;
            case TOKEN_TYPE_SECP256R1:
                bar.subText = PIC(LABEL_SECP256R1);
                break;
            case TOKEN_TYPE_Ed25519:
                bar.subText = PIC(LABEL_Ed25519);
                break;
            default:
                break;
        }
        bar.text = PIC(keyNameTexts[i]);
        bar.iconRight = &RIGHT_ARROW_ICON;
        bar.token = TOKEN_TEMPLATE_SIG + i;
        bar.centered = false;
        bar.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddTouchableBar(layoutCtx, &bar);
        nbgl_layoutAddSeparationLine(layoutCtx);
    }

    nbgl_layoutDraw(layoutCtx);
}

/* --------------------------------- SEED UX --------------------------------- */

enum {
    TOKEN_SEED = FIRST_USER_TOKEN,
    TOKEN_SEED_BACK,
};

/**
 * Seed Mode Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void seed_confirm_cb(bool confirm) {
    if (confirm) {
        G_gpg_vstate.seed_mode = 0;
        ui_info("SEED MODE", "DEACTIVATED", ui_settings_seed, true);
    } else {
        G_gpg_vstate.seed_mode = 1;
        ui_settings_seed();
    }
}

/**
 * Seed Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void seed_cb(int token, uint8_t index) {
    switch (token) {
        case TOKEN_SEED_BACK:
            ui_home_init();
            break;
        case TOKEN_SEED:
            if (index == 0) {
                nbgl_useCaseChoice(NULL,
                                   "SEED mode",
                                   "This mode allows to derive your key from Master SEED.\n"
                                   "Without such configuration, an OS or App update "
                                   "will cause your private key to be lost!\n"
                                   "Are you sure you want to disable SEED mode?",
                                   "Deactivate",
                                   "Cancel",
                                   seed_confirm_cb);
            }
            break;
    }
}

/**
 * Seed Settings menu
 *
 */
static void ui_settings_seed(void) {
    static nbgl_layoutSwitch_t option = {0};

    ui_setting_header("Seed mode", TOKEN_SEED_BACK, seed_cb);

    option.initState = G_gpg_vstate.seed_mode;
    option.text = "Seed Mode";
    option.subText = "Key derivation from Master seed";
    option.token = TOKEN_SEED;
    option.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddSwitch(layoutCtx, &option);

    nbgl_layoutDraw(layoutCtx);
}

/* --------------------------------- PIN UX ---------------------------------- */

enum {
    TOKEN_PIN_SET = FIRST_USER_TOKEN,
    TOKEN_PIN_DEF,
    TOKEN_PIN_BACK,
};

/**
 * Trust Mode Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void trust_cb(bool confirm) {
    if (confirm) {
        G_gpg_vstate.pinmode = G_gpg_vstate.pinmode_req;
        ui_info("TRUST MODE", "SELECTED", ui_settings_pin, true);
    } else {
        ui_settings_pin();
    }
}

/**
 * Pin Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void pin_cb(int token, uint8_t index) {
    const char* err = NULL;
    switch (token) {
        case TOKEN_PIN_BACK:
            ui_home_init();
            break;
        case TOKEN_PIN_SET:
            if (G_gpg_vstate.pinmode == index) {
                break;
            }
            switch (index) {
                case PIN_MODE_SCREEN:
                case PIN_MODE_CONFIRM:
                    if ((gpg_pin_is_verified(PIN_ID_PW1) == 0) &&
                        (gpg_pin_is_verified(PIN_ID_PW2) == 0)) {
                        err = PIN_USER;
                    }
                    break;
                case PIN_MODE_TRUST:
                    if (gpg_pin_is_verified(PIN_ID_PW3) == 0) {
                        err = PIN_ADMIN;
                    }
                    break;
            }
            if (err != NULL) {
                ui_info(err, NOT_VERIFIED, ui_settings_pin, false);
                break;
            }
            if ((G_gpg_vstate.pinmode != PIN_MODE_TRUST) && (index == PIN_MODE_TRUST)) {
                G_gpg_vstate.pinmode_req = index;
                nbgl_useCaseChoice(NULL,
                                   "TRUST mode",
                                   "This mode won't request any more PINs "
                                   "or validation before operations!\n"
                                   "Are you sure you want to select TRUST mode?",
                                   "Select",
                                   "Cancel",
                                   trust_cb);
            } else {
                G_gpg_vstate.pinmode = index;
            }
            break;
        case TOKEN_PIN_DEF:
            if (G_gpg_vstate.pinmode == PIN_MODE_TRUST) {
                ui_info(DEFAULT_MODE, NOT_ALLOWED, ui_settings_pin, false);
                break;
            } else if (G_gpg_vstate.pinmode != N_gpg_pstate->config_pin[0]) {
                // set new mode
                nvm_write((void*) (&N_gpg_pstate->config_pin[0]), &G_gpg_vstate.pinmode, 1);
                gpg_activate_pinpad(3);
            }
            ui_settings_pin();
            break;
    }
}

/**
 * Pin Settings menu
 *
 */
static void ui_settings_pin(void) {
    static nbgl_layoutRadioChoice_t choices = {0};
    nbgl_layoutButton_t buttonInfo = {0};
    static char* names[3] = {0};
    static char text[3][64];
    uint32_t i;

    static const char* const PinNameTexts[] = {
        "On Screen",
        "Confirm Only",
        "Trust",
    };

    ui_setting_header("PIN mode", TOKEN_PIN_BACK, pin_cb);

    for (i = 0; i < ARRAYLEN(PinNameTexts); i++) {
        snprintf(text[i],
                 sizeof(text[i]),
                 "%s %s",
                 (const char*) PIC(PinNameTexts[i]),
                 (N_gpg_pstate->config_pin[0] == i) ? "[default]" : "");
        names[i] = text[i];
    }
    choices.names = (const char* const*) names;
    choices.localized = false;
    choices.nbChoices = ARRAYLEN(PinNameTexts);
    choices.initChoice = G_gpg_vstate.pinmode;
    choices.token = TOKEN_PIN_SET;
    nbgl_layoutAddRadioChoice(layoutCtx, &choices);

    buttonInfo.fittingContent = false;
    buttonInfo.onBottom = true;
    buttonInfo.style = BLACK_BACKGROUND;
    buttonInfo.text = "Set default";
    buttonInfo.token = TOKEN_PIN_DEF;
    buttonInfo.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddButton(layoutCtx, &buttonInfo);

    nbgl_layoutDraw(layoutCtx);
}

/* --------------------------------- UIF UX ---------------------------------- */

enum {
    TOKEN_UIF_SIG = FIRST_USER_TOKEN,
    TOKEN_UIF_DEC,
    TOKEN_UIF_AUT,
    TOKEN_UIF_BACK,
};

/**
 * UIF Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void uif_cb(int token, uint8_t index) {
    unsigned char* uif = NULL;
    switch (token) {
        case TOKEN_UIF_BACK:
            ui_home_init();
            break;
        case TOKEN_UIF_SIG:
            uif = &G_gpg_vstate.kslot->sig.UIF[0];
            break;
        case TOKEN_UIF_DEC:
            uif = &G_gpg_vstate.kslot->dec.UIF[0];
            break;
        case TOKEN_UIF_AUT:
            uif = &G_gpg_vstate.kslot->aut.UIF[0];
            break;
    }
    if (uif == NULL) {
        return;
    }
    if (uif[0] == 2) {
        ui_info(UIF_LOCKED, EMPTY, ui_home_init, false);
    } else if (uif[0] != index) {
        nvm_write(&uif[0], &index, 1);
    }
}

/**
 * UIF Settings menu
 *
 */
static void ui_settings_uif(void) {
    static nbgl_layoutSwitch_t option = {0};
    uint8_t nbOptions = 0;

    ui_setting_header("User Interaction Flags", TOKEN_UIF_BACK, uif_cb);

    if (G_gpg_vstate.kslot->sig.UIF[0] != 2) {
        explicit_bzero(&option, sizeof(nbgl_layoutSwitch_t));
        option.initState = G_gpg_vstate.kslot->sig.UIF[0];
        option.text = "UIF for Signature";
        option.token = TOKEN_UIF_SIG;
        option.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddSwitch(layoutCtx, &option);
        nbOptions++;
    }

    if (G_gpg_vstate.kslot->dec.UIF[0] != 2) {
        explicit_bzero(&option, sizeof(nbgl_layoutSwitch_t));
        option.initState = G_gpg_vstate.kslot->dec.UIF[0];
        option.text = "UIF for Decryption";
        option.token = TOKEN_UIF_DEC;
        option.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddSwitch(layoutCtx, &option);
        nbOptions++;
    }

    if (G_gpg_vstate.kslot->aut.UIF[0] != 2) {
        explicit_bzero(&option, sizeof(nbgl_layoutSwitch_t));
        option.initState = G_gpg_vstate.kslot->aut.UIF[0];
        option.text = "UIF for Authentication";
        option.token = TOKEN_UIF_AUT;
        option.tuneId = TUNE_TAP_CASUAL;
        nbgl_layoutAddSwitch(layoutCtx, &option);
        nbOptions++;
    }
    if (nbOptions == 0) {
        // UIF flags are all "Permanent Enable", just display for information
        static const char* const infoTypes[] = {"UIF for Signature",
                                                "UIF for Decryption",
                                                "UIF for Authentication"};
        static const char* const infoContents[] = {"Permanently Enabled",
                                                   "Permanently Enabled",
                                                   "Permanently Enabled"};

        for (nbOptions = 0; nbOptions < ARRAYLEN(infoTypes); nbOptions++) {
            nbgl_layoutAddText(layoutCtx, infoTypes[nbOptions], infoContents[nbOptions]);
            nbgl_layoutAddSeparationLine(layoutCtx);
        }
    }

    nbgl_layoutDraw(layoutCtx);
}

/* -------------------------------- RESET UX --------------------------------- */

enum { TOKEN_RESET = FIRST_USER_TOKEN, TOKEN_RESET_BACK };

static void reset_cb(int token, uint8_t index) {
    setting_initPage = 0;
    switch (token) {
        case TOKEN_RESET_BACK:
            ui_home_init();
            break;
        case TOKEN_RESET:
            switch (index) {
                case 0:
                    app_reset();
                    ui_info("App Reset", "Done", ui_init, true);
                    break;
                case 1:
                    ui_home_init();
                    break;
            }
            break;
    }
}

/**
 * Reset Settings menu
 *
 */
static void ui_reset(void) {
    nbgl_contentCenteredInfo_t centeredInfo = {0};
    nbgl_layoutChoiceButtons_t buttonInfo = {0};

    ui_setting_header("Reset to Default", TOKEN_RESET_BACK, reset_cb);

    centeredInfo.onTop = true;
    centeredInfo.text1 = "This will reset the app to factory default,\nand delete ALL the keys!!!";
    centeredInfo.text2 = "Are you sure you want to continue?";
    centeredInfo.style = LARGE_CASE_BOLD_INFO;

    nbgl_layoutAddCenteredInfo(layoutCtx, &centeredInfo);

    buttonInfo.topText = "Reset";
    buttonInfo.bottomText = "Cancel";
    buttonInfo.token = TOKEN_RESET;
    buttonInfo.style = BOTH_ROUNDED_STYLE;
    buttonInfo.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddChoiceButtons(layoutCtx, &buttonInfo);

    nbgl_layoutDraw(layoutCtx);
}

/* ------------------------------ PIN CONFIRM UX ----------------------------- */

/**
 * Pin Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void pin_confirm_cb(bool confirm) {
    gpg_pin_set_verified(G_gpg_vstate.io_p2, confirm);

    gpg_io_discard(0);
    gpg_io_insert_u16(confirm ? SW_OK : SW_CONDITIONS_NOT_SATISFIED);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_init();
}

/**
 * Pin Confirmation page display
 *
 * @param[in] value PinCode ID to confirm
 *
 */
void ui_menu_pinconfirm_display(unsigned int value) {
    snprintf(G_gpg_vstate.menu,
             sizeof(G_gpg_vstate.menu),
             "%s %x",
             value == 0x83 ? "Admin" : "User",
             value);
    nbgl_useCaseChoice(NULL, "Confirm PIN", G_gpg_vstate.menu, "Yes", "No", pin_confirm_cb);
}

/* ------------------------------ PIN ENTRY UX ----------------------------- */

enum {
    TOKEN_PIN_ENTRY_BACK = FIRST_USER_TOKEN,
};

static void ui_menu_pinentry_cb(void);

/**
 * Pin Entry Validation callback
 *
 * @param[in] value PinCode ID to confirm
 *
 */
static void pinentry_validate_cb(const uint8_t* pinentry, uint8_t length) {
    unsigned int sw = SW_UNKNOWN;
    unsigned int len1 = 0;
    unsigned char* pin1 = NULL;
    gpg_pin_t* pin = NULL;

    switch (G_gpg_vstate.io_ins) {
        case INS_VERIFY:
            pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
            sw = gpg_pin_check(pin, G_gpg_vstate.io_p2, pinentry, length);
            gpg_io_discard(1);
            if (sw == SW_PIN_BLOCKED) {
                gpg_io_insert_u16(sw);
                gpg_io_do(IO_RETURN_AFTER_TX);
                ui_info(PIN_LOCKED, EMPTY, ui_init, false);
                break;
            } else if (sw != SW_OK) {
                snprintf(G_gpg_vstate.line,
                         sizeof(G_gpg_vstate.line),
                         "%d tries remaining",
                         pin->counter);
                ui_info(WRONG_PIN, G_gpg_vstate.line, ui_menu_pinentry_cb, false);
                break;
            }
            gpg_io_insert_u16(sw);
            gpg_io_do(IO_RETURN_AFTER_TX);
            snprintf(G_gpg_vstate.line,
                     sizeof(G_gpg_vstate.line),
                     "%s PIN",
                     (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "ADMIN" : "USER");
            ui_info(G_gpg_vstate.line, "VERIFIED", ui_init, true);
            break;

        case INS_CHANGE_REFERENCE_DATA:
            switch (G_gpg_vstate.ux_step) {
                case 0:
                    // Check Current pin code
                    pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
                    sw = gpg_pin_check(pin, G_gpg_vstate.io_p2, pinentry, length);
                    gpg_io_discard(1);
                    if (sw == SW_PIN_BLOCKED) {
                        gpg_io_insert_u16(sw);
                        gpg_io_do(IO_RETURN_AFTER_TX);
                        ui_info(PIN_LOCKED, EMPTY, ui_init, false);
                        break;
                    } else if (sw != SW_OK) {
                        snprintf(G_gpg_vstate.line,
                                 sizeof(G_gpg_vstate.line),
                                 " %d tries remaining",
                                 pin->counter);
                        ui_info(WRONG_PIN, G_gpg_vstate.line, ui_menu_pinentry_cb, false);
                        break;
                    }
                    ui_menu_pinentry_display(++G_gpg_vstate.ux_step);
                    break;
                case 1:
                    // Store the New pin codes
                    gpg_io_insert_u8(length);
                    gpg_io_insert(pinentry, length);
                    ui_menu_pinentry_display(++G_gpg_vstate.ux_step);
                    break;
                case 2:
                    // Compare the 2 pin codes (New + Confirm)
                    len1 = G_gpg_vstate.work.io_buffer[0];
                    pin1 = G_gpg_vstate.work.io_buffer + 1;
                    if ((len1 != length) || (memcmp(pin1, pinentry, length) != 0)) {
                        gpg_io_discard(1);
                        ui_info(PIN_DIFFERS, EMPTY, ui_menu_pinentry_cb, false);
                    } else {
                        pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
                        sw = gpg_pin_set(pin, G_gpg_vstate.work.io_buffer + 1, length);
                        gpg_io_discard(1);
                        gpg_io_insert_u16(sw);
                        gpg_io_do(IO_RETURN_AFTER_TX);
                        if (sw != SW_OK) {
                            ui_info("Process Error", EMPTY, ui_init, false);
                        } else {
                            snprintf(G_gpg_vstate.line,
                                     sizeof(G_gpg_vstate.line),
                                     "%s PIN",
                                     (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "ADMIN" : "USER");
                            ui_info(G_gpg_vstate.line, "CHANGED", ui_init, true);
                        }
                    }
                    break;
                default:
                    break;
            }
            break;

        default:
            break;
    }
}

/**
 * Pin Entry Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void pinentry_cb(int token, uint8_t index) {
    UNUSED(index);
    if (token == TOKEN_PIN_ENTRY_BACK) {
        gpg_io_discard(0);
        gpg_io_insert_u16(SW_CONDITIONS_NOT_SATISFIED);
        gpg_io_do(IO_RETURN_AFTER_TX);
        ui_init();
    }
}

/**
 * Pin Entry page display
 *
 * @param[in] step Pin Entry step
 *
 */
void ui_menu_pinentry_display(unsigned int step) {
    uint8_t minLen;
    char line[10];

    // Init the page title
    explicit_bzero(G_gpg_vstate.line, sizeof(G_gpg_vstate.line));
    if (G_gpg_vstate.io_ins == INS_CHANGE_REFERENCE_DATA) {
        switch (step) {
            case 0:
                // Default or initial case
                snprintf(line, sizeof(line), "Current");
                break;
            case 1:
                snprintf(line, sizeof(line), "New");
                break;
            case 2:
                snprintf(line, sizeof(line), "Confirm");
                break;
            default:
                break;
        }
        G_gpg_vstate.ux_step = step;
    } else {
        snprintf(line, sizeof(line), "Enter");
    }
    snprintf(G_gpg_vstate.menu,
             sizeof(G_gpg_vstate.menu),
             "%s %s PIN",
             line,
             (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? "Admin" : "User");

    minLen = (G_gpg_vstate.io_p2 == PIN_ID_PW3) ? GPG_MIN_PW3_LENGTH : GPG_MIN_PW1_LENGTH;
    // Draw the keypad
    nbgl_useCaseKeypadPIN(G_gpg_vstate.menu,
                          minLen,
                          GPG_MAX_PW_LENGTH,
                          TOKEN_PIN_ENTRY_BACK,
                          false,
                          TUNE_TAP_CASUAL,
                          pinentry_validate_cb,
                          pinentry_cb);
}

/**
 * Pin Entry Navigation callback
 *
 */
static void ui_menu_pinentry_cb(void) {
    unsigned int value = 0;

    if ((G_gpg_vstate.io_ins == INS_CHANGE_REFERENCE_DATA) && (G_gpg_vstate.ux_step == 2)) {
        // Current step is Change Password with PINs differ
        value = 1;
    }
    ui_menu_pinentry_display(value);
}

/* ------------------------------ UIF CONFIRM UX ----------------------------- */

/**
 * UIF Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void uif_confirm_cb(bool confirm) {
    unsigned int sw = SW_SECURITY_UIF_ISSUE;

    if (confirm) {
        G_gpg_vstate.UIF_flags = 1;
        if (G_gpg_vstate.io_ins == INS_PSO) {
            sw = gpg_apdu_pso();
        } else if (G_gpg_vstate.io_ins == INS_INTERNAL_AUTHENTICATE) {
            sw = gpg_apdu_internal_authenticate();
        } else {
            gpg_io_discard(1);
        }
        G_gpg_vstate.UIF_flags = 0;
    } else {
        gpg_io_discard(1);
    }
    gpg_io_insert_u16(sw);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_init();
}

/**
 * UIF page display
 *
 * @param[in] step unused
 *
 */
void ui_menu_uifconfirm_display(unsigned int value) {
    UNUSED(value);

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
    if (G_gpg_vstate.menu[0] == 0) {
        snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "Please Cancel");
    }
    nbgl_useCaseChoice(NULL, "Confirm operation", G_gpg_vstate.menu, "Yes", "No", uif_confirm_cb);
}

#endif  // defined(HAVE_NBGL) && defined(TARGET_STAX)
