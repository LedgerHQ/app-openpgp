
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
static void ui_home_init(void);
static void ui_menu_slot_action();
static void ui_settings_template(void);
static void ui_settings_seed(void);
static void ui_settings_pin(void);
static void ui_settings_uif(uint8_t page);
static void ui_reset(void);

#ifdef SCREEN_SIZE_WALLET
// context for background and modal pages
static nbgl_layout_t layoutCtx = {0};
#else   // SCREEN_SIZE_WALLET
// Slot setting page to display
static uint8_t slot_initPage;
// Pin setting page to display
static uint8_t pin_initPage;
#endif  // SCREEN_SIZE_WALLET
// Keys setting page to display
static uint8_t keys_initPage;
// Setting page to display
static uint8_t setting_initPage;

static nbgl_content_t contents;
static nbgl_genericContents_t settingContents;
static nbgl_contentSwitch_t switches[5];  // 5 should be enough for all switches

/* ------------------------------- Helpers  UX ------------------------------- */

/**
 * @brief Display popup message on screen
 *
 * @param[in] msg1 1st part of the message
 * @param[in] msg2 2nd part of the message
 *
 */
static void ui_info(const char* msg1, const char* msg2, nbgl_callback_t cb, bool isSuccess) {
    snprintf(G_gpg_vstate.menu, sizeof(G_gpg_vstate.menu), "%s\n%s", msg1, msg2);

    nbgl_useCaseStatus((const char*) G_gpg_vstate.menu, isSuccess, cb);
};

#ifdef SCREEN_SIZE_WALLET
/**
 * @brief Display Setting page header
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
    nbgl_layoutHeader_t headerDesc = {0};

    layoutDescription.onActionCallback = touch_cb;
    layoutDescription.modal = false;
    layoutCtx = nbgl_layoutGet(&layoutDescription);

    headerDesc.type = HEADER_BACK_AND_TEXT;
    headerDesc.backAndText.text = PIC(title);
    headerDesc.backAndText.token = back_token;
    headerDesc.backAndText.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddHeader(layoutCtx, &headerDesc);
    nbgl_layoutAddSeparationLine(layoutCtx);
}
#endif  // SCREEN_SIZE_WALLET

//  -----------------------------------------------------------
//  ----------------------- HOME PAGE -------------------------
//  -----------------------------------------------------------

// clang-format off
enum {
    TOKEN_SETTINGS_TEMPLATE = FIRST_USER_TOKEN,
    TOKEN_SETTINGS_SEED,
    TOKEN_SETTINGS_PIN,
    TOKEN_SETTINGS_UIF,
    TOKEN_SETTINGS_RESET,
};
// clang-format on

/**
 * @brief Settings callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget value
 * @param[in] page index of the page
 *
 */
static void controlsCallback(int token, uint8_t index, int page) {
    UNUSED(index);
    setting_initPage = page;
    switch (token) {
        case TOKEN_SETTINGS_TEMPLATE:
            keys_initPage = 0;
            ui_settings_template();
            break;
        case TOKEN_SETTINGS_SEED:
            ui_settings_seed();
            break;
        case TOKEN_SETTINGS_PIN:
            ui_settings_pin();
            break;
        case TOKEN_SETTINGS_UIF:
            ui_settings_uif(0);
            break;
        case TOKEN_SETTINGS_RESET:
            ui_reset();
            break;
    }
}

#ifdef SCREEN_SIZE_NANO
#define COMBINED_VERSION APPVERSION "\n(Spec: " SPEC_VERSION ")"
#else
#define COMBINED_VERSION APPVERSION " (Spec: " SPEC_VERSION ")"
#endif
/**
 * @brief home page display
 *
 */
static void ui_home_init(void) {
    static nbgl_contentInfoList_t infosList = {0};
    static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
    static const char* const infoContents[] = {COMBINED_VERSION, "Ledger", "Ledger (c) 2025"};
    char name[32];
    unsigned int serial = U4BE(G_gpg_vstate.kslot->serial, 0);

    explicit_bzero(name, sizeof(name));
    if (N_gpg_pstate->name.value[0] != 0) {
        memmove(name, (void*) (N_gpg_pstate->name.value), sizeof(name) - 1);
        for (uint8_t i = 0; i < sizeof(name) - 1; i++) {
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

    infosList.nbInfos = ARRAYLEN(infoTypes);
    infosList.infoTypes = (const char**) infoTypes;
    infosList.infoContents = (const char**) infoContents;

    static const char* const barTexts[] = {"Keys Templates",
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
#ifdef HAVE_PIEZO_SOUND
    contents.content.barsList.tuneId = TUNE_TAP_CASUAL;
#endif
    contents.contentActionCallback = controlsCallback;

    settingContents.contentsList = &contents;
    settingContents.nbContents = 1;

    static nbgl_homeAction_t actionContent = {0};
    actionContent.text = "Select Slot";
    actionContent.callback = ui_menu_slot_action;

#ifdef SCREEN_SIZE_NANO
    actionContent.icon = &C_icon_certificate;
    slot_initPage = 0;
    pin_initPage = 0;
#endif

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP,
                                G_gpg_vstate.menu,
                                setting_initPage,
                                &settingContents,
                                &infosList,
                                &actionContent,
                                app_exit);
}

/**
 * @brief home page init
 *
 */
void ui_init(void) {
    setting_initPage = INIT_HOME_PAGE;
#ifdef SCREEN_SIZE_NANO
    slot_initPage = 0;
    pin_initPage = 0;
#endif
    keys_initPage = 0;
    ui_home_init();
}

//  -----------------------------------------------------------
//  ------------------------ SLOT UX --------------------------
//  -----------------------------------------------------------

// clang-format off
enum {
    TOKEN_SLOT_SELECT = FIRST_USER_TOKEN,
    TOKEN_SLOT_DEF,
    TOKEN_SLOT_BACK,
};
// clang-format on

/**
 * @brief Slot Action callback
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
#ifdef SCREEN_SIZE_NANO
                slot_initPage = index;
                ui_menu_slot_action();
#endif
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

#ifdef SCREEN_SIZE_NANO
/**
 * @brief Slot Configuration callback
 *
 * @param[in] page index to fill
 * @param[out] content of the page
 *
 */
static bool slot_cfg_cb(uint8_t page, nbgl_pageContent_t* content) {
    static char* names[GPG_KEYS_SLOTS] = {0};
    static char text[GPG_KEYS_SLOTS][32];
    uint32_t slot;

    switch (page) {
        case 0:
            for (slot = 0; slot < GPG_KEYS_SLOTS; slot++) {
                if (G_gpg_vstate.slot == slot) {
                    snprintf(text[slot],
                             sizeof(text[slot]),
                             "[Slot %d]\n%s",
                             (slot + 1),
                             (N_gpg_pstate->config_slot[1] == slot) ? "(default)" : " ");
                } else {
                    snprintf(text[slot],
                             sizeof(text[slot]),
                             "Slot %d\n%s",
                             (slot + 1),
                             (N_gpg_pstate->config_slot[1] == slot) ? "(default)" : " ");
                }
                names[slot] = text[slot];
            }

            content->type = CHOICES_LIST;
            content->choicesList.names = (const char* const*) names;
            content->choicesList.token = TOKEN_SLOT_SELECT;
            content->choicesList.nbChoices = GPG_KEYS_SLOTS;
            content->choicesList.initChoice = G_gpg_vstate.slot;
            break;
        case 1:
            snprintf(text[0], sizeof(text[0]), "Set Slot %d", (G_gpg_vstate.slot + 1));
            content->type = INFO_BUTTON;
            content->infoButton.text = "Set Default Slot";
            content->infoButton.buttonText = text[0];
            content->infoButton.buttonToken = TOKEN_SLOT_DEF;
            break;
        default:
            return false;
    }
    return true;
}
#endif  // SCREEN_SIZE_NANO

/**
 * @brief Slot Navigation callback
 *
 */
static void ui_menu_slot_action(void) {
#ifdef SCREEN_SIZE_WALLET
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
#else   // SCREEN_SIZE_WALLET
    nbgl_useCaseNavigableContent("Slots configuration",
                                 slot_initPage,
                                 2,
                                 ui_home_init,
                                 slot_cfg_cb,
                                 slot_cb);
#endif  // SCREEN_SIZE_WALLET
}

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------

/* ------------------------------- TEMPLATE UX ------------------------------- */

// clang-format off
enum {
    TOKEN_TEMPLATE_SIG = FIRST_USER_TOKEN,
    TOKEN_TEMPLATE_DEC,
    TOKEN_TEMPLATE_AUT,
};
enum {
    TOKEN_TYPE_RSA2048 = FIRST_USER_TOKEN,
    TOKEN_TYPE_RSA3072,
    TOKEN_TYPE_RSA4096,
    TOKEN_TYPE_SECP256K1,
    TOKEN_TYPE_SECP256R1,
    TOKEN_TYPE_Ed25519,
    TOKEN_TYPE_BACK
};

static uint8_t nb_elt_per_page = 0;

const uint8_t tokens[KEY_NB] = {TOKEN_TEMPLATE_SIG, TOKEN_TEMPLATE_DEC, TOKEN_TEMPLATE_AUT};

static const char* const keyNameTexts[] = {LABEL_SIG, LABEL_DEC, LABEL_AUT};

static const char* const keyTypeTexts[] = {LABEL_RSA2048,
                                           LABEL_RSA3072,
                                           LABEL_RSA4096,
                                           LABEL_SECP256K1,
                                           LABEL_SECP256R1,
                                           LABEL_Ed25519};

#ifdef NO_DECRYPT_cv25519
static const char* const keyTypeDecTexts[] = {LABEL_RSA2048,
                                              LABEL_RSA3072,
                                              LABEL_RSA4096,
                                              LABEL_SECP256K1,
                                              LABEL_SECP256R1};
#endif
// clang-format on

/**
 * @brief Determine the selected key type from its attributes
 *
 * @param[in] key token describing the selected key
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
                case 4096:
                    token = TOKEN_TYPE_RSA4096;
                    break;
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
 * @brief Keys Templates Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 * @param[in] page index of the page
 *
 */
static void template_key_cb(int token, uint8_t index, int page) {
    LV(attributes, GPG_KEY_ATTRIBUTES_LENGTH);
    gpg_key_t* dest = NULL;
    static uint8_t* oid = NULL;
    uint32_t oid_len = 0;
    uint32_t size = 0;
    uint8_t key_type = index + (page * nb_elt_per_page) + FIRST_USER_TOKEN;

    if (token != TOKEN_TYPE_BACK) {
        explicit_bzero(&attributes, sizeof(attributes));
        switch (key_type) {
            case TOKEN_TYPE_RSA2048:
            case TOKEN_TYPE_RSA3072:
            case TOKEN_TYPE_RSA4096:
                switch (key_type) {
                    case TOKEN_TYPE_RSA2048:
                        size = 2048;
                        break;
                    case TOKEN_TYPE_RSA3072:
                        size = 3072;
                        break;
                    case TOKEN_TYPE_RSA4096:
                        size = 4096;
                        break;
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
 * @brief Template Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 * @param[in] page index of the page
 *
 */
static void template_cb(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    uint8_t page_index = 0;

    explicit_bzero(&contents, sizeof(contents));
    explicit_bzero(&settingContents, sizeof(settingContents));
    switch (token) {
        case TOKEN_TEMPLATE_SIG:
        case TOKEN_TEMPLATE_DEC:
        case TOKEN_TEMPLATE_AUT:
            G_gpg_vstate.ux_key = token;
            contents.type = CHOICES_LIST;
#ifdef NO_DECRYPT_cv25519
            if (token == TOKEN_TEMPLATE_DEC) {
                contents.content.choicesList.names = (const char* const*) keyTypeDecTexts;
                contents.content.choicesList.nbChoices = ARRAYLEN(keyTypeDecTexts);
            } else
#endif
            {
                contents.content.choicesList.names = (const char* const*) keyTypeTexts;
                contents.content.choicesList.nbChoices = ARRAYLEN(keyTypeTexts);
            }
            contents.content.choicesList.initChoice = _getKeyType(token) - FIRST_USER_TOKEN;
            contents.content.choicesList.token = token;
#ifdef HAVE_PIEZO_SOUND
            contents.content.choicesList.tuneId = TUNE_TAP_CASUAL;
#endif
            contents.contentActionCallback = template_key_cb;

            settingContents.contentsList = &contents;
            settingContents.nbContents = 1;
            // Save nb radio choices per page to select the right one in the callback
            nb_elt_per_page = nbgl_useCaseGetNbChoicesInPage(contents.content.choicesList.nbChoices,
                                                             &contents.content.choicesList,
                                                             0,
                                                             false);

#ifdef SCREEN_SIZE_NANO
            keys_initPage = page;
            page_index = contents.content.choicesList.initChoice;
#endif
            nbgl_useCaseGenericConfiguration(keyNameTexts[token - FIRST_USER_TOKEN],
                                             page_index,
                                             &settingContents,
                                             ui_settings_template);
            break;
    }
}

/**
 * @brief Template Settings menu
 *
 */
static void ui_settings_template(void) {
    static char* names[3] = {0};
    static char text[3][64];
    char* subText = NULL;
    uint32_t i;

    explicit_bzero(&contents, sizeof(contents));
    explicit_bzero(&settingContents, sizeof(settingContents));
    contents.type = BARS_LIST;
    contents.content.barsList.nbBars = KEY_NB;
    contents.content.barsList.barTexts = (const char* const*) names;
    contents.content.barsList.tokens = tokens;
    for (i = 0; i < KEY_NB; i++) {
        switch (_getKeyType(TOKEN_TEMPLATE_SIG + i)) {
            case TOKEN_TYPE_RSA2048:
                subText = PIC(LABEL_RSA2048);
                break;
            case TOKEN_TYPE_RSA3072:
                subText = PIC(LABEL_RSA3072);
                break;
            case TOKEN_TYPE_RSA4096:
                subText = PIC(LABEL_RSA4096);
                break;
            case TOKEN_TYPE_SECP256K1:
                subText = PIC(LABEL_SECP256K1);
                break;
            case TOKEN_TYPE_SECP256R1:
                subText = PIC(LABEL_SECP256R1);
                break;
            case TOKEN_TYPE_Ed25519:
                subText = PIC(LABEL_Ed25519);
                break;
            default:
                break;
        }
        snprintf(text[i], sizeof(text[i]), "%s\n%s", (const char*) PIC(keyNameTexts[i]), subText);
        names[i] = text[i];
    }
#ifdef HAVE_PIEZO_SOUND
    contents.content.barsList.tuneId = TUNE_TAP_CASUAL;
#endif
    contents.contentActionCallback = template_cb;

    settingContents.contentsList = &contents;
    settingContents.nbContents = 1;

    nbgl_useCaseGenericConfiguration("Keys Templates",
                                     keys_initPage,
                                     &settingContents,
                                     ui_home_init);
}

/* --------------------------------- SEED UX --------------------------------- */

// clang-format off
enum {
    TOKEN_SEED = FIRST_USER_TOKEN,
};
enum {
    SWITCH_SEED,
    SWITCH_SEED_NB,
};
// clang-format on
_Static_assert(SWITCH_SEED_NB < ARRAYLEN(switches), "Too small switches array");

/**
 * @brief Seed Mode Confirmation callback
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
 * @brief Seed Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 * @param[in] page index of the page
 *
 */
static void seed_cb(int token, uint8_t index, int page) {
    UNUSED(page);
    switch (token) {
        case TOKEN_SEED:
            if (index == 0) {
                nbgl_useCaseChoice(NULL,
                                   "SEED mode",
                                   "This mode allows to derive your key from Master SEED.\n"
                                   "Without such configuration, an OS or App update "
                                   "will cause your private key to be lost!\n"
                                   "Are you sure you want to disable SEED mode?",
                                   "Yes, deactivate",
                                   "Cancel",
                                   seed_confirm_cb);
                break;
            }
            G_gpg_vstate.seed_mode = 1;
            switches[SWITCH_SEED].initState = G_gpg_vstate.seed_mode;
            break;
    }
}

/**
 * @brief Seed Settings menu
 *
 */
static void ui_settings_seed(void) {
    explicit_bzero(&contents, sizeof(contents));
    explicit_bzero(&settingContents, sizeof(settingContents));
    explicit_bzero(&switches, sizeof(switches));
    // Initialize switches data
    switches[SWITCH_SEED].initState = G_gpg_vstate.seed_mode ? ON_STATE : OFF_STATE;
    switches[SWITCH_SEED].text = "Seed Mode";
    switches[SWITCH_SEED].subText = "Key derivation from Master seed";
    switches[SWITCH_SEED].token = TOKEN_SEED;
#ifdef HAVE_PIEZO_SOUND
    switches[SWITCH_SEED].tuneId = TUNE_TAP_CASUAL;
#endif

    contents.type = SWITCHES_LIST;
    contents.content.switchesList.nbSwitches = SWITCH_SEED_NB;
    contents.content.switchesList.switches = switches;
    contents.contentActionCallback = seed_cb;

    settingContents.contentsList = &contents;
    settingContents.nbContents = 1;

    nbgl_useCaseGenericConfiguration("Seed mode", 0, &settingContents, ui_home_init);
}

//* --------------------------------- PIN UX ---------------------------------- */

// clang-format off
enum {
    TOKEN_PIN_SET = FIRST_USER_TOKEN,
    TOKEN_PIN_DEF,
    TOKEN_PIN_BACK,
};
// clang-format on

/**
 * @brief Trust Mode Confirmation callback
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
 * @brief Pin Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void pin_cb(int token, uint8_t index) {
    const char* err = NULL;
    G_gpg_vstate.pinmode_req = 0xFF;
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
#ifdef SCREEN_SIZE_NANO
            pin_initPage = index;
#endif
            if ((G_gpg_vstate.pinmode != PIN_MODE_TRUST) && (index == PIN_MODE_TRUST)) {
                G_gpg_vstate.pinmode_req = index;
                nbgl_useCaseChoice(NULL,
                                   "TRUST mode",
                                   "This mode won't request any more PINs "
                                   "or validation before operations!\n"
                                   "Are you sure you want to select TRUST mode?",
                                   "Yes, select",
                                   "Cancel",
                                   trust_cb);
            } else {
                G_gpg_vstate.pinmode = index;
#ifdef SCREEN_SIZE_NANO
                ui_settings_pin();
#endif
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

static const char* const PinNameTexts[PIN_MODE_MAX] = {
    "On Screen",
    "Confirm Only",
    "Trust",
};
#ifdef SCREEN_SIZE_NANO
/**
 * @brief Pin Configuration callback
 *
 * @param[in] page index to fill
 * @param[out] content of the page
 *
 */
static bool pin_cfg_cb(uint8_t page, nbgl_pageContent_t* content) {
    static char* names[PIN_MODE_MAX] = {0};
    static char text[PIN_MODE_MAX][32];
    uint32_t pin;

    switch (page) {
        case 0:
            for (pin = 0; pin < PIN_MODE_MAX; pin++) {
                if (G_gpg_vstate.pinmode == pin) {
                    snprintf(text[pin],
                             sizeof(text[pin]),
                             "[%s]\n%s",
                             (const char*) PIC(PinNameTexts[pin]),
                             (N_gpg_pstate->config_pin[0] == pin) ? "(default)" : " ");
                } else {
                    snprintf(text[pin],
                             sizeof(text[pin]),
                             "%s\n%s",
                             (const char*) PIC(PinNameTexts[pin]),
                             (N_gpg_pstate->config_pin[0] == pin) ? "(default)" : " ");
                }
                names[pin] = text[pin];
            }

            content->type = CHOICES_LIST;
            content->choicesList.names = (const char* const*) names;
            content->choicesList.token = TOKEN_PIN_SET;
            content->choicesList.nbChoices = PIN_MODE_MAX;
            content->choicesList.initChoice = G_gpg_vstate.pinmode;
            break;
        case 1:
            snprintf(text[0],
                     sizeof(text[0]),
                     "Set %s",
                     (const char*) PIC(PinNameTexts[G_gpg_vstate.pinmode]));
            content->type = INFO_BUTTON;
            content->infoButton.text = "Set Default Mode";
            content->infoButton.buttonText = text[0];
            content->infoButton.buttonToken = TOKEN_PIN_DEF;
            break;
        default:
            return false;
    }
    return true;
}
#endif  // SCREEN_SIZE_NANO

/**
 * @brief Pin Settings menu
 *
 */
static void ui_settings_pin(void) {
#ifdef SCREEN_SIZE_WALLET
    static nbgl_layoutRadioChoice_t choices = {0};
    nbgl_layoutButton_t buttonInfo = {0};
    static char* names[PIN_MODE_MAX] = {0};
    static char text[PIN_MODE_MAX][32];
    uint32_t pin;

    ui_setting_header("PIN mode", TOKEN_PIN_BACK, pin_cb);

    for (pin = 0; pin < PIN_MODE_MAX; pin++) {
        snprintf(text[pin],
                 sizeof(text[pin]),
                 "%s %s",
                 (const char*) PIC(PinNameTexts[pin]),
                 (N_gpg_pstate->config_pin[0] == pin) ? "[default]" : "");
        names[pin] = text[pin];
    }
    choices.names = (const char* const*) names;
    choices.localized = false;
    choices.nbChoices = PIN_MODE_MAX;
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
#else   // SCREEN_SIZE_WALLET
    nbgl_useCaseNavigableContent("PIN mode", pin_initPage, 2, ui_home_init, pin_cfg_cb, pin_cb);
#endif  // SCREEN_SIZE_WALLET
}

/* --------------------------------- UIF UX ---------------------------------- */

// clang-format off
enum {
    TOKEN_UIF_SIG = FIRST_USER_TOKEN,
    TOKEN_UIF_DEC,
    TOKEN_UIF_AUT,
};
enum {
    SWITCH_UIF_SIG,
    SWITCH_UIF_DEC,
    SWITCH_UIF_AUT,
    SWITCH_UIF_NB,
};
// clang-format on
_Static_assert(SWITCH_UIF_NB < ARRAYLEN(switches), "Too small switches array");

/**
 * @brief UIF Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 * @param[in] page index of the page
 *
 */
static void uif_cb(int token, uint8_t index, int page) {
    UNUSED(page);
    uint8_t* uif = NULL;

    switch (token) {
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
        return;
    }
    nvm_write(&uif[0], &index, 1);

    switches[token - FIRST_USER_TOKEN].initState = index;
}

/**
 * @brief UIF Settings menu
 *
 * @param[in] page requested
 *
 */
static void ui_settings_uif(uint8_t page) {
    explicit_bzero(&contents, sizeof(contents));
    explicit_bzero(&settingContents, sizeof(settingContents));
    explicit_bzero(&switches, sizeof(switches));

    // Initialize switches data
    switches[SWITCH_UIF_SIG].initState = G_gpg_vstate.kslot->sig.UIF[0] ? ON_STATE : OFF_STATE;
#ifdef SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_SIG].text = "User Interaction Flag";
#else   // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_SIG].text = "UIF";
#endif  // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_SIG].subText = "For signature";
    switches[SWITCH_UIF_SIG].token = TOKEN_UIF_SIG;
#ifdef HAVE_PIEZO_SOUND
    switches[SWITCH_UIF_SIG].tuneId = TUNE_TAP_CASUAL;
#endif

    switches[SWITCH_UIF_DEC].initState = G_gpg_vstate.kslot->dec.UIF[0] ? ON_STATE : OFF_STATE;
#ifdef SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_DEC].text = "User Interaction Flag";
#else   // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_DEC].text = "UIF";
#endif  // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_DEC].subText = "For decryption";
    switches[SWITCH_UIF_DEC].token = TOKEN_UIF_DEC;
#ifdef HAVE_PIEZO_SOUND
    switches[SWITCH_UIF_DEC].tuneId = TUNE_TAP_CASUAL;
#endif

    switches[SWITCH_UIF_AUT].initState = G_gpg_vstate.kslot->aut.UIF[0] ? ON_STATE : OFF_STATE;
#ifdef SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_AUT].text = "User Interaction Flag";
#else   // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_AUT].text = "UIF";
#endif  // SCREEN_SIZE_WALLET
    switches[SWITCH_UIF_AUT].subText = "For authentication";
    switches[SWITCH_UIF_AUT].token = TOKEN_UIF_AUT;
#ifdef HAVE_PIEZO_SOUND
    switches[SWITCH_UIF_AUT].tuneId = TUNE_TAP_CASUAL;
#endif

    contents.type = SWITCHES_LIST;
    contents.content.switchesList.nbSwitches = SWITCH_UIF_NB;
    contents.content.switchesList.switches = switches;
    contents.contentActionCallback = uif_cb;

    settingContents.contentsList = &contents;
    settingContents.nbContents = 1;

    nbgl_useCaseGenericConfiguration("UIF mode", page, &settingContents, ui_home_init);
}

/* -------------------------------- RESET UX --------------------------------- */

/**
 * @brief Reset callback
 *
 */
static void reset_cb(bool confirm) {
    if (confirm) {
        app_reset();
        nbgl_useCaseStatus("App Reset done", true, ui_home_init);
    } else {
        ui_home_init();
    }
}

/**
 * Reset Settings menu
 *
 */
static void ui_reset(void) {
    nbgl_useCaseChoice(NULL,
                       "Factory Reset",
                       "This will reset the app to factory default, and delete ALL keys!!!\n"
                       "Are you sure you want to continue?",
                       "Yes, reset",
                       "Cancel",
                       reset_cb);
}

/* ------------------------------ PIN CONFIRM UX ----------------------------- */

/**
 * @brief Pin Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void pin_confirm_cb(bool confirm) {
    gpg_pin_set_verified(G_gpg_vstate.io_p2, confirm);

    gpg_io_discard(0);
    gpg_io_insert_u16(confirm ? SWO_SUCCESS : SWO_CONDITIONS_NOT_SATISFIED);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_init();
}

/**
 * @brief Pin Confirmation page display
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

// clang-format off
enum {
    TOKEN_PIN_ENTRY_BACK = FIRST_USER_TOKEN,
};
// clang-format on

static void ui_menu_pinentry_cb(void);

/**
 * @brief Pin Entry Validation callback
 *
 * @param[in] value PinCode ID to confirm
 *
 */
static void pinentry_validate_cb(const uint8_t* pinentry, uint8_t length) {
    unsigned int sw = SWO_UNKNOWN;
    unsigned int len1 = 0;
    unsigned char* pin1 = NULL;
    gpg_pin_t* pin = NULL;

    switch (G_gpg_vstate.io_ins) {
        case INS_VERIFY:
            pin = gpg_pin_get_pin(G_gpg_vstate.io_p2);
            sw = gpg_pin_check(pin, G_gpg_vstate.io_p2, pinentry, length);
            gpg_io_discard(1);
            if (sw == SWO_AUTH_METHOD_BLOCKED) {
                gpg_io_insert_u16(sw);
                gpg_io_do(IO_RETURN_AFTER_TX);
                ui_info(PIN_LOCKED, EMPTY, ui_init, false);
                break;
            } else if (sw != SWO_SUCCESS) {
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
                    if (sw == SWO_AUTH_METHOD_BLOCKED) {
                        gpg_io_insert_u16(sw);
                        gpg_io_do(IO_RETURN_AFTER_TX);
                        ui_info(PIN_LOCKED, EMPTY, ui_init, false);
                        break;
                    } else if (sw != SWO_SUCCESS) {
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
                        if (sw != SWO_SUCCESS) {
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
 * @brief Pin Back button callback
 *
 */
static void pinback_cb(void) {
    gpg_io_discard(0);
    gpg_io_insert_u16(SWO_CONDITIONS_NOT_SATISFIED);
    gpg_io_do(IO_RETURN_AFTER_TX);
    ui_init();
}

#ifdef SCREEN_SIZE_WALLET
/**
 * @brief Pin Entry Action callback
 *
 * @param[in] token button Id pressed
 * @param[in] index widget index on the page
 *
 */
static void pinentry_cb(int token, uint8_t index) {
    UNUSED(index);
    if (token == TOKEN_PIN_ENTRY_BACK) {
        pinback_cb();
    }
}
#endif  // SCREEN_SIZE_WALLET

/**
 * @brief Pin Entry page display
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
#ifdef SCREEN_SIZE_WALLET
    nbgl_useCaseKeypadPIN(G_gpg_vstate.menu,
                          minLen,
                          GPG_MAX_PW_LENGTH,
                          TOKEN_PIN_ENTRY_BACK,
                          false,
                          TUNE_TAP_CASUAL,
                          pinentry_validate_cb,
                          pinentry_cb);
#else   // SCREEN_SIZE_WALLET
    nbgl_useCaseKeypadPIN(G_gpg_vstate.menu,
                          minLen,
                          GPG_MAX_PW_LENGTH,
                          false,
                          pinentry_validate_cb,
                          pinback_cb);
#endif  // SCREEN_SIZE_WALLET
}

/**
 * @brief Pin Entry Navigation callback
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
 * @brief UIF Confirmation callback
 *
 * @param[in] confirm indicate if the user press 'Confirm' or 'Cancel'
 *
 */
void uif_confirm_cb(bool confirm) {
    unsigned int sw = SWO_SECURITY_ISSUE;

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
 * @brief UIF page display
 *
 * @param[in] value unused
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
