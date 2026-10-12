#!/usr/bin/env python3
# *****************************************************************************
#   Ledger App OpenPGP.
#   (c) 2024 Ledger SAS.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# *****************************************************************************

import sys
from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

from gpgapp.credentials import (
    ASK,
    ENV_ADMIN_PIN,
    ENV_NEW_ADMIN_PIN,
    ENV_NEW_USER_PIN,
    ENV_RESET_CODE,
    ENV_USER_PIN,
    get_pins,
    get_secret,
)
from gpgapp.gpgcard import SEED_MODE_LEGACY, SEED_MODE_V2, GPGCard, GPGCardExcpetion
from gpgapp.gpgcmd import KEY_OPERATIONS, KEY_TEMPLATES, USER_SALUTATION, ErrorCodes, KeyTypes, PassWord

# Seed derivation of the regenerated keys, as GEN ASYM KEY P2
SEED_DERIVATIONS = {"v2": SEED_MODE_V2, "legacy": SEED_MODE_LEGACY}


# ===============================================================================
#          Parse command line options
# ===============================================================================
def get_argparser() -> Namespace:
    """Parse the commandline options"""

    parser = ArgumentParser(
        description="Manage OpenPGP App on Ledger device",
        epilog="PIN and code options given without value are read from their environment variable,\n"
        + "or prompted. Giving the value on the command line exposes it in the process list.",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument("--info", action="store_true", help="Get and display card information")
    parser.add_argument(
        "--reader",
        type=str,
        default="Ledger",
        help="HID path of the device, or 'speculos' (default is '%(default)s', the only Ledger device connected)",
    )

    parser.add_argument("--apdu", action="store_true", help="Log APDU exchange")
    parser.add_argument("--slot", type=int, choices=range(1, 4), help="Select slot (1 to 3)")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset the application (all data will be erased)",
    )

    parser.add_argument("--pinpad", action="store_true", help="PIN validation delegated to pinpad")
    parser.add_argument(
        "--adm-pin", metavar="PIN", nargs="?", const=ASK, help=f"Admin PIN (if pinpad not used), or ${ENV_ADMIN_PIN}"
    )
    parser.add_argument(
        "--user-pin", metavar="PIN", nargs="?", const=ASK, help=f"User PIN (if pinpad not used), or ${ENV_USER_PIN}"
    )
    parser.add_argument("--new-user-pin", metavar="PIN", nargs="?", const=ASK, help=f"Change User PIN, or ${ENV_NEW_USER_PIN}")
    parser.add_argument("--new-adm-pin", metavar="PIN", nargs="?", const=ASK, help=f"Change Admin PIN, or ${ENV_NEW_ADMIN_PIN}")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--reset-code", nargs="?", const=ASK, help=f"Update 'PW1 Resetting Code', or ${ENV_RESET_CODE}")
    group.add_argument("--reset-pw1", metavar="PIN", nargs="?", const=ASK, help=f"Reset the User PIN, or ${ENV_NEW_USER_PIN}")

    parser.add_argument("--serial", help="Update the 'serial' data (4 bytes)")
    parser.add_argument("--salutation", choices=list(USER_SALUTATION), help="Update 'salutation' data")
    parser.add_argument("--name", help="Update 'name' data")
    parser.add_argument("--url", help="Update 'url' data")
    parser.add_argument("--login", help="Update 'login' data")
    parser.add_argument("--lang", help="Update 'lang' data")

    parser.add_argument(
        "--key-type",
        type=KeyTypes,
        choices=[k.value for k in KeyTypes],
        help="Select key type SIG:DEC:AUT (default is all)",
    )

    parser.add_argument(
        "--key-action",
        choices=list(KEY_OPERATIONS),
        help="Generate key pair or Read public key",
    )
    parser.add_argument(
        "--set-fingerprints",
        metavar="SIG:DEC:AUT",
        help="Set fingerprints for selected 'key-type'\n"
        + "If 'key-type' is not specified, set for all keys (SIG:DEC:AUT)\n"
        + "Each fingerprint is 20 hex bytes long",
    )
    parser.add_argument(
        "--set-templates",
        metavar="SIG:DEC:AUT",
        help="Set template identifier for selected 'key-type'\n"
        + "If 'key-type' is not specified, set for all keys (SIG:DEC:AUT)\n"
        + f"Valid values are {', '.join(list(KEY_TEMPLATES))}",
    )
    parser.add_argument(
        "--seed-key",
        nargs="?",
        const="v2",
        choices=list(SEED_DERIVATIONS),
        help="Regenerate the keys from the device seed\n"
        + "'v2' (default) for keys generated by app 3.x, 'legacy' for keys generated by app 2.x",
    )

    parser.add_argument(
        "--file",
        type=str,
        default="pubkey",
        help="Public Key export file (default is '%(default)s')",
    )

    return parser.parse_args()


# ===============================================================================
#          Error handler
# ===============================================================================
def error(code: int, msg: str) -> None:
    """Print error message and exit with status 1

    Args:
        msg (str): Message to display
    """

    scode = f" {code:x}" if code else ""
    if not msg:
        if code in ErrorCodes.err_list:
            msg = ErrorCodes.err_list[code]
    print(f"\n### Error{scode}: {msg}\n", file=sys.stderr)
    sys.exit(1)


# ===============================================================================
#          PIN codes verification
# ===============================================================================
def verify_user_pin(gpgcard: GPGCard, user_pin: str, pinpad: bool) -> None:
    """Verify the User pin code, for both PW1 and PW2

    Args:
        gpgcard (GPGCard): smartcard object
        user_pin (str): User pin code
        pinpad (bool): Indicates to use pinpad
    """

    if not gpgcard.verify_pin(PassWord.PW1, user_pin, pinpad) or not gpgcard.verify_pin(PassWord.PW2, user_pin, pinpad):
        error(ErrorCodes.ERR_INTERNAL, "PIN not verified")


def verify_admin_pin(gpgcard: GPGCard, adm_pin: str, pinpad: bool) -> None:
    """Verify the Admin pin code

    Args:
        gpgcard (GPGCard): smartcard object
        adm_pin (str): Admin pin code
        pinpad (bool): Indicates to use pinpad
    """

    if not gpgcard.verify_pin(PassWord.PW3, adm_pin, pinpad):
        error(ErrorCodes.ERR_INTERNAL, "PIN not verified")


# ===============================================================================
#          Reset the Application
# ===============================================================================
def reset_app(gpgcard: GPGCard) -> None:
    """Reset Application and re-init

    Args:
        gpgcard (GPGCard): smartcard object
    """

    print("Reset application...")
    gpgcard.terminate()
    gpgcard.activate()
    print(" -> OK")


# ===============================================================================
#          Retrieve the OpenPGP Card information
# ===============================================================================
def printable(text: str) -> str:
    """Escape the control, format and other non-printable characters of a card text

    Args:
        text (str): Text read from the card

    Returns:
        The text, with each non-printable character as a Python escape sequence
    """

    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in text)


def get_info(gpgcard: GPGCard, display: bool = True) -> None:
    """Retrieve and display Card information

    Args:
        gpgcard (GPGCard): smartcard object
        display (bool): Print Card info
    """

    print("Get card info...")
    gpgcard.get_all()

    if not display:
        return

    line = "=" * 15
    print(f"{line} Application Identifier {line}")
    for k, v in gpgcard.decode_AID().items():
        if k == "AID":
            print(f" # {k:20s}: {v}")
        else:
            print(f"   - {k:18s}: {v}")
    print(f"{line} Historical Bytes {line}")
    for k, v in gpgcard.decode_histo().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} Max Extended Length {line}")
    for k, v in gpgcard.decode_extlength().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} PIN Info {line}")
    for k, v in gpgcard.decode_pws().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} Extended Capabilities {line}")
    for k, v in gpgcard.decode_ext_capabilities().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} Hardware Features {line}")
    for k, v in gpgcard.decode_hardware().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} User Info {line}")
    print(f" - {'Name':20s}: {printable(gpgcard.get_name())}")
    print(f" - {'Login':20s}: {printable(gpgcard.get_login())}")
    print(f" - {'URL':20s}: {printable(gpgcard.get_url())}")
    print(f" - {'Salutation':20s}: {printable(gpgcard.get_salutation())}")
    print(f" - {'Lang':20s}: {printable(gpgcard.get_lang())}")
    print(f"{line} Slots Info {line}")
    for k, v in gpgcard.decode_slot().items():
        print(f" - {k:20s}: {v}")
    print(f"{line} Keys Info {line}")
    print(f" - {'CDS counter':20s}: {gpgcard.get_sig_count()}")
    print(f" - {'RSA Pub Exponent':20s}: 0x{gpgcard.get_rsa_pub_exp():06x}")

    for key in [k.value for k in KeyTypes]:
        print(f" # {key}:")
        print(f"   - {'UIF':18s}: {gpgcard.decode_key_uif(key)}")
        print(f"   - {'Fingerprint':18s}: {gpgcard.get_key_fingerprint(key)}")
        print(f"   - {'CA fingerprint':18s}: {gpgcard.get_key_CA_fingerprint(key)}")
        print(f"   - {'Creation date':18s}: {gpgcard.get_key_date(key)}")
        print(f"   - {'Attribute':18s}: {gpgcard.decode_attributes(key)}")
        print(f"   - {'Certificate':18s}: {gpgcard.get_key_cert(key)}")


# ===============================================================================
#          Set fingerprints
# ===============================================================================
def set_fingerprints(gpgcard: GPGCard, fingerprints: str, key_type: KeyTypes | None = None) -> None:
    """Set Key template

    Args:
        gpgcard (GPGCard): smartcard object
        fingerprints (str): SIG, DEC, AUT fingerprints separated by ':'
        key_type (KeyTypes): Key type selected
    """

    d = {}
    if key_type is None:
        # Consider all keys fingerprints are given
        try:
            d[KeyTypes.KEY_SIG], d[KeyTypes.KEY_DEC], d[KeyTypes.KEY_AUT] = fingerprints.split(":")
        except ValueError as err:
            raise GPGCardExcpetion(0, f"Wrong fingerprints arguments: {err}") from err

    else:
        # a key_type is specified, using only this fingerprint
        d[key_type] = fingerprints

    for k, v in d.items():
        print(f"Set fingerprints for '{k}' Key...")
        gpgcard.set_key_fingerprint(k, bytes.fromhex(v))


# ===============================================================================
#          Set Key Templates
# ===============================================================================
def set_templates(gpgcard: GPGCard, templates: str, key_type: KeyTypes | None = None) -> None:
    """Set Key template

    Args:
        gpgcard (GPGCard): smartcard object
        templates (str): SIG, DEC, AUT template separated by ':'
        key_type (KeyTypes): Key type selected
    """

    d = {}
    if key_type is None:
        # Consider all keys template are given
        try:
            d[KeyTypes.KEY_SIG], d[KeyTypes.KEY_DEC], d[KeyTypes.KEY_AUT] = templates.split(":")
        except ValueError as err:
            raise GPGCardExcpetion(0, f"Wrong templates arguments: {err}") from err
    else:
        # a key_type is specified, using only this template
        d[key_type] = templates

    for _, v in d.items():
        if v not in KEY_TEMPLATES:
            raise GPGCardExcpetion(0, f"Invalid template: {v}")

    for k, v in d.items():
        print(f"Set template {v} for '{k}' Key...")
        gpgcard.set_template(k, v)


# ===============================================================================
#          Handle Asymmetric keys
# ===============================================================================
def handle_key(
    gpgcard: GPGCard,
    action: str,
    key_type: KeyTypes,
    file: str = "",
    seed: str | None = None,
) -> None:
    """Generate Key pair and/or Read Public key

    Args:
        gpgcard (GPGCard): smartcard object
        action (str): Generate or Read
        key_type (KeyTypes): Key type selected
        file (str): Public key export file
        seed (str): Seed derivation, None for a random key
    """

    if action not in KEY_OPERATIONS:
        raise GPGCardExcpetion(0, f"Invalid operation: {action}")

    key_list = [key_type] if key_type else list(KeyTypes)
    for key in key_list:
        print(f"{action} '{key}' Key...")
        key_action = "Read" if action == "Export" else action
        pubkey = gpgcard.asymmetric_key(key, key_action, SEED_DERIVATIONS[seed] if seed else 0)
        if action == "Export":
            if len(key_list) > 1:
                filename = key + "_" + file
            else:
                filename = file
            path = Path(filename)
            if path.suffix == "":
                filename += ".pem"
            gpgcard.export_pub_key(pubkey, filename)
        else:
            for k, v in pubkey.items():
                print(f" - {k:13s}: {v}")


# ===============================================================================
#          MAIN
# ===============================================================================
def entrypoint() -> None:
    """Main function"""

    # Arguments parsing
    # -----------------
    args = get_argparser()

    # PINs to verify: the User PIN (PW2) to select a slot, the Admin PIN (PW3) to write to the card
    needs_user = args.slot is not None
    needs_admin = bool(
        args.salutation
        or args.name
        or args.url
        or args.login
        or args.lang
        or args.serial
        or args.reset_code
        or args.reset
        or args.set_templates
        or args.set_fingerprints
        or args.seed_key
        or args.key_action == "Generate"
    )

    # Arguments checking
    # ------------------
    try:
        get_pins(
            args,
            user=args.reset_pw1 is None and (needs_user or args.new_user_pin is not None),
            admin=needs_admin or args.new_adm_pin is not None or args.reset_pw1 is not None,
        )
        if args.new_user_pin is not None:
            args.new_user_pin = get_secret(args.new_user_pin, "--new-user-pin", ENV_NEW_USER_PIN, "New User PIN", confirm=True)
            if not args.new_user_pin:
                error(ErrorCodes.ERR_INTERNAL, f"Provide the new User PIN in ${ENV_NEW_USER_PIN}")
        if args.new_adm_pin is not None:
            args.new_adm_pin = get_secret(args.new_adm_pin, "--new-adm-pin", ENV_NEW_ADMIN_PIN, "New Admin PIN", confirm=True)
            if not args.new_adm_pin:
                error(ErrorCodes.ERR_INTERNAL, f"Provide the new Admin PIN in ${ENV_NEW_ADMIN_PIN}")
        if args.reset_pw1 is not None:
            args.reset_pw1 = get_secret(args.reset_pw1, "--reset-pw1", ENV_NEW_USER_PIN, "New User PIN", confirm=True)
            if not args.reset_pw1:
                error(ErrorCodes.ERR_INTERNAL, f"Provide the new User PIN in ${ENV_NEW_USER_PIN}")
        elif args.reset_code is not None:
            args.reset_code = get_secret(args.reset_code, "--reset-code", ENV_RESET_CODE, "Resetting Code", confirm=True)
            if not args.reset_code:
                error(ErrorCodes.ERR_INTERNAL, f"Provide the Resetting Code in ${ENV_RESET_CODE}")
    except ValueError as err:
        error(ErrorCodes.ERR_INTERNAL, str(err))

    if args.serial and len(args.serial) != 8:
        error(
            ErrorCodes.ERR_INTERNAL,
            "Serial must be a 4 bytes hex string value (8 characters)",
        )

    if args.reset_code and len(args.reset_code) != 8:
        error(
            ErrorCodes.ERR_INTERNAL,
            "Reset Code must be a 4 bytes hex string value (8 characters)",
        )

    if args.key_action == "Export" and not args.file:
        error(ErrorCodes.ERR_INTERNAL, "Provide a file to export public key")

    # Processing
    # ----------
    gpgcard: GPGCard = GPGCard()
    try:
        print(f"Connect to card '{args.reader}'...")
        gpgcard.log_apdu(args.apdu)
        gpgcard.connect(args.reader)

        if args.reset_pw1:
            # The User PIN may be blocked: reset it with the Admin PIN, then verify the new value
            print("Verify PINs...")
            verify_admin_pin(gpgcard, args.adm_pin, args.pinpad)
            if not gpgcard.reset_PW1("", args.reset_pw1):
                error(ErrorCodes.ERR_INTERNAL, "User PIN not reset")
            args.user_pin = args.reset_pw1
            verify_user_pin(gpgcard, args.user_pin, args.pinpad)
        elif needs_user or needs_admin:
            print("Verify PINs...")
            if needs_user:
                verify_user_pin(gpgcard, args.user_pin, args.pinpad)
            if needs_admin:
                verify_admin_pin(gpgcard, args.adm_pin, args.pinpad)

        if args.slot:
            gpgcard.select_slot(args.slot - 1)

        if args.salutation:
            gpgcard.set_salutation(args.salutation)
        if args.name:
            gpgcard.set_name(args.name)
        if args.url:
            gpgcard.set_url(args.url)
        if args.login:
            gpgcard.set_login(args.login)
        if args.lang:
            gpgcard.set_lang(args.lang)

        if args.new_user_pin:
            if not gpgcard.change_pin(PassWord.PW1, args.user_pin, args.new_user_pin):
                error(ErrorCodes.ERR_INTERNAL, "User PIN not changed")
            # Changing the User PIN closes the PW2 session
            args.user_pin = args.new_user_pin
            verify_user_pin(gpgcard, args.user_pin, args.pinpad)
        if args.new_adm_pin:
            if not gpgcard.change_pin(PassWord.PW3, args.adm_pin, args.new_adm_pin):
                error(ErrorCodes.ERR_INTERNAL, "Admin PIN not changed")
            # Check that the card accepts the new Admin PIN
            args.adm_pin = args.new_adm_pin
            verify_admin_pin(gpgcard, args.adm_pin, args.pinpad)
        if args.reset_code:
            # Use the Resetting code to set the value
            if not gpgcard.set_RC(args.reset_code):
                error(ErrorCodes.ERR_INTERNAL, "Resetting Code not set")

        get_info(gpgcard, args.info)

        if args.reset:
            reset_app(gpgcard)

        if args.set_templates:
            set_templates(gpgcard, args.set_templates, args.key_type)

        if args.seed_key and not args.key_action:
            gpgcard.seed_key(SEED_DERIVATIONS[args.seed_key])

        if args.set_fingerprints:
            set_fingerprints(gpgcard, args.set_fingerprints, args.key_type)

        if args.serial:
            gpgcard.set_serial(args.serial)

        if args.key_action:
            handle_key(gpgcard, args.key_action, args.key_type, args.file, args.seed_key)

    except GPGCardExcpetion as err:
        error(err.code, err.message)
    except (OSError, ValueError, KeyError) as err:
        error(0, repr(err))
    finally:
        if gpgcard.transport is not None:
            cleared = True
            try:
                gpgcard.logout()
            except GPGCardExcpetion:
                cleared = False
            gpgcard.disconnect()
            if not cleared:
                print(
                    "\n### Error: the PIN session could not be cleared on the card; exit the OpenPGP app or unplug the device!\n",
                    file=sys.stderr,
                )
                sys.exit(1)


if __name__ == "__main__":
    entrypoint()
