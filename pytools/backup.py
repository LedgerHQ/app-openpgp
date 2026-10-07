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

from gpgapp.credentials import ASK, ENV_ADMIN_PIN, ENV_FILE_PASSPHRASE, ENV_USER_PIN, get_pins, get_secret
from gpgapp.gpgcard import GPGCard, GPGCardExcpetion, PassWord


# ===============================================================================
#          Parse command line options
# ===============================================================================
def get_argparser() -> Namespace:
    """Parse the commandline options"""

    parser = ArgumentParser(
        description="Backup/Restore OpenPGP App configuration",
        epilog="Keys restore is only possible with SEED mode...\n"
        + "PIN and passphrase options given without value are read from their environment variable,\n"
        + "or prompted. Giving the value on the command line exposes it in the process list.",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "--reader",
        type=str,
        default="Ledger",
        help="HID path of the device, or 'speculos' (default is '%(default)s', the only Ledger device connected)",
    )

    parser.add_argument("--apdu", action="store_true", help="Log APDU exchange")
    parser.add_argument("--slot", type=int, choices=range(1, 4), help="Select slot (1 to 3)")

    parser.add_argument("--pinpad", action="store_true", help="PIN validation delegated to pinpad")
    parser.add_argument(
        "--adm-pin", metavar="PIN", nargs="?", const=ASK, help=f"Admin PIN (if pinpad not used), or ${ENV_ADMIN_PIN}"
    )
    parser.add_argument(
        "--user-pin", metavar="PIN", nargs="?", const=ASK, help=f"User PIN (if pinpad not used), or ${ENV_USER_PIN}"
    )

    parser.add_argument("--restore", action="store_true", help="Perform a Restore instead of Backup")

    parser.add_argument(
        "--file",
        type=str,
        default="gpg_backup",
        help="Backup/Restore file (default is '%(default)s')",
    )

    parser.add_argument(
        "--seed-key",
        action="store_true",
        help="After Restore, regenerate the backed up keys from the device seed and check their fingerprints",
    )

    parser.add_argument(
        "--file-passphrase",
        metavar="PASS",
        nargs="?",
        const=ASK,
        help=f"Passphrase to encrypt (backup) or decrypt (restore) the backup file, or ${ENV_FILE_PASSPHRASE}",
    )

    return parser.parse_args()


# ===============================================================================
#          MAIN
# ===============================================================================
def entrypoint() -> None:
    """Main function"""

    # Arguments parsing
    # -----------------
    args = get_argparser()

    # Arguments checking
    # ------------------
    try:
        get_pins(args)
        if args.file_passphrase is not None:
            args.file_passphrase = get_secret(
                args.file_passphrase,
                "--file-passphrase",
                ENV_FILE_PASSPHRASE,
                "File passphrase",
                confirm=not args.restore,
            )
            if not args.file_passphrase:
                print(f"Provide the file passphrase in ${ENV_FILE_PASSPHRASE}. Aborting!")
                sys.exit()
    except ValueError as err:
        print(f"{err}. Aborting!")
        sys.exit()

    if args.restore is False:
        if Path(args.file).is_file():
            print(f"Provided backup file '{args.file}' already exist. Aborting!")
            sys.exit()

    # Processing
    # ----------
    gpgcard: GPGCard = GPGCard()
    try:
        print(f"Connect to card '{args.reader}'...")
        gpgcard.log_apdu(args.apdu)
        gpgcard.connect(args.reader)

        # PW2 (same value as PW1) is required to read/write the private DOs
        # 0x0101 and 0x0103; verifying only PW1+PW3 silently loses them.
        if (
            not gpgcard.verify_pin(PassWord.PW1, args.user_pin, args.pinpad)
            or not gpgcard.verify_pin(PassWord.PW2, args.user_pin, args.pinpad)
            or not gpgcard.verify_pin(PassWord.PW3, args.adm_pin, args.pinpad)
        ):
            raise GPGCardExcpetion(0, "PIN not verified")

        if args.slot:
            gpgcard.select_slot(args.slot - 1)

        gpgcard.get_all()

        if args.restore:
            gpgcard.restore(args.file, args.file_passphrase, seed_key=args.seed_key)
            print(f"Configuration restored from file '{args.file}'.")

            if args.seed_key:
                gpgcard.restore_seed_keys()

        else:
            gpgcard.backup(args.file, args.file_passphrase)
            print(f"Configuration saved in file '{args.file}'.")
            if args.file_passphrase is None:
                print(
                    "Warning: the file is not encrypted, its private data objects and card details are readable."
                    " Use --file-passphrase to encrypt it."
                )

    except GPGCardExcpetion as err:
        print(f"\n### Error {err.code}: {err.message}!\n")
    finally:
        if gpgcard.transport is not None:
            try:
                gpgcard.logout()
            except GPGCardExcpetion:
                pass
            gpgcard.disconnect()


if __name__ == "__main__":
    entrypoint()
