#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#*****************************************************************************
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
#*****************************************************************************

import sys
from pathlib import Path
from argparse import ArgumentParser, RawTextHelpFormatter, Namespace
from gpgapp.gpgcard import GPGCard, PassWord, GPGCardExcpetion

# ===============================================================================
#          Parse command line options
# ===============================================================================
def get_argparser() -> Namespace:
    """Parse the commandline options"""

    parser = ArgumentParser(
        description="Backup/Restore OpenPGP App configuration",
        epilog="Keys restore is only possible with SEED mode...",
        formatter_class=RawTextHelpFormatter
    )
    parser.add_argument("--reader", type=str, default="Ledger",
                        help="PCSC reader name (default is '%(default)s') or 'speculos'")

    parser.add_argument("--slot", type=int, choices=range(1, 4), help="Select slot (1 to 3)")

    parser.add_argument("--pinpad", action="store_true",
                        help="PIN validation will be delegated to pinpad")
    parser.add_argument("--adm-pin", metavar="PIN",
                        help="Admin PIN (if pinpad not used)", required="--pinpad" not in sys.argv)
    parser.add_argument("--user-pin", metavar="PIN",
                        help="User PIN (if pinpad not used)", required="--pinpad" not in sys.argv)

    parser.add_argument("--restore", action="store_true",
                       help="Perform a Restore instead of Backup")

    parser.add_argument("--file", type=str, default="gpg_backup",
                        help="Backup/Restore file (default is '%(default)s')")

    parser.add_argument("--seed-key", action="store_true",
                        help="After Restore, regenerate all keys, based on seed mode")

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
    if not args.pinpad:
        if not args.adm_pin or not args.user_pin:
            print("If 'pinpad' is not use, 'userpin' and 'admpin' must be provided.")
            sys.exit()

    if args.restore is False:
        if Path(args.file).is_file():
            print(f"Provided backup file '{args.file}' already exist. Aborting!")
            sys.exit()

    # Processing
    # ----------
    try:
        print(f"Connect to card '{args.reader}'...")
        gpgcard: GPGCard = GPGCard()
        gpgcard.connect(args.reader)

        if not gpgcard.verify_pin(PassWord.PW1, args.user_pin, args.pinpad) or \
           not gpgcard.verify_pin(PassWord.PW3, args.adm_pin,  args.pinpad):
            raise GPGCardExcpetion(0, "PIN not verified")

        if args.slot:
            gpgcard.select_slot(args.slot - 1)

        gpgcard.get_all()

        if args.restore:
            gpgcard.restore(args.file)
            print(f"Configuration restored from file '{args.file}'.")

            if args.seed_key:
                gpgcard.seed_key()

        else:
            gpgcard.backup(args.file)
            print(f"Configuration saved in file '{args.file}'.")

        gpgcard.disconnect()

    except GPGCardExcpetion as err:
        print(f"\n### Error {err.code}: {err.message}!\n")


if __name__ == "__main__":

    entrypoint()
