# Copyright 2018 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
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
#

import sys
import argparse

from .gpgcard import GPGCard

def get_argparser():
        parser = argparse.ArgumentParser(epilog="""
Note 1: reset, backup, restore are always executed in THIS order
 """
)
        parser.add_argument('--adm-pin',   metavar='PIN',          help='Administrative PIN, if pinpad not used')
        parser.add_argument('--backup',                            help='Perfom a full backup except the key',              action='store_true')                           
        parser.add_argument('--backup-keys',                       help='Perfom keys encrypted backup',                     action='store_true')                           
        parser.add_argument('--file',                              help='basckup/restore file',                             type=str, default='backup_card.pickle')
        parser.add_argument('--pinpad',                            help='PIN validation will be deledated to pinpad',       action='store_true')
        parser.add_argument('--reader',                            help='PCSC reader',                                      type=str, default='pcsc:Ledger') 
        parser.add_argument('--reset',                             help='Reset the application. All data are erased',       action='store_true')
        parser.add_argument('--restore',                           help='Perfom a full restore except the key',             action='store_true')
        parser.add_argument('--set-serial', metavar='SERIAL',      help='set the four serial bytes')
        parser.add_argument('--set-fp',     metavar='SIG:DEC:AUT', help='sig:dec:aut fingerprints, 20 bytes each in hexa')
        parser.add_argument('--seed-key',                          help='Regenerate all keys, based on seed mode',          action='store_true')
        parser.add_argument('--user-pin',   metavar='PIN',         help='User PIN, if pinpad not used')
        return parser

def banner():
    print(
"""
GPG Ledger Admin Tool v0.1.
Copyright 2018 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS

""" 
    )


def error(msg) :
    print("Error: ")
    print("  "+msg)
    sys.exit()

banner()

args = get_argparser().parse_args()

if args.backup and args.restore:
    error('Only one backup or restore must be specified')


if not args.pinpad:
    if not args.adm_pin is None or not args.user_pin:
        error('If pinpad is not use, userpin and admpin must be provided')


try:

    print("Connect to card...", end='', flush=True)
    gpgcard = GPGCard()
    gpgcard.connect(args.reader)
    print("OK")

    print("Verfify PINs...", end='', flush=True)
    if args.pinpad:
        if not gpgcard.verify_pin(0x82, "", True) or not gpgcard.verify_pin(0x83, "", True):
           error("PIN not verified")
    else:
        if not gpgcard.verify_pin(0x82, args.user_pin) or not gpgcard.verify_pin(0x83, args.adm_pin):
           error("PIN not verified")
    print("OK")

    if args.reset:
        print("Reset application...", end='', flush=True)
        if not gpgcard.terminate() or not gpgcard.activate():
            error ("NOK")
        print("OK")

    print("Get card info...", end='', flush=True)
    gpgcard.get_all()
    print("OK", flush=True)

    if args.backup:
        print("Backup application...", end='', flush=True)
        if not gpgcard.backup(args.file, args.backup_keys):
            error("NOK")
        print("OK")

    if args.restore:
        print("Restore application...", end='', flush=True)
        if not gpgcard.restore(args.file, args.seed_key):
            error("NOK")
        print("OK", flush=True)

    if args.set_fp:
        print("Set fingerprints...", end='', flush=True)
        sig,dec,aut = args.setfp.split(":")
        if (not gpgcard.set_key_fingerprints("sig", sig) or 
            not gpgcard.set_key_fingerprints("dec", dec) or
            not gpgcard.set_key_fingerprints("aut", aut)):
            error("NOK")
        print("OK", flush=True)

    if args.set_serial:
        print("Set serial...", end='', flush=True)
        serial = binascii.unhexilify(args.set_serial)
        if len(serial>8) :
            error('Serial must be a 4 bytes hexa string value (8 characters)')
        gpgcard.set_serial(args.set_serial)
        print("OK", flush=True)
except Exception as e:
    error(str(e))
