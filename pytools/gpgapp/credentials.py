# *****************************************************************************
#   Ledger App OpenPGP.
#   (c) 2026 Ledger SAS.
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

import os
import sys
from getpass import getpass

# Value of an option given without argument: the secret is read from the environment or prompted
ASK = object()

ENV_USER_PIN = "OPENPGP_USER_PIN"
ENV_ADMIN_PIN = "OPENPGP_ADMIN_PIN"
ENV_NEW_USER_PIN = "OPENPGP_NEW_USER_PIN"
ENV_NEW_ADMIN_PIN = "OPENPGP_NEW_ADMIN_PIN"
ENV_RESET_CODE = "OPENPGP_RESET_CODE"
ENV_FILE_PASSPHRASE = "OPENPGP_FILE_PASSPHRASE"


def get_secret(value, option: str, env: str, prompt: str, confirm: bool = False) -> str | None:
    """Resolve a secret from its command line option, the environment, or an interactive prompt

    Args:
        value: Option value: a string, ASK, or None when the option is absent
        option (str): Option name, for messages
        env (str): Environment variable holding the secret
        prompt (str): Interactive prompt
        confirm (bool): Ask the secret twice

    Returns:
        The secret, or None when it is not provided and cannot be prompted
    """

    if isinstance(value, str):
        print(
            f"Warning: {option} exposes its value in the process list and the shell history."
            f" Prefer the {env} environment variable, or {option} without value to be prompted.",
            file=sys.stderr,
        )
        return value
    if os.environ.get(env):
        return os.environ[env]
    if not sys.stdin.isatty():
        return None
    secret = getpass(f"{prompt}: ")
    if confirm and secret and getpass(f"{prompt} (again): ") != secret:
        raise ValueError(f"{prompt}: the two entries differ")
    return secret or None


def get_pins(args, user: bool = True) -> None:
    """Resolve the User and Admin PINs of the parsed arguments, defaulting to the factory values

    Args:
        args: Parsed arguments, with 'pinpad', 'user_pin' and 'adm_pin'
        user (bool): Resolve the User PIN too
    """

    if args.pinpad:
        return
    if user:
        args.user_pin = get_secret(args.user_pin, "--user-pin", ENV_USER_PIN, "User PIN (empty for default)")
        if not args.user_pin:
            args.user_pin = "123456"
            print(f"Using default 'userpin': {args.user_pin}")
    args.adm_pin = get_secret(args.adm_pin, "--adm-pin", ENV_ADMIN_PIN, "Admin PIN (empty for default)")
    if not args.adm_pin:
        args.adm_pin = "12345678"
        print(f"Using default 'admpin': {args.adm_pin}")
