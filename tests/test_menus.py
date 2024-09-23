from typing import Sequence
import pytest
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.navigator.navigator import InstructionType

from application_client.command_sender import CommandSender
from application_client.app_def import PassWord

from utils import check_pincode
from utils import ROOT_SCREENSHOT_PATH


# In this test we check the behavior of the Slot menu
# The Navigations go and check:
#  - Select slot / Slot 2 / (next page) / Set default
def test_menu_slot(firmware: Firmware, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # Check slots availability
    nb_slots, def_slot = client.get_slot_config()
    print("Slots configuration:")
    print(f"  Nb: {nb_slots}")
    print(f"  default: {def_slot}")
    if nb_slots == 1:
        pytest.skip("single slot configuration")

    # Navigate in the main menu
    instructions: Sequence[InstructionType]
    if firmware.is_nano:
        initial_instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Select slot
        ]
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Slot 2
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Set as default)
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back)
        ]

    else:
        initial_instructions = [
            NavInsID.USE_CASE_CHOICE_CONFIRM,    # Slots
        ]
        instructions = [
            NavIns(NavInsID.TOUCH, (350, 220)), # Slot 2
            NavInsID.CENTERED_FOOTER_TAP,       # Set default
        ]

    # Navigate to settings menu to avoid 1st screen with random serial no
    navigator.navigate(initial_instructions,
                        screen_change_before_first_instruction=False,
                        screen_change_after_last_instruction=True)

    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                   screen_change_before_first_instruction=False,
                                   screen_change_after_last_instruction=False)


# In this test we check the behavior of the Setting menus
# The Navigations go and check:
#  - Settings / Key Template / Decryption / SECP 256K1 / Confirm
#               Seed mode
#               (back)
#               PIN mode / On Screen / (next page) / Set default
#               UIF / Enable UIF for Signature
#               (back)
#               Reset / Long press 'Yes'
def test_menu_settings(firmware: Firmware, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    # Navigate in the main menu
    instructions: Sequence[InstructionType]
    if firmware == Firmware.NANOS:
        # Use the app interface instead of raw interface
        client = CommandSender(backend)

        # Check slots availability
        nb_slots, _ = client.get_slot_config()

        initial_instructions = []
        if nb_slots > 1:
            initial_instructions.append(NavInsID.RIGHT_CLICK)
        initial_instructions.append(NavInsID.RIGHT_CLICK)
        initial_instructions.append(NavInsID.BOTH_CLICK)    # Settings

        instructions = [
            NavInsID.BOTH_CLICK,    # Key Template
            NavInsID.BOTH_CLICK,    # Choose Key
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Decryption
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Choose Type
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # NIST P256
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Set Template
            NavInsID.BOTH_CLICK,    # OK
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Seed mode ON
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # PIN mode
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # On Screen
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Set as default
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # UIF
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # UIF for Signature
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Reset
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Validate
        ]

    elif firmware.is_nano:
        initial_instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Settings
        ]
        instructions = [
            NavInsID.BOTH_CLICK,    # Key Template
            NavInsID.BOTH_CLICK,    # Choose Key
            NavInsID.RIGHT_CLICK,   # Decryption
            NavInsID.RIGHT_CLICK,   # Authentication
            NavInsID.BOTH_CLICK,    # Key Authentication
            NavInsID.RIGHT_CLICK,   # Choose Type
            NavInsID.BOTH_CLICK,    # (Select)
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # SECP 256R1
            NavInsID.RIGHT_CLICK,   # Type SECP 256R1
            NavInsID.BOTH_CLICK,    # Set Template
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back)

            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Seed mode ON
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # PIN mode
            NavInsID.BOTH_CLICK,    # On Screen
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Set as default
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # UIF
            NavInsID.BOTH_CLICK,    # UIF for Signature
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # (Back to settings)

            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Reset
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,    # Validate
        ]

    else:
        initial_instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,    # Settings
        ]
        if firmware == Firmware.STAX:
            instructions = [
                NavIns(NavInsID.TOUCH, (350, 130)), # Key Template
                NavIns(NavInsID.TOUCH, (350, 390)), # Authentication
                NavIns(NavInsID.TOUCH, (350, 390)), # SECP 256K1
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (350, 220)), # Seed mode
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (350, 300)), # PIN mode
                NavIns(NavInsID.TOUCH, (350, 130)), # On Screen
                NavInsID.CENTERED_FOOTER_TAP,       # Set default
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (350, 390)), # UIF
                NavIns(NavInsID.TOUCH, (350, 130)), # UIF for Signature
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (350, 480)), # Reset
                NavInsID.USE_CASE_CHOICE_CONFIRM,   # Press 'Reset'
            ]

        else:
            instructions = [
                NavIns(NavInsID.TOUCH, (430, 130)), # Key Template
                NavIns(NavInsID.TOUCH, (430, 420)), # Authentication
                NavIns(NavInsID.TOUCH, (430, 320)), # SECP 256K1
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (430, 230)), # Seed mode
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (430, 325)), # PIN mode
                NavIns(NavInsID.TOUCH, (430, 140)), # On Screen
                NavInsID.EXIT_FOOTER_TAP,       # Set default
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavIns(NavInsID.TOUCH, (430, 420)), # UIF
                NavIns(NavInsID.TOUCH, (430, 130)), # UIF for Signature
                NavInsID.NAVIGATION_HEADER_TAP,     # (Back)
                NavInsID.USE_CASE_SETTINGS_NEXT,    # Next page
                NavIns(NavInsID.TOUCH, (430, 130)), # Reset
                NavInsID.USE_CASE_CHOICE_CONFIRM,   # Press 'Reset'
            ]

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Navigate to settings menu to avoid 1st screen with random serial no
    navigator.navigate(initial_instructions,
                        screen_change_before_first_instruction=False,
                        screen_change_after_last_instruction=True)

    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                   screen_change_before_first_instruction=False,
                                   screen_change_after_last_instruction=False)
