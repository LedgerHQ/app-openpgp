from collections.abc import Sequence

import pytest
from application_client.app_def import DataObject, Errors, PassWord, PubkeyAlgo
from application_client.command_sender import CommandSender
from ledgered.devices import Device, DeviceType
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID
from ragger.navigator.navigator import InstructionType
from utils import KEY_TEMPLATES, ROOT_SCREENSHOT_PATH, check_pincode, generate_key, get_key_attributes


# In this test we check the behavior of the Slot menu
# The Navigations go and check:
#  - Select slot / Slot 2 / (next page) / Set default
def test_menu_slot(device: Device, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:

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
    if device.is_nano:
        initial_instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Select slot
        ]
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Slot 2
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # (Set as default)
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # (Back)
        ]

    else:
        initial_instructions = [
            NavInsID.USE_CASE_CHOICE_CONFIRM,  # Slots
        ]
        if device.type == DeviceType.APEX_P:
            instructions = [NavIns(NavInsID.TOUCH, (270, 160))]  # Slot 2
        else:
            instructions = [NavIns(NavInsID.TOUCH, (350, 220))]  # Slot 2
        instructions += [NavInsID.CENTERED_FOOTER_TAP]  # Set default

    # Navigate to settings menu to avoid 1st screen with random serial no
    navigator.navigate(
        initial_instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=True,
    )

    navigator.navigate_and_compare(
        ROOT_SCREENSHOT_PATH,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )


# In this test we check the behavior of the Setting menus
# The Navigations go and check:
#  - Settings / Key Template / Decryption / SECP 256K1 / Confirm
#               Seed mode
#               (back)
#               PIN mode / On Screen / (next page) / Set default
#               UIF / Enable UIF for Signature
#               (back)
#               Reset / Long press 'Yes'
def test_menu_settings(device: Device, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    # Navigate in the main menu
    instructions: Sequence[InstructionType]
    if device.is_nano:
        initial_instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Settings
        ]
        instructions = [
            NavInsID.BOTH_CLICK,  # Key Template
            NavInsID.RIGHT_CLICK,  # Decryption
            NavInsID.RIGHT_CLICK,  # Authentication
            NavInsID.BOTH_CLICK,  # Key Authentication
            NavInsID.RIGHT_CLICK,  # Choose Type
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # SECP 256R1
            NavInsID.RIGHT_CLICK,  # Type SECP 256R1
            NavInsID.BOTH_CLICK,  # (Back)
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Seed mode ON
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # (Back to settings)
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # PIN mode
            NavInsID.BOTH_CLICK,  # Random keypad
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Set as default
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # (Back to settings)
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # UIF
            NavInsID.BOTH_CLICK,  # UIF for Signature
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # (Back to settings)
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Reset
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # Validate
        ]

    else:
        initial_instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,  # Settings
        ]
        if device.type == DeviceType.STAX:
            instructions = [
                NavIns(NavInsID.TOUCH, (350, 130)),  # Key Template
                NavIns(NavInsID.TOUCH, (350, 330)),  # Authentication
                NavIns(NavInsID.TOUCH, (350, 420)),  # SECP 256K1
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (350, 220)),  # Seed mode
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (350, 320)),  # PIN mode
                NavIns(NavInsID.TOUCH, (350, 140)),  # Random keypad
                NavInsID.CENTERED_FOOTER_TAP,  # Set default
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (350, 420)),  # UIF
                NavIns(NavInsID.TOUCH, (350, 130)),  # UIF for Signature
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (350, 510)),  # Reset
                NavInsID.USE_CASE_CHOICE_CONFIRM,  # Press 'Reset'
            ]
        elif device.type == DeviceType.FLEX:
            instructions = [
                NavIns(NavInsID.TOUCH, (430, 130)),  # Key Template
                NavIns(NavInsID.TOUCH, (430, 320)),  # Authentication
                NavIns(NavInsID.TOUCH, (430, 410)),  # SECP 256K1
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (430, 230)),  # Seed mode
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (430, 325)),  # PIN mode
                NavIns(NavInsID.TOUCH, (430, 140)),  # Random keypad
                NavInsID.EXIT_FOOTER_TAP,  # Set default
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (430, 420)),  # UIF
                NavIns(NavInsID.TOUCH, (430, 140)),  # UIF for Signature
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavInsID.USE_CASE_SETTINGS_NEXT,  # Next page
                NavIns(NavInsID.TOUCH, (430, 130)),  # Reset
                NavInsID.USE_CASE_CHOICE_CONFIRM,  # Press 'Reset'
            ]
        else:
            instructions = [
                NavIns(NavInsID.TOUCH, (270, 90)),  # Key Template
                NavIns(NavInsID.TOUCH, (265, 230)),  # Authentication
                NavIns(NavInsID.TOUCH, (275, 300)),  # SECP 256K1
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (270, 160)),  # Seed mode
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (270, 235)),  # PIN mode
                NavIns(NavInsID.TOUCH, (270, 90)),  # Random keypad
                NavInsID.EXIT_FOOTER_TAP,  # Set default
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavIns(NavInsID.TOUCH, (270, 300)),  # UIF
                NavIns(NavInsID.TOUCH, (270, 90)),  # UIF for Signature
                NavInsID.NAVIGATION_HEADER_TAP,  # (Back)
                NavInsID.USE_CASE_SETTINGS_NEXT,  # Next page
                NavIns(NavInsID.TOUCH, (270, 90)),  # Reset
                NavInsID.USE_CASE_CHOICE_CONFIRM,  # Press 'Reset'
            ]

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    # Verify PW2 (User)
    check_pincode(client, PassWord.PW2)

    # Navigate to settings menu to avoid 1st screen with random serial no
    navigator.navigate(
        initial_instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=True,
    )

    navigator.navigate_and_compare(
        ROOT_SCREENSHOT_PATH,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=False,
    )


# In this test we check that a Curve25519 decryption key is labelled Curve25519, not Ed25519:
#  - Settings / Key Template (summary) / Decryption (choices)
def test_menu_template_decryption_label(device: Device, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)
    rapdu = client.set_template(DataObject.DO_DEC_ATTR, KEY_TEMPLATES["cv25519"])
    assert rapdu.status == Errors.SW_OK

    instructions: Sequence[InstructionType]
    if device.is_nano:
        initial_instructions = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]  # Settings
        instructions = [
            NavInsID.BOTH_CLICK,  # Key Template
            NavInsID.RIGHT_CLICK,  # Decryption
            NavInsID.BOTH_CLICK,  # Key Decryption
        ]
    else:
        initial_instructions = [NavInsID.USE_CASE_HOME_SETTINGS]
        positions = {
            DeviceType.STAX: ((350, 130), (350, 230)),
            DeviceType.FLEX: ((430, 130), (430, 225)),
            DeviceType.APEX_P: ((270, 90), (265, 160)),
        }
        # Key Template, Decryption
        instructions = [NavIns(NavInsID.TOUCH, pos) for pos in positions[device.type]]
        if device.type != DeviceType.STAX:
            # Page holding Curve25519
            instructions.append(NavInsID.USE_CASE_SETTINGS_NEXT)

    navigator.navigate(
        initial_instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=True,
    )
    navigator.navigate_and_compare(
        ROOT_SCREENSHOT_PATH,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )


def _change_template_with_key(
    device: Device, backend: BackendInterface, navigator: Navigator, test_name: str, confirm: bool
) -> None:
    """Generate the AUT key, then select another AUT template on the device and answer the confirmation"""

    client = CommandSender(backend)
    generate_key(client, DataObject.DO_AUT_KEY)

    to_new_type: Sequence[InstructionType]
    if device.is_nano:
        initial_instructions = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]  # Settings
        to_new_type = [
            NavInsID.BOTH_CLICK,  # Key Template
            NavInsID.RIGHT_CLICK,  # Decryption
            NavInsID.RIGHT_CLICK,  # Authentication
            NavInsID.BOTH_CLICK,  # Key Authentication
            NavInsID.RIGHT_CLICK,  # Choose Type
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,  # SECP 256R1
        ]
    else:
        initial_instructions = [NavInsID.USE_CASE_HOME_SETTINGS]
        positions = {
            DeviceType.STAX: ((350, 130), (350, 330), (350, 420)),
            DeviceType.FLEX: ((430, 130), (430, 320), (430, 410)),
            DeviceType.APEX_P: ((270, 90), (265, 230), (275, 300)),
        }
        # Key Template, Authentication, SECP 256K1
        to_new_type = [NavIns(NavInsID.TOUCH, pos) for pos in positions[device.type]]

    navigator.navigate(
        initial_instructions,
        screen_change_before_first_instruction=False,
        screen_change_after_last_instruction=True,
    )
    navigator.navigate(to_new_type, screen_change_before_first_instruction=False)

    if device.is_nano:
        navigator.navigate_until_text_and_compare(
            NavInsID.RIGHT_CLICK,
            [NavInsID.BOTH_CLICK],
            "Yes, delete key" if confirm else "Cancel",
            ROOT_SCREENSHOT_PATH,
            test_name,
            screen_change_before_first_instruction=False,
        )
    else:
        navigator.navigate_and_compare(
            ROOT_SCREENSHOT_PATH,
            test_name,
            [NavInsID.USE_CASE_CHOICE_CONFIRM if confirm else NavInsID.USE_CASE_CHOICE_REJECT],
            screen_change_before_first_instruction=False,
        )


# In this test we check that cancelling a template change keeps the existing key
def test_menu_template_change_cancelled(device: Device, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    _change_template_with_key(device, backend, navigator, test_name, confirm=False)

    client = CommandSender(backend)
    rapdu = client.read_key(DataObject.DO_AUT_KEY)
    assert rapdu.status == Errors.SW_OK
    key_algo, _ = get_key_attributes(client, DataObject.DO_AUT_ATTR)
    assert key_algo == PubkeyAlgo.RSA


# In this test we check that confirming a template change deletes the existing key
def test_menu_template_change_confirmed(device: Device, backend: BackendInterface, navigator: Navigator, test_name: str) -> None:
    _change_template_with_key(device, backend, navigator, test_name, confirm=True)

    client = CommandSender(backend)
    rapdu = client.read_key(DataObject.DO_AUT_KEY)
    assert rapdu.status == Errors.SW_REFERENCED_DATA_NOT_FOUND
    key_algo, _ = get_key_attributes(client, DataObject.DO_AUT_ATTR)
    assert key_algo == PubkeyAlgo.ECDSA


# In this test we check that the home screen only displays the current cardholder name
def test_home_name(device: Device, backend: BackendInterface, navigator: Navigator) -> None:
    client = CommandSender(backend)
    check_pincode(client, PassWord.PW3)

    rapdu = client.put_data(DataObject.DO_CARD_NAME, b"Alexander")
    assert rapdu.status == Errors.SW_OK
    rapdu = client.put_data(DataObject.DO_CARD_NAME, b"Bob")
    assert rapdu.status == Errors.SW_OK

    # Refuse a PIN confirmation to get back to a refreshed home screen
    if device.is_nano:
        nav_inst, valid_instr, text = NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "No"
    else:
        nav_inst, valid_instr, text = NavInsID.USE_CASE_REVIEW_REJECT, [NavInsID.USE_CASE_CHOICE_REJECT], "Confirm"
    with pytest.raises(ExceptionRAPDU):
        with client.send_verify_pw_with_confirmation(PassWord.PW1):
            navigator.navigate_until_text(nav_inst, valid_instr, text, screen_change_after_last_instruction=False)

    backend.wait_for_text_on_screen("Bob")
    assert not backend.compare_screen_with_text("Bobxander")
