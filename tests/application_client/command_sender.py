# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command sending part.
"""
from typing import Generator, Optional, Tuple
from contextlib import contextmanager

import binascii

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.error import ExceptionRAPDU

from application_client.app_def import ClaType, InsType, PassWord, Errors, DataObject, PubkeyAlgo


class CommandSender:
    """Base class to send APDU to the selected backend"""

    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend


    ############### CARD interface ###############
    def send_select(self) -> RAPDU:
        """APDU Select

        Returns:
            Response APDU
        """

        data = binascii.unhexlify(b"06D27600012401")
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_SELECT,
                                    p1=0x04,
                                    data=data)

    def send_activate(self) -> RAPDU:
        """APDU Activate

        Returns:
            Response APDU
        """

        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_ACTIVATE_FILE)

    def send_terminate(self) -> RAPDU:
        """APDU Terminate

        Returns:
            Response APDU
        """

        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_TERMINATE_DF)


    ############### API interfaces ###############
    def get_data(self, tag: DataObject) -> RAPDU:
        """APDU Get Data

        Args:
            tag (DataObject): Tag identifying the data to process

        Returns:
            Response APDU
        """

        p1 = 0x00 if tag <= 0xFF else (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_GET_DATA,
                                    p1=p1,
                                    p2=p2)

    def put_data(self, tag: DataObject, data: bytes) -> RAPDU:
        """APDU Put Data

        Args:
            tag (DataObject): Tag identifying the data to process
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        p1 = 0x00 if tag <= 0xFF else (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_PUT_DATA,
                                    p1=p1,
                                    p2=p2,
                                    data=data)


    ############### SLOT interface ###############
    def get_slot(self) -> int:
        """APDU Get Slot

        Returns:
            Response APDU
        """

        rapdu = self.get_data(DataObject.CMD_SLOT_CUR)
        assert rapdu.status == Errors.SW_OK
        return int.from_bytes(rapdu.data, "big")


    def get_slot_config(self) -> Tuple[int, int]:
        """APDU Get Slot config

        Returns:
            Number of slots available and default one
        """

        rapdu = self.get_data(DataObject.CMD_SLOT_CFG)
        assert rapdu.status == Errors.SW_OK
        nb_slots = rapdu.data[0]
        def_slot = rapdu.data[1]
        return nb_slots, def_slot


    def set_slot(self, slot: int) -> RAPDU:
        """APDU Set Slot

        Args:
            slot (int): Slot number (0 - 2)

        Returns:
            Response APDU
        """

        assert slot >= 0
        assert slot <= 3
        data = slot.to_bytes(1, "big")
        return self.put_data(DataObject.CMD_SLOT_CUR, data)


    ############### PASSWORD interface ###############
    def send_verify_pw(self, pwd: PassWord, value: str="", reset: bool=False) -> RAPDU:
        """APDU Verify Pincode

        Args:
            pwd (PassWord): Password type
            value (str):    Pincode value
            reset (bool):   Set the Pincode status to 'not verified'

        Returns:
            Response APDU
        """

        if value:
            assert reset is False
            data = value.encode("utf-8")
        else:
            data = b""
        p1 = 0xFF if reset else 0x00
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_VERIFY,
                                    p1=p1,
                                    p2=pwd,
                                    data=data)


    @contextmanager
    def send_verify_pw_with_confirmation(self, pwd: PassWord) -> Generator[None, None, None]:
        """APDU Verify Pincode - with confirmation

        Args:
            pwd (PassWord): Password type

        Returns:
            Response APDU
        """

        with self.backend.exchange_async(cla=ClaType.CLA_APP_VERIFY,
                                    ins=InsType.INS_VERIFY,
                                    p2=pwd) as response:
            yield response

    def send_change_pw(self, pwd: PassWord, actual: str, new: str) -> RAPDU:
        """APDU Change Pincode

        Args:
            pwd (PassWord): Password type
            actual (str):   Current pincode value
            new (str):      New pincode value

        Returns:
            Response APDU
        """

        assert actual
        assert new
        data = actual.encode("utf-8") + new.encode("utf-8")
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_CHANGE_REF_DATA,
                                    p2=pwd,
                                    data=data)

    def send_reset_pw(self, value: str) -> RAPDU:
        """APDU Reset Retry Counter

        Args:
            value (str): Reset Code + new PW1 Pincode value

        Returns:
            Response APDU
        """

        assert value
        data = value.encode("utf-8")
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_RESET_RC,
                                    p1=0x02,
                                    p2=PassWord.PW1,
                                    data=data)


    ############### Key TEMPLATE interface ###############
    def set_template(self, key: DataObject, value: str):
        """APDU Set Key Template

        Args:
            key (DataObject): Tag identifying the key to process
            value (str):      String representing the OID of the key template

        Returns:
            Response APDU
        """

        data = binascii.unhexlify(value)
        return self.put_data(key, data)


    ############### Perform Security Operation ###############
    def set_uif(self, tag: DataObject, uif: bool):
        """APDU Set User Interaction Flag

        Args:
            tag (DataObject): Tag identifying the key to process
            uif (bool):       Enable/disable

        Returns:
            Response APDU
        """
        value = 1 if uif else 0
        data = value.to_bytes(2, "little")
        return self.put_data(tag, data)


    def manage_security_env(self, key: DataObject, ref: int) -> RAPDU:
        """APDU Manage Security Environment

        Args:
            key (DataObject): Tag identifying the key to process
            ref (int):        New key usage

        Returns:
            Response APDU
        """

        data = b"\x83\x01" + bytes.fromhex(f"{ref:02x}")
        return self.backend.exchange(cla=ClaType.CLA_APP,
                                    ins=InsType.INS_MSE,
                                    p1=0x41,
                                    p2=key,
                                    data=data)


    def get_challenge(self, size: int) -> RAPDU:
        """APDU Get Challenge

        Args:
            size (int): requested Challenge size

        Returns:
            Response APDU
        """

        cla = ClaType.CLA_APP
        ins = InsType.INS_GET_CHALLENGE
        Le = f"{size:02x}" if size < 255 else f"{size:04x}"
        data = bytes.fromhex(f"{cla:02x}{ins:02x}0000{Le}")
        try:
            rapdu = self.backend.exchange_raw(data)
        except ExceptionRAPDU as err:
            rapdu = RAPDU(err.status, err.data)

        # Receive long response
        return self.get_long_response(rapdu)


    def read_key(self, key: DataObject) -> RAPDU:
        """APDU Read Asymmetric Public Key

        Args:
            key (DataObject): Tag identifying the key to process

        Returns:
            Response APDU
        """

        return self.__key(0x81, key, False)


    def generate_key(self, key: DataObject, seed: bool = False) -> RAPDU:
        """APDU Generate Asymmetric Key pair

        Args:
            key (DataObject): Tag identifying the key to process
            seed (bool):      Generate a key in SEED mode

        Returns:
            Response APDU
        """

        return self.__key(0x80, key, seed)


    def authenticate(self, frame: bytes) -> RAPDU:
        """APDU Internal Authenticate

        Args:
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        return self.__pso(InsType.INS_INT_AUTHENTICATE, 0x0000, frame)

    def sign(self, frame: bytes) -> RAPDU:
        """APDU Sign

        Args:
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        return self.__pso(InsType.INS_PSO, 0x9e9a, frame)

    def encrypt(self, frame: bytes) -> RAPDU:
        """APDU Encipher

        Args:
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        return self.__pso(InsType.INS_PSO, 0x8680, frame)

    def decrypt(self, frame: bytes) -> RAPDU:
        """APDU Decipher

        Args:
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        return self.__pso(InsType.INS_PSO, 0x8086, frame)

    def decrypt_asym(self, frame: bytes, algo: PubkeyAlgo = PubkeyAlgo.RSA) -> RAPDU:
        """APDU Decipher with RSA

        Args:
            frame (bytes):     Data to process
            algo (PubkeyAlgo): Public Key Algorithm

        Returns:
            Response APDU
        """

        ins = InsType.INS_PSO
        size = len(frame)
        bFist: bool = True
        # Max input size is 254 B
        # Longer message uses Chaining mode APDU
        # Including a Padding Indicator for the 1st message
        # Including a 0x00 suffix at the end of the message
        while size > 0:
            if bFist:
                bFist = False
                # On the 1st message, add padding indicator
                if algo == PubkeyAlgo.RSA:
                    pad_ind = b"\x00"
                elif algo == PubkeyAlgo.ECDH:
                    pad_ind = b"\xa6"
                else:
                    rapdu = RAPDU(Errors.SW_WRONG_DATA, b"")
                    break
                max_len = 253
            else:
                pad_ind = b""
                max_len = 254

            if size > max_len:
                d_len = max_len
                cla = ClaType.CLA_APP_CHAIN
                m_frame = frame[:d_len]
            else:
                d_len = size # Remaining len
                cla = ClaType.CLA_APP
                m_frame = frame[:d_len] + b"\x00" # 0x00 suffix on the last message

            data = bytes.fromhex(f"{cla:02x}{ins:02x}8086{d_len + len(pad_ind):02x}") + pad_ind + m_frame
            try:
                rapdu = self.backend.exchange_raw(data)
                frame = frame[d_len:]
                size -= d_len
            except ExceptionRAPDU as err:
                rapdu = RAPDU(err.status, err.data)
                if rapdu.status != Errors.SW_OK:
                    break

        # Return result
        return rapdu


    ############### Responses ###############
    def get_long_response(self, rapdu: RAPDU) -> RAPDU:
        """Retrieve a synchronous Long Buffer Response

        Args:
            rapdu (RAPDU): Initial Response APDU from the command

        Returns:
            Response APDU
        """

        cla = ClaType.CLA_APP
        ins = InsType.INS_GET_RESPONSE
        rdata = rapdu.data

        # Receive long response
        while (rapdu.status & 0xFF00) == Errors.SW_CORRECT_LONG_RESPONSE:
            data = bytes.fromhex(f"{cla:02x}{ins:02x}0000{(rapdu.status & 0xFF):02x}")
            try:
                rapdu = self.backend.exchange_raw(data)
            except ExceptionRAPDU as err:
                if (err.status & 0xFF00) != Errors.SW_CORRECT_LONG_RESPONSE:
                    rapdu = RAPDU(err.status, err.data)
                    break

            rdata += rapdu.data
        return RAPDU(rapdu.status, rdata)


    def get_async_response(self) -> Optional[RAPDU]:
        """Asynchronous APDU response

        Returns:
            Response APDU
        """

        return self.backend.last_async_response


    ############### Internal functions ###############
    def __pso(self, ins: int, tag: int, frame: bytes) -> RAPDU:
        """APDU Perform Security Operation

        Args:
            ins (int):     Value for INS parameter in APDU
            tag (int):     Value for P1/P2 parameter in APDU
            frame (bytes): Data to process

        Returns:
            Response APDU
        """

        cla = ClaType.CLA_APP
        data = bytes.fromhex(f"{cla:02x}{ins:02x}{tag:04x}{len(frame):02x}") + frame + b"\x00"
        try:
            rapdu = self.backend.exchange_raw(data)
        except ExceptionRAPDU as err:
            rapdu = RAPDU(err.status, err.data)

        # Receive long response
        return self.get_long_response(rapdu)


    def __key(self, p1: int, key: DataObject, seed: bool = False) -> RAPDU:
        """APDU Asymmetric Key pair

        Args:
            p1 (int):         Value for P1 parameter in APDU
            key (DataObject): Tag identifying the key
            seed (bool):      Generate a key in SEED mode

        Returns:
            Response APDU
        """

        data = bytes.fromhex(f"{key:02x}00")
        p2 = 0x01 if seed else 0x00
        try:
            rapdu = self.backend.exchange(cla=ClaType.CLA_APP,
                                  ins=InsType.INS_GEN_ASYM_KEYPAIR,
                                  p1=p1,
                                  p2=p2,
                                  data=data)
        except ExceptionRAPDU as err:
            rapdu = RAPDU(err.status, err.data)

        # Receive long response
        return self.get_long_response(rapdu)
