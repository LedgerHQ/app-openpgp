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

import binascii
from datetime import datetime, timezone
import pickle
from hashlib import sha1
from typing import Optional, Tuple
from dataclasses import dataclass
from Crypto.PublicKey.RSA import construct

from gpgapp.gpgcmd import DataObject, ErrorCodes, KeyTypes, PassWord, PubkeyAlgo  # type: ignore
from gpgapp.gpgcmd import KEY_OPERATIONS, KEY_TEMPLATES, USER_SALUTATION  # type: ignore

# pylint: disable=import-error
from ledgercomm import Transport  # type: ignore
# pylint: enable=import-error

APDU_MAX_SIZE: int = 0xFE
APDU_CHAINING_MODE: int = 0x10


class GPGCardExcpetion(Exception):
    """Exception handler.

    Attributes:
        code    (int): Error code
        message (str): Error message
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(self.message)


@dataclass
class KeyInfo:
    """Key description information"""

    attribute: bytes = b""
    fingerprint: bytes = b""
    ca_fingerprint: bytes = b""
    cert: str = ""
    date: datetime = datetime.min
    uif: int = 0
    key: bytes = b""

    def reset(self):
        """Reset the data to the initial value"""

        self.attribute      = b""
        self.fingerprint    = b""
        self.ca_fingerprint = b""
        self.cert           = ""
        self.date           = datetime.min
        self.uif            = 0
        self.key            = b""


@dataclass
class CardInfo:
    """Card description information"""

    #token info
    AID: str = ""
    ext_length: bytes = b""
    ext_capabilities: bytes = b""
    histo_bytes: bytes = b""
    PW_status: bytes = b""
    hw_features: int = 0

    #user info
    name: str = ""
    login: str = ""
    url: str = ""
    lang: str = ""
    salutation: str = ""

    #keys info
    rsa_pub_exp: int = 0
    digital_counter: int = 0

    sig: KeyInfo = KeyInfo()
    dec: KeyInfo = KeyInfo()
    aut: KeyInfo = KeyInfo()

    #private info
    private_01: bytes = b""
    private_02: bytes = b""
    private_03: bytes = b""
    private_04: bytes = b""


    def reset(self):
        """Reset the data to the initial value"""

        #token info
        self.AID              = ""
        self.ext_length       = b""
        self.ext_capabilities = b""
        self.histo_bytes      = b""
        self.PW_status        = b""

        #user info
        self.name             = ""
        self.login            = ""
        self.url              = ""
        self.lang             = ""
        self.salutation       = ""

        #keys info
        self.rsa_pub_exp      = 0
        self.digital_counter  = 0

        self.sig.reset()
        self.dec.reset()
        self.aut.reset()

        #private info
        self.private_01          = b""
        self.private_02          = b""
        self.private_03          = b""


class GPGCard() :
    def __init__(self) -> None:
        self.log: bool = False
        self.transport: Transport = None
        self.slot_current: bytes = b"\x00"
        self.slot_config: bytes = bytes(3)
        self.data: CardInfo = CardInfo()
        self.data.reset()

    def connect(self, device: str) -> None:
        """Connect to the selected Reader

        Args:
            device (str): Reader device name
        """

        if device == "speculos":
            self.transport = Transport("tcp", server="127.0.0.1", port=9999, debug=False)
        else:
            self.transport = Transport("hid")
        print("")


    def disconnect(self):
        """Connect from the selected Reader"""

        self.transport.close()


    ############### LOG interface ###############
    def log_apdu(self, log: bool) -> None:
        """Control APDU debugging display

        Args:
            log (bool): Activate or not the debug print
        """

        self.log = log

    def add_log(self, mode: str, data: bytes, sw: int = 0) -> None:
        """Print APDU content

        Args:
            mode (str):   Indicate the Send or Recv information
            data (bytes): APDU content
            sw (int):     Returned Status
        """

        if self.log:
            sw_code = f" ({sw:04x})" if mode == "recv" else ""
            print(f"{mode}:{sw_code} {''.join([f'{b:02x}' for b in data])}")


    ############### CARD interface ###############
    def select(self):
        """Send SELECT APDU command"""

        apdu = binascii.unhexlify(b"00A4040006D27600012401")
        return self._exchange(apdu)


    def activate(self):
        """Send ACTIVATE APDU command"""

        apdu = binascii.unhexlify(b"00440000")
        return self._exchange(apdu)


    def terminate(self):
        """Send TERMINATE APDU command"""

        apdu = binascii.unhexlify(b"00E60000")
        return self._exchange(apdu)


    def get_log(self):
        """Send GET_LOG APDU command"""

        apdu = binascii.unhexlify(b"00040000")
        return self._exchange(apdu)


    ############### API interfaces ###############
    def get_all(self) -> None:
        """Retrieve all Data Object values from the Card"""

        self.data.reset()
        data: Optional[bytes] = b""
        b_data: bytes = b""
        s_data: str = ""

        self.slot_current                     = self._get_data(DataObject.CMD_SLOT_CUR)
        self.slot_config                      = self._get_data(DataObject.CMD_SLOT_CFG)

        self.data.AID                         = self._get_data(DataObject.DO_AID).hex().upper()
        self.data.login                       = self._get_data(DataObject.DO_LOGIN).decode("utf-8")
        self.data.url                         = self._get_data(DataObject.DO_URL).decode("utf-8")
        self.data.histo_bytes                 = self._get_data(DataObject.DO_HIST)
        data                                  = self._get_data(DataObject.DO_GEN_FEATURES)
        if data:
            self.data.hw_features             = data[0]

        data                                  = self._get_data(DataObject.DO_CARDHOLDER_DATA)
        tags                                  = self._decode_tlv(data)
        if DataObject.DO_CARD_NAME in tags:
            self.data.name                    = tags[DataObject.DO_CARD_NAME].decode("utf-8")
        if DataObject.DO_CARD_SALUTATION in tags:
            s_data                            = tags[DataObject.DO_CARD_SALUTATION].decode("utf-8")
            for k,v in USER_SALUTATION.items():
                if v == s_data:
                    self.data.salutation = k
                    break

        if DataObject.DO_CARD_LANG in tags:
            self.data.lang                    = tags[DataObject.DO_CARD_LANG].decode("utf-8")

        data                                  = self._get_data(DataObject.DO_APP_DATA)
        tags                                  = self._decode_tlv(data)
        if DataObject.DO_EXT_LEN in tags:
            self.data.ext_length              = tags[DataObject.DO_EXT_LEN]
        if DataObject.DO_DISCRET_DATA in tags:
            b_data                            = tags[DataObject.DO_DISCRET_DATA]
            tags                              = self._decode_tlv(b_data)
            if DataObject.DO_EXT_CAP in tags:
                self.data.ext_capabilities    = tags[DataObject.DO_EXT_CAP]
            if DataObject.DO_SIG_ATTR in tags:
                self.data.sig.attribute       = tags[DataObject.DO_SIG_ATTR]
            if DataObject.DO_DEC_ATTR in tags:
                self.data.dec.attribute       = tags[DataObject.DO_DEC_ATTR]
            if DataObject.DO_AUT_ATTR in tags:
                self.data.aut.attribute       = tags[DataObject.DO_AUT_ATTR]
            if DataObject.DO_PW_STATUS in tags:
                self.data.PW_status           = tags[DataObject.DO_PW_STATUS]

            data                              = tags.get(DataObject.DO_FINGERPRINTS)
            if data:
                self.data.sig.fingerprint     = data[0:20]
                self.data.dec.fingerprint     = data[20:40]
                self.data.aut.fingerprint     = data[40:60]
            data                              = tags.get(DataObject.DO_CA_FINGERPRINTS)
            if data:
                self.data.sig.ca_fingerprint  = data[0:20]
                self.data.dec.ca_fingerprint  = data[20:40]
                self.data.aut.ca_fingerprint  = data[40:60]
            data                              = tags.get(DataObject.DO_KEY_DATES)
            if data:
                dates                         = tags[DataObject.DO_KEY_DATES]
                self._conv_date_from_bytes(KeyTypes.KEY_SIG, dates[0:4])
                self._conv_date_from_bytes(KeyTypes.KEY_DEC, dates[4:8])
                self._conv_date_from_bytes(KeyTypes.KEY_AUT, dates[8:12])

        data                                  = self._get_data(DataObject.CMD_RSA_EXP)
        self.data.rsa_pub_exp                 = self._get_int(data, 4)
        self.data.aut.cert                    = self._get_data(DataObject.DO_CERT).decode("utf-8")
        self.data.dec.cert                    = self._get_data(DataObject.DO_CERT, True).decode("utf-8")
        self.data.sig.cert                    = self._get_data(DataObject.DO_CERT, True).decode("utf-8")

        self.data.sig.uif                     = int(self._get_data(DataObject.DO_UIF_SIG)[0])
        self.data.dec.uif                     = int(self._get_data(DataObject.DO_UIF_DEC)[0])
        self.data.aut.uif                     = int(self._get_data(DataObject.DO_UIF_AUT)[0])

        data                                  = self._get_data(DataObject.DO_SEC_TEMPL)
        tags                                  = self._decode_tlv(data)
        if DataObject.DO_SIG_COUNT in tags:
            b_data                            = tags[DataObject.DO_SIG_COUNT]
            self.data.digital_counter         = self._get_int(b_data, 3)

        if self.data.ext_capabilities[0] & 0x08:
            self.data.private_01              = self._get_data(DataObject.DO_PRIVATE_01)
            self.data.private_02              = self._get_data(DataObject.DO_PRIVATE_02)
            self.data.private_03              = self._get_data(DataObject.DO_PRIVATE_03)
            self.data.private_04              = self._get_data(DataObject.DO_PRIVATE_04)

        self.data.sig.key                     = self._get_data(DataObject.DO_SIG_KEY)
        self.data.dec.key                     = self._get_data(DataObject.DO_DEC_KEY)
        self.data.aut.key                     = self._get_data(DataObject.DO_AUT_KEY)


    def backup(self, file_name: str) -> None:
        """Backup data to backup file

        Args:
            file_name (str): Backup filename
        """

        self.get_all()
        with open(file_name, mode="w+b") as f:
            pickle.dump(
                (self.data.AID, self.data.PW_status, self.data.rsa_pub_exp, self.data.digital_counter,
                self.data.private_01, self.data.private_02,
                self.data.private_03, self.data.private_04,
                self.data.name, self.data.login, self.data.salutation, self.data.url, self.data.lang,
                self.data.sig.key, self.data.sig.uif, self.data.sig.attribute, self.data.sig.date,
                self.data.sig.fingerprint, self.data.sig.ca_fingerprint, self.data.sig.cert,
                self.data.dec.key, self.data.dec.uif, self.data.dec.attribute, self.data.dec.date,
                self.data.dec.fingerprint, self.data.dec.ca_fingerprint, self.data.dec.cert,
                self.data.aut.key, self.data.aut.uif, self.data.aut.attribute, self.data.aut.date,
                self.data.aut.fingerprint, self.data.aut.ca_fingerprint, self.data.aut.cert),
                f, 2)


    def restore(self, file_name: str) -> None:
        """Restore data from backup file

        Args:
            file_name (str): Backup filename
        """

        with open(file_name, mode="r+b") as f:
            (self.data.AID, self.data.PW_status, self.data.rsa_pub_exp, self.data.digital_counter,
            self.data.private_01, self.data.private_02, self.data.private_03, self.data.private_04,
            self.data.name, self.data.login, self.data.salutation, self.data.url, self.data.lang,
            self.data.sig.key, self.data.sig.uif, self.data.sig.attribute, self.data.sig.date,
            self.data.sig.fingerprint, self.data.sig.ca_fingerprint, self.data.sig.cert,
            self.data.dec.key, self.data.dec.uif, self.data.dec.attribute, self.data.dec.date,
            self.data.dec.fingerprint, self.data.dec.ca_fingerprint, self.data.dec.cert,
            self.data.aut.key, self.data.aut.uif, self.data.aut.attribute, self.data.aut.date,
            self.data.aut.fingerprint, self.data.aut.ca_fingerprint, self.data.aut.cert) = pickle.load(f)

        self._put_data(DataObject.DO_AID,        bytes.fromhex(self.data.AID[20:28]))
        self._put_data(DataObject.DO_PW_STATUS,  self.data.PW_status)

        self._put_data(DataObject.DO_PRIVATE_01, self.data.private_01)
        self._put_data(DataObject.DO_PRIVATE_02, self.data.private_02)
        self._put_data(DataObject.DO_PRIVATE_03, self.data.private_03)
        self._put_data(DataObject.DO_PRIVATE_04, self.data.private_04)

        self._put_data(DataObject.DO_CARD_NAME,  self.data.name.encode("utf-8"))
        self._put_data(DataObject.DO_LOGIN,      self.data.login.encode("utf-8"))
        self._put_data(DataObject.DO_CARD_LANG,  self.data.lang.encode("utf-8"))
        self._put_data(DataObject.DO_URL,        self.data.url.encode("utf-8"))
        if len(self.data.salutation) == 0:
            self._put_data(DataObject.DO_CARD_SALUTATION, b'\x30')
        else:
            self._put_data(DataObject.DO_CARD_SALUTATION,
                           bytes.fromhex(USER_SALUTATION[self.data.salutation]))

        self._put_data(DataObject.DO_SIG_ATTR,   self.data.sig.attribute)
        self._put_data(DataObject.DO_DEC_ATTR,   self.data.dec.attribute)
        self._put_data(DataObject.DO_AUT_ATTR,   self.data.aut.attribute)

        self._put_data(DataObject.DO_UIF_SIG,    self.data.sig.uif.to_bytes(2, "little"))
        self._put_data(DataObject.DO_UIF_DEC,    self.data.dec.uif.to_bytes(2, "little"))
        self._put_data(DataObject.DO_UIF_AUT,    self.data.aut.uif.to_bytes(2, "little"))

        self._put_data(DataObject.DO_SIG_COUNT,  self.data.digital_counter.to_bytes(4, "big"))
        self._put_data(DataObject.CMD_RSA_EXP,   self.data.rsa_pub_exp.to_bytes(4, "little"))

        self._put_data(DataObject.DO_CERT, self.data.aut.cert.encode("utf-8"))
        self._put_data(DataObject.DO_CERT, self.data.dec.cert.encode("utf-8"))
        self._put_data(DataObject.DO_CERT, self.data.sig.cert.encode("utf-8"))

        self._put_data(DataObject.DO_CA_FINGERPRINT_WR_SIG, self.data.sig.ca_fingerprint)
        self._put_data(DataObject.DO_FINGERPRINT_WR_SIG, self.data.sig.fingerprint)
        date = str(self.data.sig.date)
        dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        bdate = int(dt.timestamp()).to_bytes(4, "big")
        self._put_data(DataObject.DO_DATES_WR_SIG, bdate)
        self._put_data(DataObject.DO_SIG_KEY, self.data.sig.key)

        self._put_data(DataObject.DO_CA_FINGERPRINT_WR_DEC, self.data.dec.ca_fingerprint)
        self._put_data(DataObject.DO_FINGERPRINT_WR_DEC, self.data.dec.fingerprint)
        date = str(self.data.dec.date)
        dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        bdate = int(dt.timestamp()).to_bytes(4, "big")
        self._put_data(DataObject.DO_DATES_WR_DEC, bdate)
        self._put_data(DataObject.DO_DEC_KEY, self.data.dec.key)

        self._put_data(DataObject.DO_CA_FINGERPRINT_WR_AUT, self.data.aut.ca_fingerprint)
        self._put_data(DataObject.DO_FINGERPRINT_WR_AUT, self.data.aut.fingerprint)
        date = str(self.data.aut.date)
        dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        bdate = int(dt.timestamp()).to_bytes(4, "big")
        self._put_data(DataObject.DO_DATES_WR_AUT, bdate)
        self._put_data(DataObject.DO_AUT_KEY, self.data.aut.key)


    def export_pub_key(self, pubkey: dict, file_name: str) -> None:
        """Export a Public to file

        Args:
            pubkey (dict): Public key parameters
            file_name (str): Backup filename
        """

        modulus = bytearray.fromhex(pubkey["Modulus"])
        exponent = bytearray.fromhex(pubkey["Pub Exp"][2:])
        key = construct((int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')))
        public_key = key.publickey().export_key()
        with open(file_name, mode="wb") as f:
            f.write(public_key)


    def seed_key(self) -> None:
        """Regenerate keys, based on seed mode"""

        apdu = binascii.unhexlify(b"0047800102B600")
        self._exchange(apdu)
        apdu = binascii.unhexlify(b"0047800102B800")
        self._exchange(apdu)
        apdu = binascii.unhexlify(b"0047800102A400")
        self._exchange(apdu)


    ############### Information decoding ###############
    def decode_AID(self) -> dict:
        """Decode Application IDentity information"""

        return  {
            "AID": f"{self.data.AID}",
            "RID": f"{self.data.AID[0:10]}",
            "Application": f"{self.data.AID[10:12]}",
            "Version": f"{int(self.data.AID[12:14]):d}.{int(self.data.AID[14:16]):d}",
            "Manufacturer": f"{self.data.AID[16:20]}",
            "Serial": f"{self.data.AID[20:28]}"
        }

    def decode_histo(self) -> dict:
        """Decode Historical Bytes information"""

        return {
            "historical bytes": self.data.histo_bytes.hex()
        }

    def decode_extlength(self) -> dict:
        """Decode Extended Length information"""

        d = {
            "Command": "N/A",
            "Response": "N/A",
        }

        if self.data.ext_length:
            d["Command"] = f"{self._get_int(self.data.ext_length, offset=2):d}"
            d["Response"] = f"{self._get_int(self.data.ext_length, offset=6):d}"
        return d

    def decode_ext_capabilities(self) -> dict:
        """Decode Extended Capabilities information"""

        d = {}
        b1 = self.data.ext_capabilities[0]
        if b1 & 0x80:
            if self.data.ext_capabilities[1] == 1:
                d["Secure Messaging"] = "✓: AES 128 bits"
            elif self.data.ext_capabilities[1] == 2:
                d["Secure Messaging"] = "✓: AES 256 bits"
            else:
                d["Secure Messaging"] = "✓: ?? bits"
        else:
            d["Secure Messaging"] = "✗"

        if b1 & 0x40:
            max_val = self._get_int(self.data.ext_capabilities, offset=2)
            d["Get Challenge"] = f"✓ (Max length: {max_val:d})"
        else:
            d["Get Challenge"] = "✗"

        if b1 & 0x20:
            d["Key import"] = "✓"
        else:
            d["Key import"] = "✗"

        if b1 & 0x10:
            d["PW status"] = "Changeable"
        else:
            d["PW status"] = "Fixed"

        if b1 & 0x08:
            d["Private DOs"] = "✓"
        else:
            d["Private DOs"] = "✗"

        if b1 & 0x04:
            d["Algo attributes"] = "Changeable"
        else:
            d["Algo attributes"] = "Fixed"

        if b1 & 0x02:
            d["PSO:DEC AES"] = "✓"
        else:
            d["PSO:DEC AES"] = "✗"

        if b1 & 0x01:
            d["Key Derived Format"] = "✓"
        else:
            d["Key Derived Format"] = "✗"

        max_val = self._get_int(self.data.ext_capabilities, offset=4)
        d["Max Cert len"] = f"{max_val:d}"
        max_val = self._get_int(self.data.ext_capabilities, offset=6)
        d["Max Special DO"] = f"{max_val:d}"

        if self.data.ext_capabilities[8]:
            d["PIN 2 format"] = "✓"
        else:
            d["PIN 2 format"] = "✗"
        if self.data.ext_capabilities[9]:
            d["MSE"] = "✓"
        else:
            d["MSE"] = "✗"
        return d

    def decode_pws(self) -> dict:
        """Decode Password information"""

        if self.data.PW_status[0] == 0:
            validity = "Only 1 PSO:CDS"
        elif self.data.PW_status[0] == 1:
            validity = "Several PSO:CDS"
        else:
            validity = f"unknown ({self.data.PW_status[0]:d})"

        cfg = {
            "PW1": {"format": 1, "counter": 4},
            "Reset Counter": {"format": 2, "counter": 5},
            "PW3": {"format": 3, "counter": 6},
        }

        d = {}
        for name, pw in cfg.items():
            if self.data.PW_status[pw["format"]] & 0x80:
                fmt = "Format-2"
            else:
                fmt = "UTF-8"
            pwlen = self.data.PW_status[pw["format"]] & 0x7f
            counter = self.data.PW_status[pw['counter']]
            d[name] = f"{fmt} ({pwlen:d} bytes), Error Counter={counter:d}"
            if name == "PW1":
                d[name] += f", Validity={validity}"
        return d

    def decode_hardware(self) -> dict:
        """Decode Hardware features information"""

        d = {}
        d["Display"] = "✓" if self.data.hw_features & 0x80 else "✗"
        d["Biometric sensor"] = "✓" if self.data.hw_features & 0x40 else "✗"
        d["Button/Keypad"] = "✓" if self.data.hw_features & 0x20 else "✗"
        d["LED"] = "✓" if self.data.hw_features & 0x10 else "✗"
        d["Loudspeaker"] = "✓" if self.data.hw_features & 0x08 else "✗"
        d["Microphone"] = "✓" if self.data.hw_features & 0x04 else "✗"
        d["Touchscreen"] = "✓" if self.data.hw_features & 0x02 else "✗"
        d["Battery"] = "✓" if self.data.hw_features & 0x01 else "✗"
        return d


    ############### SLOT interface ###############
    def select_slot(self, slot: int) -> None:
        """Select the key slot

        Args:
            slot (int): slot id to select (0 to 3)
        """

        self.slot_current = slot.to_bytes(1, "big")
        self._put_data(DataObject.CMD_SLOT_CUR, self.slot_current)

    def decode_slot(self) -> dict:
        """Decode Slots information

        Returns:
            Slots configuration dictionary
        """

        d = {}
        d["Number of Slots"] = str(self.slot_config[0])
        d["Default Slot"] = str(self.slot_config[1] + 1)
        d["Selection by APDU"] = "✓" if self.slot_config[2] & 0x01 else "✗"
        d["Selection by screen"] = "✓" if self.slot_config[2] & 0x02 else "✗"
        d["Current"] = str(int.from_bytes(self.slot_current, "big") + 1)
        return d


    ############### USER interface ###############
    def set_serial(self, serial: str) -> None:
        """Set the Card serial number

        Args:
            serial (str): New serial number
        """

        if not self.data.AID:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, "Invalid AID!")

        self.data.AID = self.data.AID[0:20] + serial
        self._put_data(DataObject.DO_AID, bytes.fromhex(serial))


    def set_name(self, name: str) -> None:
        """Set the Card User name

        Args:
            name (str): New name
        """

        self.data.name = name
        self._put_data(DataObject.DO_CARD_NAME, name.encode("utf-8"))

    def get_name(self) -> str:
        """Get the Card User name"""

        return self.data.name


    def set_login(self, login: str) -> None:
        """Set the Card User login

        Args:
            login (str): New login
        """

        self.data.login = login
        self._put_data(DataObject.DO_LOGIN, login.encode("utf-8"))

    def get_login(self) -> str:
        """Get the Card User login"""

        return self.data.login


    def set_url(self, url: str) -> None:
        """Set the Card User URL

        Args:
            url (str): New URL
        """

        self.data.url = url
        self._put_data(DataObject.DO_URL, url.encode("utf-8"))

    def get_url(self) -> str:
        """Get the Card User URL"""

        return self.data.url


    def set_lang(self, lang: str) -> None:
        """Set the Card User language

        Args:
            lang (str): New language
        """

        self.data.lang = lang
        self._put_data(DataObject.DO_CARD_LANG, lang.encode("utf-8"))

    def get_lang(self) -> str:
        """Get the Card User language"""

        return self.data.lang


    def set_salutation(self, salutation: str) -> None:
        """Set the Card User salutation

        Args:
            salutation (str): New salutation
        """

        try:
            salutation_str = USER_SALUTATION[salutation].encode("utf-8")
        except KeyError as err:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL,
                                   f"Invalid salutation value ({salutation})!") from err

        self.data.salutation = salutation
        self._put_data(DataObject.DO_CARD_SALUTATION, salutation_str)

    def get_salutation(self) -> str:
        """Get the Card User salutation"""

        return self.data.salutation


    ############### PASSWORD interface ###############
    def verify_pin(self, pw: PassWord, value: str, pinpad: bool = False) -> bool:
        """Verify the password

        Args:
              pw (PassWord): Password type, corresponding to User, Admin
              value (str)  : Password value
              pinpad (bool): Indicate to use pinpad

        Return:
            Success / KO boolean
        """

        value = value if value else ""
        if pinpad:
            apdu = bytes.fromhex(f"EF2000{pw:02x}00")
        else:
            apdu = bytes.fromhex(f"002000{pw:02x}{len(value):02x}") + value.encode("utf-8")
        _, sw = self._exchange(apdu)
        return sw == ErrorCodes.ERR_SUCCESS


    def change_pin(self, pw: PassWord, cur_value: str, new_value: str) -> bool:
        """Update the password

        Args:
            pw (PassWord):   Password type, corresponding to User, Admin
            cur_value (str): Current password value
            new_value (str): New password value

        Return:
            Success / KO boolean
        """

        lc = len(cur_value) + len(new_value)
        apdu = bytes.fromhex(f"002400{pw:02x}{lc:02x}") + \
                cur_value.encode("utf-8") + \
                new_value.encode("utf-8")
        _, sw = self._exchange(apdu)
        return sw == ErrorCodes.ERR_SUCCESS


    def set_RC(self, value: str) -> bool:
        """Set the User Password Resetting Code

        Args:
            value (str): Resetting Code value

        Return:
            Success / KO boolean
        """

        b_value = value.encode("utf-8")
        return self._put_data(DataObject.DO_RESET_CODE, b_value) == ErrorCodes.ERR_SUCCESS


    def reset_PW1(self, RC: str, value: str) -> bool:
        """Reset the User Password with Resetting Code

        Args:
            RC (str):    Resetting Code value
            value (str): User Password value

        Return:
            Success / KO boolean
        """

        p1 = 2 if len(RC) == 0 else 0
        lc = len(RC) + len(value)
        apdu = bytes.fromhex(f"002C{p1:02x}81{lc:02x}") + RC.encode("utf-8") + value.encode("utf-8")
        _, sw = self._exchange(apdu)
        return sw == ErrorCodes.ERR_SUCCESS


    ############### KEYS interface ###############
    def decode_key_uif(self, key: str) -> str:
        """Decode the selected key User Interaction Flag

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            UIF status for the selected key
        """

        uif = self._get_key_object(key).uif
        if uif == 0:
            return "✗"
        if uif == 1:
            return "✓"
        if uif == 2:
            return "✓ (Permanent)"
        return ""

    def get_key_date(self, key: str) -> str:
        """Get key Creation Date

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            Key Creation Date
        """

        return str(self._get_key_object(key).date)

    def get_sig_count(self) -> int:
        """Get Digital Signatures Count

        Return:
            Number of Digital Signatures Count
        """

        return self.data.digital_counter

    def get_rsa_pub_exp(self) -> int:
        """Get RSA Public Exponent

        Return:
            RSA Public Exponent
        """

        return self.data.rsa_pub_exp

    def get_key_cert(self, key: str) -> str:
        """Get key Certificate

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            Key Certificate
        """

        return self._get_key_object(key).cert

    def set_template(self, key: str, template: str) -> None:
        """Set key Template

        Args:
            key (str):      Key type (SIG, DC, AUT)
            template (str): Key template
        """

        if template not in KEY_TEMPLATES:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, f"Invalid template: {template}")

        data = binascii.unhexlify(KEY_TEMPLATES[template])
        if key == KeyTypes.KEY_SIG:
            self._put_data(DataObject.DO_SIG_ATTR, data)
        elif key == KeyTypes.KEY_DEC:
            self._put_data(DataObject.DO_DEC_ATTR, data)
        elif key == KeyTypes.KEY_AUT:
            self._put_data(DataObject.DO_AUT_ATTR, data)

    def set_key_fingerprint(self, key: str, data: bytes) -> None:
        """Set key fingerprint

        Args:
            key (str):    Key type (SIG, DC, AUT)
            data (bytes): Fingerprint
        """

        if key == KeyTypes.KEY_SIG:
            self.data.sig.fingerprint = data
            self._put_data(DataObject.DO_FINGERPRINT_WR_SIG, data)
        elif key == KeyTypes.KEY_AUT:
            self.data.aut.fingerprint = data
            self._put_data(DataObject.DO_FINGERPRINT_WR_AUT, data)
        elif key == KeyTypes.KEY_DEC:
            self.data.dec.fingerprint = data
            self._put_data(DataObject.DO_FINGERPRINT_WR_DEC, data)

    def get_key_fingerprint(self, key: str) -> str:
        """Get key fingerprint

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            Key Fingerprint
        """

        fingerprint = self._get_key_object(key).fingerprint
        sdata = binascii.hexlify(fingerprint).decode("ascii")
        return sdata if sdata != "0"*40 else "N/A"

    def get_key_CA_fingerprint(self, key: str) -> str:
        """Get key CA fingerprint

        Args:
              ey (str): Key type (SIG, DC, AUT)

        Return:
            Key CA Fingerprint
        """

        fingerprint = self._get_key_object(key).ca_fingerprint
        sdata = binascii.hexlify(fingerprint).decode("ascii")
        return sdata if sdata != "0"*40 else "N/A"

    def decode_attributes(self, key: str) -> str:
        """Decode key attribute

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            String with attributes and size
        """

        attributes = self._get_key_object(key).attribute
        if not attributes or len(attributes) == 0:
            return ""

        if attributes[0] == PubkeyAlgo.RSA:
            if attributes[5] == 0:
                fmt = "standard (e, p, q)"
            elif attributes[5] == 1:
                fmt = "standard with modulus (n)"
            elif attributes[5] == 2:
                fmt = "crt (Chinese Remainder Theorem)"
            elif attributes[5] == 3:
                fmt = "crt (Chinese Remainder Theorem) with modulus (n)"
            ret = f"RSA-{self._get_int(attributes, offset=1)}"
            ret += f", Format: {fmt}"
            ret += f", Exponent size: {self._get_int(attributes, offset=3)}"
            return ret

        if attributes[0] == PubkeyAlgo.ECDSA:
            return "ECDSA"
        if attributes[0] == PubkeyAlgo.ECDH:
            return "ECDH"
        if attributes[0] == PubkeyAlgo.EDDSA:
            return "EDDSA"
        return ""


    def decode_key(self, key: str) -> dict:
        """Get key parameters

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            Key information dictionary
        """

        d = {}
        offset: int = 0
        key_data = self._get_key_object(key).key

        d["OS Target ID"] = f"0x{int.from_bytes(key_data[offset:offset + 4], 'big'):04x}"
        offset += 4
        d["API Level"] = str(int.from_bytes(key_data[offset:offset + 4], 'big'))
        offset += 4
        size = int.from_bytes(key_data[offset:offset + 4], 'big')
        # Should be Public key here from doc, but only Public Exp from the code
        d["Public exp size"] = str(size)
        offset += 4
        d["Public exp"] = f"0x{int.from_bytes(key_data[offset:offset + 4], 'big'):06x}"
        offset += size
        size = int.from_bytes(key_data[offset:offset + 4], 'big')
        d["Private key size"] = str(size)
        # offset += 4
        # d["Private key encrypted"] = key_data[offset:offset + size].hex()
        return d

    def asymmetric_key(self, key: str, action: str) -> dict:
        """Asymmetric key operation

        Args:
            key (str):    Key type (SIG, DC, AUT)
            action (str): Generate or Read

        Return:
            Public key information:
                RSA (Encrypt or Sign): {
                    "id":     (int) 1,
                    "Modulus":  (int)
                    "Pub Exp"   (int)
                }
                ECDSA for PSO:CDS and INT-AUT: {
                    "id":     (int) 19,
                    "OID":    (bytes)
                }
                ECDH for PSO:DEC {
                    "id":     (int) 18,
                    "OID":    (bytes)
                }
        """

        if action not in KEY_OPERATIONS:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, f"Invalid Key operation: {action}")

        op = KEY_OPERATIONS[action]
        attributes = None
        b_key: int = 0
        if key == KeyTypes.KEY_SIG:
            attributes = self.data.sig.attribute
            b_key = DataObject.DO_SIG_KEY
        elif key == KeyTypes.KEY_DEC:
            attributes = self.data.dec.attribute
            b_key = DataObject.DO_DEC_KEY
        elif key == KeyTypes.KEY_AUT:
            attributes = self.data.aut.attribute
            b_key = DataObject.DO_AUT_KEY
        if not attributes or len(attributes) == 0:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, "Invalid key attribute!")

        if attributes[0] not in set(iter(PubkeyAlgo)):
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, "Invalid key ID in attribute!")

        d = {}
        tags = self._asym_key_pair(op, b_key)

        if attributes[0] == PubkeyAlgo.RSA:
            d["ID"] = f"RSA-{self._get_int(attributes, offset=1)}"
            d["Modulus"] = tags[0x81].hex()
            d["Pub Exp"] = f"0x{tags[0x82].hex()}"
        else:
            if attributes[0] == PubkeyAlgo.ECDSA:
                d["ID"] = "ECDSA"
            if attributes[0] == PubkeyAlgo.ECDH:
                d["ID"] = "ECDH"
            if attributes[0] == PubkeyAlgo.EDDSA:
                d["ID"] = "EDDSA"
            d["oid"] = tags[0x86].hex()

        if attributes[0] == PubkeyAlgo.RSA:
            if action == "Generate":
                # Set the generation date
                self._set_key_date_now(key)

            # Get the generation date
            date = self.get_key_date(key)
            dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            kdate = int(dt.timestamp())
            d["Creation date"] = date

            # Compute the fingerprint https://www.rfc-editor.org/rfc/rfc4880#section-12.2
            modulus: bytes = bytes.fromhex(d["Modulus"])
            ksize: int = self._get_int(attributes, offset=1)
            size: int = int(ksize / 8) + 0x0D # len(header + tag + pub exp)

            header: bytes = bytes.fromhex(f"99{size:04x}04{kdate:08x}01{ksize:04x}")
            footer: bytes = bytes.fromhex("0011010001")
            data: bytes = header + modulus + footer

            _hash = sha1()
            _hash.update(data)
            result: bytes = _hash.digest()
            d["Fingerprint"] = result.hex()
            if action == "Generate":
                self.set_key_fingerprint(key, result)

        return d


    # ===============================================================
    # Internal functions
    # ===============================================================

    def _get_key_object(self, key: str) -> KeyInfo:
        """Get KeyInfo data class object

        Args:
            key (str): Key type (SIG, DC, AUT)

        Return:
            KeyInfo Object
        """

        if key == KeyTypes.KEY_SIG:
            return self.data.sig
        if key == KeyTypes.KEY_AUT:
            return self.data.aut
        if key == KeyTypes.KEY_DEC:
            return self.data.dec

        raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, f"Invalid key type {key}!")


    def _get_data(self, tag: int, bnext: bool = False) -> bytes:
        """Send APDU command to GET a specific Data Object

        Args:
            tag (int): Data Object tag

        Return:
            Data Object bytes
        """

        ins = 0xCC if bnext else 0xCA
        apdu = bytes.fromhex(f"00{ins:02x}{tag:04x}00")
        resp, _ = self._exchange(apdu)
        return resp


    def _put_data(self, tag: int, data: bytes) -> int:
        """Send APDU command to PUT a Data Object value

        Args:
            tag (int):    Data Object tag
            data (bytes): Data Object bytes

        Return:
            Status Word
        """

        apdu = bytes.fromhex(f"00DA{tag:04x}")
        _, sw = self._exchange(apdu, data)
        return sw


    def _asym_key_pair(self, op: int, key: int) -> dict:
        """Asymmetric key pair operation

        Args:
            op (int):  Operation to execute
            key (int): Key type

        Return:
            Public key decoded data bytes
        """

        apdu = bytes.fromhex(f"0047{op:02x}0002{key:02x}00")
        resp, sw = self._exchange(apdu)
        if sw != ErrorCodes.ERR_SUCCESS:
            raise GPGCardExcpetion(ErrorCodes.ERR_INTERNAL, "Key operation error!")
        tags = self._decode_tlv(resp)
        return self._decode_tlv(tags[DataObject.DO_PUB_KEY])


    def _conv_date_from_bytes(self, key: str, data: bytes) -> None:
        """Convert date from bytes to datetime local dataclass

        Args:
            key (str):    Key type (SIG, DC, AUT)
            data (bytes): Date value
        """

        idate = int.from_bytes(data, "big")
        self._get_key_object(key).date = datetime.utcfromtimestamp(idate)


    def _set_key_date_now(self, key: str) -> None:
        """Set Key creation date

        Args:
            key (str):    Key type (SIG, DC, AUT)
        """

        dt = datetime.utcnow().replace(microsecond=0)
        bdate = int(dt.timestamp()).to_bytes(4, "big")
        tag: Optional[DataObject] = None
        if key == KeyTypes.KEY_SIG:
            self.data.sig.date = dt
            tag = DataObject.DO_DATES_WR_SIG
        elif key == KeyTypes.KEY_AUT:
            self.data.aut.date = dt
            tag = DataObject.DO_DATES_WR_AUT
        elif key == KeyTypes.KEY_DEC:
            self.data.dec.date = dt
            tag = DataObject.DO_DATES_WR_DEC
        if tag:
            self._put_data(tag, bdate)


    def _decode_tlv(self, tlv: bytes) -> dict:
        """Decode TLV fields

        Args:
            tlv (bytes): Input data bytes to parse

        Returns:
            dict {t: v, t:v, ...}
        """

        tags = {}
        while len(tlv):
            o = 0
            l = 0
            if (tlv[0] & 0x1F) == 0x1F:
                t = self._get_int(tlv)
                o = 2
            else:
                t = tlv[0]
                o = 1
            l = tlv[o]
            if l & 0x80 :
                if (l & 0x7f) == 1:
                    l = tlv[o + 1]
                    o += 2
                if (l & 0x7f) == 2:
                    l = self._get_int(tlv, offset=o + 1)
                    o += 3
            else:
                o += 1
            v = tlv[o:o + l]
            tags[t] = v
            tlv = tlv[o + l:]
        return tags


    def _transmit(self, data: bytes, long_resp: bool = False) -> Tuple[bytes, int, int]:
        """Transmit data, and get the response

        Args:
            data (bytes): APDU to transmit
            long_resp (bool): Indicate if long response is expected

        Return:
            Response data bytes and the Status Word
        """

        self.add_log("send", data)
        sw, resp = self.transport.exchange_raw(data)
        sw1 = (sw >> 8) & 0xFF
        sw2 = sw & 0xFF
        self.add_log("recv", resp, sw)
        if sw != ErrorCodes.ERR_SUCCESS and not long_resp:
            raise GPGCardExcpetion(sw, "")
        return resp, sw1, sw2


    def _exchange(self, apdu: bytes, data: bytes = b"") -> Tuple[bytes, int]:
        """Exchange APDU, and get the response

        Args:
            apdu (bytes): APDU content
            data (bytes): Data to transmit

        Return:
            Response data bytes and the Status Word
        """

        #send
        apdux: bytes = b""
        resp: bytes = b""
        if len(data) > 0:
            if len(data) > APDU_MAX_SIZE:
                cla: bytes = (apdu[0] | APDU_CHAINING_MODE).to_bytes(1, "big")
                m_apdu: bytes = cla + apdu[1:5] + APDU_MAX_SIZE.to_bytes(1, "big")
            while len(data) > APDU_MAX_SIZE:
                apdux = m_apdu + data[0:APDU_MAX_SIZE]
                self._transmit(apdux)
                data = data[APDU_MAX_SIZE:]
            apdu += len(data).to_bytes(1, "big") + data

        resp, sw1, sw2 = self._transmit(apdu, True)

        #receive
        while sw1 == ErrorCodes.ERR_SW1_VALID:
            apdux = bytes.fromhex(f"00c00000{sw2:02x}")
            resp2, sw1, sw2 = self._transmit(apdux, True)
            resp += resp2
        sw = (sw1 << 8) | sw2
        return bytes(resp), sw


    def _get_int(self, buffer: bytes, size: int = 2, offset: int = 0) -> int:
        """Exchange APDU, and get the response

        Args:
            buffer (bytes): data content
            offset (int): Offset of MSB

        Return:
            Converted int
        """

        if size == 2:
            return (buffer[offset] << 8) | buffer[offset + 1]
        if size == 3:
            return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2]
        if size == 4:
            return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | \
                    (buffer[offset + 2] << 8) | buffer[offset + 3]
        return 0
