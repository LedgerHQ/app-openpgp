# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the response parsing part.
"""
from typing import Tuple


def _pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    """Parse buffer and returns: remainder, data[size]"""

    return buffer[size:], buffer[0:size]


def unpack_info_response(response: bytes) -> Tuple[str, str]:
    """Unpack response for AID:
            RID (5)
            Application (1)
            Version (2)
            Manufacturer (2)
            Serial (4)
            RFU (2)
    """

    assert len(response) == 16
    response, rid = _pop_sized_buf_from_buffer(response, 5)
    response, app = _pop_sized_buf_from_buffer(response, 1)
    response, version = _pop_sized_buf_from_buffer(response, 2)
    response, manuf = _pop_sized_buf_from_buffer(response, 2)
    response, serial = _pop_sized_buf_from_buffer(response, 4)
    assert rid.hex() == "d276000124"
    assert app.hex() == "01"
    assert manuf.hex() == "2c97"

    return (version.hex(), serial.hex())
