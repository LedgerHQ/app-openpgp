# SPDX-FileCopyrightText: 2026 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for the application state kept across restarts
"""

from pathlib import Path

import pytest
from application_client.app_def import DataObject, Errors, PassWord
from application_client.command_sender import CommandSender
from ledgered.devices import Device
from ragger.backend import BackendInterface, SpeculosBackend
from ragger.error import ExceptionRAPDU
from utils import KEY_TEMPLATES, check_pincode, generate_key, get_ECDSA_pub_key


def _restarted_app(device: Device, application: Path, nvram_args: list[str]) -> SpeculosBackend:
    return SpeculosBackend(application, device, args=nvram_args)


# In this test we check that a card reset by APDU survives an application restart
def test_reset_survives_restart(
    device: Device, backend: BackendInterface, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("requires Speculos to restart the application")
    application = backend._application.resolve()
    # Speculos keeps the NVRAM file in its working directory
    monkeypatch.chdir(tmp_path)

    with _restarted_app(device, application, ["--save-nvram"]) as app:
        client = CommandSender(app)
        check_pincode(client, PassWord.PW3)
        assert client.send_terminate().status == Errors.SW_OK
        assert client.send_activate().status == Errors.SW_OK
        check_pincode(client, PassWord.PW3)
        rapdu = client.set_template(DataObject.DO_SIG_ATTR, KEY_TEMPLATES["nistp256"])
        assert rapdu.status == Errors.SW_OK
        generate_key(client, DataObject.DO_SIG_KEY)
        pubkey = get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY)

    with _restarted_app(device, application, ["--load-nvram", "--save-nvram"]) as app:
        client = CommandSender(app)
        assert get_ECDSA_pub_key(client, DataObject.DO_SIG_KEY) == pubkey
        check_pincode(client, PassWord.PW3)
        assert client.send_terminate().status == Errors.SW_OK

    with _restarted_app(device, application, ["--load-nvram"]) as app:
        client = CommandSender(app)
        with pytest.raises(ExceptionRAPDU) as err:
            client.get_data(DataObject.DO_AID)
        assert err.value.status == Errors.SW_STATE_TERMINATED
