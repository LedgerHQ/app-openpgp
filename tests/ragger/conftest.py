import pytest

# from ragger.conftest import configuration

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of
#  ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest",)


##########################
# CONFIGURATION OVERRIDE #
##########################

BACKENDS = ["speculos"]


def pytest_addoption(parser):
    parser.addoption("--full", action="store_true", help="Run full tests")
    parser.addoption(
        "--allow-physical-device",
        action="store_true",
        help="Allow running the tests on a physical device: they reset its OpenPGP data and PINs",
    )


def pytest_configure(config):
    backend = config.getoption("backend", default="speculos")
    if backend != "speculos" and not config.getoption("allow_physical_device"):
        pytest.exit(
            f"The tests reset the OpenPGP data and PINs of the device: add --allow-physical-device to run them on '{backend}'",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )
