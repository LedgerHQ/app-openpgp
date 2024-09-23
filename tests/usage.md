# How to use the Ragger test framework

This framework allows testing the application on the Speculos emulator or on a real device using LedgerComm or LedgerWallet

## Quickly get started with Ragger and Speculos

### Install ragger and dependencies

```shell
pip install --extra-index-url https://test.pypi.org/simple/ -r requirements.txt
sudo apt-get update && sudo apt-get install qemu-user-static
```

### Compile the application

The application to test must be compiled for all required devices.
You can use for this the container `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite`:

```shell
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
cd <your app repository>

docker run --user "$(id -u)":"$(id -g)" --rm -ti -v "$(realpath .):/app" --privileged -v "/dev/bus/usb:/dev/bus/usb" ledger-app-builder-lite:latest
make clean && make BOLOS_SDK=$<device>_SDK      # replace <device> with one of [NANOS, NANOX, NANOSP, STAX, FLEX]
exit
```

### Run a simple test using the Speculos emulator

You can use the following command to get your first experience with Ragger and Speculos

```shell
pytest -v --tb=short --device nanox --display
```

Or you can refer to the section `Available pytest options` to configure the options you want to use

### Run a simple test using a real device

The application to test must be loaded and started on a Ledger device plugged in USB.
You can use for this the container `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite`:

```shell
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
cd app-<appname>/

docker run --user "$(id -u)":"$(id -g)" --rm -ti -v "$(realpath .):/app" --privileged -v "/dev/bus/usb:/dev/bus/usb" ledger-app-builder-lite:latest
make clean && make BOLOS_SDK=$<device>_SDK load     # replace <device> with one of [NANOS, NANOX, NANOSP, STAX, FLEX]
exit
```

You can use the following command to get your first experience with Ragger and Ledgerwallet on a NANOX.
Make sure that the device is plugged, unlocked, and that the tested application is open.

```shell
pytest -v --tb=short --device nanox --backend ledgerwallet
```

Or you can refer to the section `Available pytest options` to configure the options you want to use

## Available pytest options

Standard useful pytest options

```shell
    -v              formats the test summary in a readable way
    -s              enable logs for successful tests, on Speculos it will enable app logs if compiled with DEBUG=1
    -k <testname>   only run the tests that contain <testname> in their names
    --tb=short      in case of errors, formats the test traceback in a readable way
```

Custom pytest options

```shell
    --full                      Run full tests
    --device <device>           Run the test on the specified device [nanos,nanox,nanosp,stax,flex,all]. This parameter is mandatory
    --backend <backend>         Run the tests against the backend [speculos, ledgercomm, ledgerwallet]. Speculos is the default
    --display                   On Speculos, enables the display of the app screen using QT
    --golden_run                Pn Speculos, screen comparison functions will save the current screen instead of comparing
    --log_apdu_file <filepath>  Log all apdu exchanges to the file in parameter. The previous file content is erased
    --seed=SEED                 Set a custom seed
```
