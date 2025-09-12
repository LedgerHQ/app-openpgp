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
make clean && make BOLOS_SDK=$<device>_SDK      # replace <device> with the device name
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
make clean && make BOLOS_SDK=$<device>_SDK load     # replace <device> with the device name
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
    --device={nanosp,nanox,flex,stax,apex_p,apex_m,all,all_nano,all_eink}
    --backend={speculos,ledgercomm,ledgerwallet}
    --no-nav              Disable the navigation
    --display             Pops up a Qt interface displaying either the emulated device (Speculos backend) or the expected screens and actions (physical backend)
    --golden_run          Do not compare the snapshots during testing, but instead save the live ones. Will only work with 'speculos' as the backend
    --pki_prod            Have Speculos accept prod PKI certificates instead of test
    --log_apdu_file=[LOG_APDU_FILE]
                          Log the APDU in a file. If no pattern provided, uses 'apdu_xxx.log'.
    --seed=SEED           Set a custom seed
    --setup={default}     Specify the setup fixture (e.g., 'prod_build')
```
