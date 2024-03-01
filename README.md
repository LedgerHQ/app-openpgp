# GnuPG application

[![Ensure compliance with Ledger guidelines](https://github.com/LedgerHQ/app-openpgp/actions/workflows/guidelines_enforcer.yml/badge.svg)](https://github.com/LedgerHQ/app-openpgp/actions/workflows/guidelines_enforcer.yml)

[![Build and run functional tests using ragger through reusable workflow](https://github.com/LedgerHQ/app-openpgp/actions/workflows/build_and_functional_tests.yml/badge.svg?branch=master)](https://github.com/LedgerHQ/app-openpgp/actions/workflows/build_and_functional_tests.yml)

GnuPG application for Ledger devices

This application implements "The OpenPGP card" specification revision 3.3.
This specification is available in *doc* directory and at <https://g10code.com/p-card.html>.

The application supports:

- RSA with key up to 3072 bits
- ECDSA with secp256k1
- EDDSA with Ed25519 curve
- ECDH with secp256k1 and curve25519 curves

## Installation and Usage

See the full doc in [rst](doc/user/app-openpgp.rst), or in [pdf](<https://github.com/LedgerHQ/app-openpgp/blob/master/doc/user/app-openpgp.pdf>)

## Add-on

The GnuPG application implements the following addon:

- Serial modification
- On screen reset
- 3 independent key slots (except for Nanos, where we have only a single slot)
- Seeded key generation

Technical specification is available in [rst](doc/developer/gpgcard-addon.rst), or in [pdf](<https://github.com/LedgerHQ/app-openpgp/blob/master/doc/developer/gpgcard-addon.pdf>)

### Key slot

The OpenPGP card specification indicates:

- 3 asymmetric keys:
  - Signature,
  - Decryption
  - Authentication
- 1 symmetric key

The application allows you to store 3 different key sets, named slot. Each slot contains the above 4 keys.
You can choose the active slot on the main screen.
When installed the default slot is "1". You can change it in settings.

### Seeded key generation

A seeded mode is implemented in order to restore private keys on a new token.
In this mode, key material is generated from the global token seed.

Also, a backup/restore mechanism is provided. Please report to the [Documentation](#documentation).

> Warning: Without such configuration, an OS or App update will cause your private key to be lost!"

The following is a repeatable process that will generate the same keys and fingerprints
(even with different card serial numbers).

1. Reset the OpenPGP App
1. Set Key Templates from the OpenPGP App menu, if needed
1. On computer, use `gpg` to edit the key with a fixed timestamp:

```shell
gpg --faked-system-time 19990101T000000! --card-edit # note the exclamation mark to keep the time fixed
gpg> admin
gpg> generate
... # complete the wizard
```

While doing this, ensure that you use the same `--faked-system-time` and "Real Name" and "Email"
during the generation wizard to reproduce the same keys each time.

### On screen reset

The application can be reset as if it was fresh installed. In settings, choose reset and confirm.

## Quick start guide

### With VSCode

You can quickly setup a convenient environment to build and test your application by using
[Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools)
which leverages the [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools)
docker image.

It will allow you, whether you are developing on macOS, Windows or Linux,
to quickly **build** your apps, **test** them on **Speculos** and **load** them on any supported device.

- Install and run [Docker](https://www.docker.com/products/docker-desktop/).
- Make sure you have an X11 server running:
  - On Ubuntu Linux, it should be running by default.
  - On macOS, install and launch [XQuartz](https://www.xquartz.org/)
    (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  - On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/)
    (make sure to configure it to disable access control).
- Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
- Open a terminal and clone `app-openpgp` with `git clone git@github.com:LedgerHQ/app-openpgp.git`.
- Open the `app-openpgp` folder with VSCode.
- Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b`
  (`command + shift + b` on a Mac) to conveniently execute actions:
  - Build the app for the device model of your choice with `Build`.
  - Test your binary on [Speculos](https://github.com/LedgerHQ/speculos) with `Run with Speculos`.
  - You can also run functional tests, load the app on a physical device, and more.

> The terminal tab of VSCode will show you what commands the extension runs behind the scene.

### With a terminal

The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools)
docker image contains all the required tools and libraries to **build**, **test** and **load** an application.

You can download it from the ghcr.io docker repository:

```shell
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

You can then enter this development environment by executing the following command
from the directory of the application `git` repository:

#### Linux (Ubuntu)

```shell
sudo docker run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

#### macOS

```shell
sudo docker run  --rm -ti --user "$(id -u):$(id -g)" --privileged -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

#### Windows (with PowerShell)

```shell
docker run --rm -ti --privileged -v "$(Get-Location):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

The application's code will be available from inside the docker container,
you can proceed to the following compilation steps to build your app.

## Compilation and load

To easily setup a development environment for compilation and loading on a physical device, you can use the [VSCode integration](#with-vscode)
whether you are on Linux, macOS or Windows.

If you prefer using a terminal to perform the steps manually, you can use the guide below.

### Compilation

Setup a compilation environment by following the [shell with docker approach](#with-a-terminal).

From inside the container, use the following command to build the app:

```shell
make DEBUG=1  # compile optionally with PRINTF
```

You can choose which device to compile and load for by setting the `BOLOS_SDK` environment variable to the following values:

- `BOLOS_SDK=$NANOS_SDK`
- `BOLOS_SDK=$NANOX_SDK`
- `BOLOS_SDK=$NANOSP_SDK`
- `BOLOS_SDK=$STAX_SDK`

### Loading on a physical device

This step will vary slightly depending on your platform.

> Your physical device must be connected, unlocked and the screen showing the dashboard (not inside an application).

#### Linux (Ubuntu)

First make sure you have the proper udev rules added on your host.
See [udev-rules](https://github.com/LedgerHQ/udev-rules)

Then once you have [opened a terminal](#with-a-terminal) in the `app-builder` image and [built the app](#compilation-and-load)
for the device you want, run the following command:

```shell
# Run this command from the app-builder container terminal.
make load    # load the app on a Nano S by default
```

[Setting the BOLOS_SDK environment variable](#compilation-and-load) will allow you to load
on whichever supported device you want.

#### macOS / Windows (with PowerShell)

> It is assumed you have [Python](https://www.python.org/downloads/) installed on your computer.

Run these commands on your host from the app's source folder once you have [built the app](#compilation-and-load)
for the device you want:

```shell
# Install Python virtualenv
python3 -m pip install virtualenv
# Create the 'ledger' virtualenv
python3 -m virtualenv ledger
```

Enter the Python virtual environment

- macOS: `source ledger/bin/activate`
- Windows: `.\ledger\Scripts\Activate.ps1`

```shell
# Install Ledgerblue (tool to load the app)
python3 -m pip install ledgerblue
# Load the app.
python3 -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

## Tests

The OpenPGP app comes with different tests:

- Functional Tests implemented with Ledger's [Ragger](https://github.com/LedgerHQ/ragger) test framework.
- Unit Tests, allowing to test basic simple functions
- Manual Tests, using some script to perform real tests on the device:
  - Key generation
  - Encryption/Decryption
  - Sign/Verify

### Functional Tests (Ragger based)

#### Linux (Ubuntu)

On Linux, you can use [Ledger's VS Code extension](#with-vscode) to run the tests.
If you prefer not to, open a terminal and follow the steps below.

Install the tests requirements:

```shell
pip install -r tests/requirements.txt
```

Then you can:

Run the functional tests (here for nanos but available for any device once you have built the binaries):

```shell
pytest tests/ --tb=short -v --device nanos
```

Or run your app directly with Speculos

```shell
speculos --model nanos build/nanos/bin/app.elf
```

#### macOS / Windows

To test your app on macOS or Windows, it is recommended to use [Ledger's VS Code extension](#with-vscode)
to quickly setup a working test environment.

You can use the following sequence of tasks and commands (all accessible in the **extension sidebar menu**):

- `Select build target`
- `Build app`

Then you can choose to execute the functional tests:

- Use `Run tests`.

Or simply run the app on the Speculos emulator:

- `Run with Speculos`.

### Unit Tests

Those tests are available in the directory `unit-tests`. Please see the corresponding [README](unit-tests/README.md)
to compile and run them.

### Manual Tests

Those tests are available in the directory `manual-tests`. This consists in a helper script (`manual.sh`)
corresponding to different cases described in the document [Quick tests](doc/developer/quick-test.md).

## Documentation

Several documents are available.

Functional Specification of the OpenPGP Application available [here](<https://github.com/LedgerHQ/app-openpgp/blob/master/doc/specification/OpenPGP-smart-card-application.pdf>),
but also at <https://g10code.com/p-card.html>.

User documentation for the Ledger Application available here: [rst](doc/user/app-openpgp.rst),
or [pdf](<https://github.com/LedgerHQ/app-openpgp/blob/master/doc/user/app-openpgp.pdf>)

Developer documentation related to the Ledger Add-ons available here: [rst](doc/developer/gpgcard-addon.rst),
or [pdf](<https://github.com/LedgerHQ/app-openpgp/blob/master/doc/developer/gpgcard-addon.pdf>)

A Quick Test document to perform `Manual Tests` available [here](doc/developer/quick-test.md)

The pdf documentation for **User** and **Developer** are available, and can be generated from
the corresponding `.rst` files (in the same respective directories) using this command:

```shell
cd doc/
./generate.sh
```

## Continuous Integration

The flow processed in [GitHub Actions](https://github.com/features/actions) is the following:

- Ledger guidelines enforcer which verifies that an app is compliant with Ledger guidelines.
  The successful completion of this reusable workflow is a mandatory step for an app to be available
  on the Ledger application store. More information on the guidelines can be found
  in the repository [ledger-app-workflow](https://github.com/LedgerHQ/ledger-app-workflows)
- Code formatting with [clang-format](http://clang.llvm.org/docs/ClangFormat.html)
- Compilation of the application for all Ledger hardware in [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder)
- Unit tests of C functions with [cmocka](https://cmocka.org/) (see [unit-tests/](unit-tests/))
- End-to-end tests with [Speculos](https://github.com/LedgerHQ/speculos) emulator
  and [ragger](https://github.com/LedgerHQ/ragger) (see [tests/](tests/))
- Code coverage with [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)/[lcov](http://ltp.sourceforge.net/coverage/lcov.php)
  and upload to [codecov.io](https://about.codecov.io)

It outputs 3 artifacts:

- `compiled_app_binaries` within binary files of the build process for each device
- `code-coverage` within HTML details of code coverage

## Known limitations

Today, the current App has some known limitations.

- RSA4096 is disabled, because of an issue with the watchdog, resetting the device
  during long prime number operation.
- Using Ed25519 template, the decrypt doesn't output a correct result.
