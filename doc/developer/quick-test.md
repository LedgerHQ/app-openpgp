# Quick Test guide

This page helps the developer to quickly test basic features of the OpenPGP Application.

Please note this guideline is targeting Linux (Ubuntu) only machine, but once installed,
all commands are valid on any other OS.

## Step 1: Install your device

Do a fresh installation of OpenPGP Application on the device.

## Step 2: Setup conf

### Tools and scripts

Ensure `pgp` is available on your host machine.

Install the needed mandatory tools:

```shell
sudo apt install libpcsclite-dev scdaemon pcscd -y
```

Optionally, the following diagnostic tool can also be installed:

```shell
sudo apt install pcsc-tools -y
```

You can check the tools are operational with the commands (see *help* for other options):

```shell
$ pcsc_scan -c

Thu Jan 18 09:45:19 2024
 Reader 0: Ledger Nano S Plus [Nano S Plus] (0001) 00 00
  Event number: 0
  Card state: Card inserted,
  ATR: 3B 00
 Reader 1: Alcor Micro AU9540 01 00
  Event number: 0
  Card state: Card removed,

$ p11-kit list-modules
p11-kit-trust: p11-kit-trust.so
    library-description: PKCS#11 Kit Trust Module
    library-manufacturer: PKCS#11 Kit
    library-version: 0.24
    token: System Trust
        manufacturer: PKCS#11 Kit
        model: p11-kit-trust
        serial-number: 1
        hardware-version: 0.24
        flags:
               write-protected
               token-initialized
opensc-pkcs11: opensc-pkcs11.so
    library-description: OpenSC smartcard framework
    library-manufacturer: OpenSC Project
    library-version: 0.22
    token: OpenPGP card (User PIN)
        manufacturer: OpenPGP project
        model: PKCS#15 emulated
        serial-number: 2c97c3e750db
        hardware-version: 3.3
        firmware-version: 3.3
        flags:
               rng
               login-required
               user-pin-initialized
               protected-authentication-path
               token-initialized
    token: OpenPGP card (User PIN (sig))
        manufacturer: OpenPGP project
        model: PKCS#15 emulated
        serial-number: 2c97c3e750db
        hardware-version: 3.3
        firmware-version: 3.3
        flags:
               rng
               login-required
               user-pin-initialized
               protected-authentication-path
               token-initialized

Check the installation of CCID driver and more particularly its device config:

Edit the file `/etc/libccid_Info.plist`, and check if the Ledger devices are correctly defined.

Please take care, the different lists are ordered in the same way. Do not insert elements anywhere!

> Note: To add a new Ledger device, check [doc/user/app-openpgp.rst](../user/app-openpgp.rst)

### Manual Tests

Jump into the directory `manual-tests`. There is a helper script to perform some of the following described operations.

```shell
cd manual-tests/
$ ./manual.sh -h

Usage: ./manual.sh <options>

Options:

  -c <init|card|encrypt|decrypt|sign|verify>  : Requested command
  -v     : Verbose mode
  -h     : Displays this help
```

The `init` command allows to prepare a local `gnupg` home directory, with the default minimal config file for *scdaemon*.
For further investigations, you can also add in the file `manual-tests/gnupg/scdaemon.conf` the following lines:

```shell
debug-level expert
debug 11
log-file /tmp/scdaemon.log
```

## Step 3: Verify the card status and the pin code

Launch the Application on the device.

Now, on the PC, inside a terminal:

```shell
$ killall scdaemon gpg-agent
$ gpg --homedir $(pwd)/gnupg --card-edit
gpg: keybox 'xxxx/manual-tests/gnupg/pubring.kbx' created

Reader ...........: Ledger Nano S Plus [Nano S Plus] (0001) 01 00
Application ID ...: D2760001240103032C97B7DA92860000
Version ..........: 3.3
Manufacturer .....: unknown
Serial number ....: B7DA9286
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 12 12 12
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

This gives the status of the current card. We can see on the 1st line, the detected Card Reader (i.e. the Ledger device).
In the Application ID information, we can see, concatenated:

- `D27600012401`: The *Registered application provider identifier* (ISO 7816-5)
- `01`: The *Proprietary application identifier extension* (OpenPGP)
- `0303`: The current specification version *3.3*
- `2C97`: The Ledger Manufacturer Id
- `B7DA9286`: the Card Serial

And currently, no keys are present on the Card.
Now, we can verify the Card pin code using the `verify` command.
You will be prompt to validate with the buttons, or enter the pin code, depending on the Application settings.

```shell
gpg/card> verify

Reader ...........: Ledger Nano S Plus [Nano S Plus] (0001) 01 00
Application ID ...: D2760001240103032C97B7DA92860000
Version ..........: 3.3
Manufacturer .....: unknown
Serial number ....: B7DA9286
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 12 12 12
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

> Note: you can exit by using the command `quit` or using `CTRL-D`.

## Step 4: Change to screen pin style

Then on the device, go to:

```text
  settings -> PIN mode, and select ‘On Screen’
  settings -> PIN mode, and select ‘Set as default’
```

unplug and replug the nanos, relaunch the Application, and check:

```text
  settings -> PIN mode, you should have ‘On Screen # +’ (DASH and PLUS)
```

## Step 5: Create RSA keys

Back in the terminal window, in `manual-tests` directory.

> Note: During this phase PIN has to be validate on the device.

```shell
$ killall scdaemon gpg-agent
$ gpg --homedir $(pwd)/gnupg --card-edit
gpg: keybox 'xxxx/manual-tests/gnupg/pubring.kbx' created

Reader ...........: Ledger Nano S Plus [Nano S Plus] (0001) 01 00
Application ID ...: D2760001240103032C97B7DA92860000
Version ..........: 3.3
Manufacturer .....: unknown
Serial number ....: B7DA9286
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 12 12 12
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

Now, switch to **Admin** mode, and generate the keys (this is an interactive operation).

```shell
gpg/card> admin
Admin commands are allowed

gpg/card> generate
Make off-card backup of encryption key? (Y/n) n

Please note that the factory settings of the PINs are
   PIN = '123456'     Admin PIN = '12345678'
You should change them using the command --change-pin

What keysize do you want for the Signature key? (2048) 2048
What keysize do you want for the Encryption key? (2048) 2048
What keysize do you want for the Authentication key? (2048) 2048
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0
Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: testkey
Email address:
Comment:
You selected this USER-ID:
      "testkey"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
gpg: xxxx/manual-tests/gnupg/trustdb.gpg: trustdb created
gpg: key 5ED17DF289C757A2 marked as ultimately trusted
gpg: directory 'xxxx/manual-tests/gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as 'xxxx/manual-tests/gnupg/openpgp-revocs.d/7FDC3D2FCD3558CB06631EAB5ED17DF289C757A2.rev'
public and secret key created and signed.

gpg/card> quit
pub   rsa2048 2017-10-03 [SC]
      7FDC3D2FCD3558CB06631EAB5ED17DF289C757A2
uid                      testkey
sub   rsa2048 2017-10-03 [A]
sub   rsa2047 2017-10-03 [E]
```

## Step 6: Encrypt/Decrypt

Simple *Encrypt* and *Decrypt* test to use and check the generated keys.

Start to create a dummy file to be encrypted and checked.

```shell
$ killall scdaemon gpg-agent
$ echo CLEAR > foo.txt
```

### Encrypt

Use this command to encrypt. Please note we specify the key to be used.

```shell
$ gpg --homedir $(pwd)/gnupg --encrypt --recipient testkey foo.txt
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
```

Just kill the processes to force pin to be asked...

```shell
$ killall gpg-agent scdaemon
```

### Decrypt

Use this command to encrypt. Here, no need to specify the key...

```shell
$ gpg --homedir $(pwd)/gnupg --decrypt foo.txt.gpg > foo_dec.txt
gpg: encrypted with 2047-bit RSA key, ID 602FE5EB7BFA4B00, created 2017-10-03
"testkey"
$ cat foo_dec.txt
CLEAR
```

## Step 7: Sign/Verify

Simple *Sign* and *Verify* test to use and check signature with the generated keys.

Start to create a dummy file to be signed and verified.

```shell
$ killall scdaemon gpg-agent
$ echo CLEAR > foo.txt
```

### Sign

Use this command to sign. The generated file is the encrypted signature.

```shell
$ gpg --homedir $(pwd)/gnupg --sign foo.txt
```

Just kill the processes to force pin to be asked...

```shell
$ killall gpg-agent scdaemon
```

### Verify

Use this command to verify the signature

```shell
$ gpg --homedir $(pwd)/gnupg --verify foo.txt.gpg
gpg: Signature made jeu. 18 janv. 2024 09:59:33 CET
gpg:                using RSA key FD2D7E0C99825F8515EDB544156DEEF5959D4DC6
gpg: Good signature from "testkey" [ultimate]
```
