# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - Unreleased

### Add

- PIN mode setting: random or fixed on-screen keypad, saved with the default PIN mode.
- TERMINATE DF is allowed with a blocked Admin PIN, after a confirmation on the device.
- Web UI: the slot is part of the backup file name.

### Change

- ECDSA signatures are returned as `r || s` of the curve size, and shorter digests are left-padded.
- The RSA DigestInfo is limited to 40% of the modulus.
- The PINs stay verified when the application is selected again; only the first SELECT resets them.
- A command or data object needing an unverified PIN returns 6982.
- v2 seeded keys are derived from a hardened slot path; a restored key matching no derivation of
  the device seed is erased.
- Settings pages share the same layout on Nano and touch screens; less RAM is used.
- Built with the SDK stack protector, link-time optimization and the SDK default APDU buffer size.

### Fix

- Truncated or malformed APDU data returns a status word instead of exiting the application.
- A command received during a UIF confirmation is rejected, and one interrupting the long response
  of a confirmed operation is processed as without UIF.
- PIN handling: constant-time check, try counter consumed before the check, no PIN left verified by
  CHANGE REFERENCE DATA or RESET RETRY COUNTER.
- Key attributes: their length and curve are checked against the algorithm.
- UIF is checked on the key mapped by MSE, and a key template change asks before deleting a key.
- Home screen: control characters in the cardholder name, and the slot selection policy.
- Seeded keys: SHAKE output length, and the seeded challenge chain code is wiped.
- Python tools and Web UI: many hardening fixes of the backup, restore and PIN flows.

### Remove

- The unused `NO_DECRYPT_cv25519` flag and the no-op CCID card and pin pad calls.

## [3.0.0] - 2026-10-15

### Add

- Key backups use AES-GCM authenticated encryption, with a random nonce in the v2 format. v1 and
  legacy backups can still be restored.
- Python tools and Web UI: optional AES-256-GCM encryption of the backup files.

### Fix

- Fix Cerberus issues: APDU parsing bounds, PIN sessions after reset or change, TERMINATE and
  ACTIVATE state, AES PSO:ENC buffers, Curve25519 ECDH, EdDSA and ECDSA signature buffers, UIF
  confirmation, seed and PIN material wiped from memory.
- Python tools and Web UI: fix Cerberus issues of the backup and restore flows.

## [2.7.4] - 2026-10-01

### Add

- AI instructions submodule.

## [2.7.3] - 2026-08-21

### Fix

- Corrected the CodeQL findings.

## [2.7.2] - 2026-08-11

### Add

- Web UI for the backup and restore, on WebHID.

### Fix

- The asynchronous PIN confirmation authorizes the PIN it was shown for.
- RSA private exponent disclosure through a key size downgrade.

## [2.7.1] - 2026-05-11

### Fix

- Bounds checks in the key restore, Ed25519 public key read, MSE and PKCS#1 v1.5 padding.
- UIF is checked on the key mapped by MSE.
- Python tools: sensitive data redacted from logs, backup files created owner-only.

## [2.7.0] - 2026-04-17

### Fix

- Bounds checks in the APDU fetch helpers and in the PUT DATA `3FFF` key import.
- TERMINATE DF requires a verified Admin PIN.
- Python tools: JSON instead of pickle for the backup files.

## [2.6.1] - 2026-01-21

### Fix

- Fix issue #135.

## [2.6.0] - 2025-12-29

### Add

- Decryption with Curve25519 keys, enabled again.

## [2.5.1] - 2025-10-02

### Add

- Apex P support.

## [2.5.0] - 2025-09-17

### Change

- Nano devices use NBGL.

### Remove

- Nano S support.

## [2.4.1] - 2025-07-24

### Fix

- RSA 4096 support enabled again.
- USB stop and start handled through the standard application exit.

## [2.4.0] - 2025-06-04

### Change

- Updated CI workflows and linter.

## [2.3.1] - 2025-05-28

### Add

- Flex support.

### Change

- Compatibility with the reworked SDK IO and NBGL v2.
- RSA 4096 keys can be used again, their generation staying disabled.

## [2.3.0] - 2024-08-08

### Fix

- Key generation features missing after a restore.

## [2.2.2] - 2024-05-22

### Change

- Code readability improvements.

## [2.2.1] - 2024-03-14

### Fix

- Security audit fixes, screen message buffer overwrite, public key URL set on each slot.

## [2.2.0] - 2024-03-13

### Add

- secp256k1 curve.

### Fix

- Missing elements in backup and restore.
- RSA 4096 disabled (watchdog issue).

## [2.1.0] - 2024-02-29

### Fix

- PIN mode change allowed with a verified PW1 or PW2.
- Historical bytes padding and status indicator.

## [2.0.1] - 2024-02-28

### Add

- Stax support.
- Functional, unit and manual tests, and CI workflows.

### Change

- Key slots, PIN modes and SEED mode management reworked.

### Remove

- RSA 1024.

## [2.0.0] - 2024-02-14

### Change

- Built with the latest SDK; one full OpenPGP application on non-Nano S devices.

### Add

- RSA 4096 key generation on Nano X and Nano S Plus.

### Remove

- Blue support.

## [1.4.4] - 2023-01-24

### Change

- Compatibility with the SDK cryptographic library.

## [1.4.3] - 2020-12-14

### Fix

- GET CHALLENGE length handling (#63).

## [1.4.2] - 2020-12-06

### Change

- RSA 4096 key generation disabled on Nano X.

## [1.4.1] - 2020-02-13

### Fix

- Fix issue #12.

## [1.4.0] - 2020-01-16

### Add

- Two levels of reset.
- Restore of a single key.

### Fix

- PIN entry on screen (#7).

## [1.3.3] - 2019-11-13

### Change

- Compatibility with the SDK 1.6.

## [1.3.2] - 2019-08-08

### Add

- Nano X support.
- UIF for PSO:ENC.

### Fix

- The PIN is verified before changing the PIN mode.

## [1.3.1] - 2019-01-31

### Fix

- Minor fixes.

## [1.3.0] - 2018-10-09

### Add

- Full backup and restore, with a Python tool.

### Fix

- APDU state machine after a response.

### Remove

- Brainpool 256R1.

## [1.2.1] - 2018-06-04

### Fix

- SSH authentication with Ed25519.

## [1.2.0] - 2018-05-30

### Change

- Port to the SDK 1.4.2.1.

## [1.1.1] - 2018-03-13

### Change

- Port to the firmware 1.4.1.

## [1.1.0] - 2017-08-31

### Add

- User guide and new logo.

## [1.0.1] - 2017-07-07

### Fix

- Access condition to change the PIN mode set to PW1.

## [1.0.0] - 2017-06-19

### Add

- First release: OpenPGP card application with on-screen PIN entry and asynchronous interaction.
