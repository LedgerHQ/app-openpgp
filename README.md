## GnuPG application: blue-app-gnupg

GnuPG application for Ledger Blue and Nano S

This application implements "The OpenPGP card" specification revision 3.0. This specification is available in *doc* directory and at https://g10code.com/p-card.html .

The application supports:
  - RSA with key up to 4096 bits 
  - ECDSA with secp256k1, secp256r1, brainpool 256r1 and brainpool 256t1 curves
  - EDDSA with Ed25519 curve 
  - ECDH with  secp256k1, secp256r1, brainpool 256r1, brainpool 256t1 and curve25519 curves


This release has known missing parts (see also Add-on) :

   * Ledger Blue support
   * Seed mode ON/OFF via apdu


## Installation and Usage

See the full doc at https://github.com/LedgerHQ/blue-app-openpgp-card/blob/master/doc/user/blue-app-openpgp-card.pdf


## Add-on

The GnuPG application implements the following addon:
  - serial modification
  - on screen reset
  - 3 independent key slots
  - seeded key generation

Technical specification is available at https://github.com/LedgerHQ/blue-app-openpgp-card/blob/master/doc/developper/gpgcard3.0-addon.rst

   
### Key slot

"The OpenPGP card" specification specifies:
  - 3 asymmetric keys : Signature, Decryption, Authentication
  - 1 symmetric key

The blue application allow you to store 3 different key sets, named slot. Each slot contains the above 4 keys.
You can choose the active slot on the main screen.
When installed the default slot is "1". You can change it in settings.

   
### seeded key generation

A seeded mode is implemented in order to restore private keys on a new token.
In this mode key material is generated from the global token seeded.

Please consider SEED mode as experimental.

More details to come... 

### On screen reset

The application can be reset as if it was fresh installed. In settings, choose reset and confirm.

