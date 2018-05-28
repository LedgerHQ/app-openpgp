..
   Copyright 2018 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

..
   ------------------------------------------------------------------------
                         LaTex substitution Definition
   ------------------------------------------------------------------------



License
=======

Author: Cedric Mesnil <cedric@ledger.fr>

License:

  | Copyright 2017 Cedric Mesnil <cedric@ledger.fr>, Ledger SAS
  |
  | Licensed under the Apache License, Version 2.0 (the "License");
  | you may not use this file except in compliance with the License.
  | You may obtain a copy of the License at
  |
  |   http://www.apache.org/licenses/LICENSE-2.0
  |
  | Unless required by applicable law or agreed to in writing, software
  | distributed under the License is distributed on an "AS IS" BASIS,
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  | See the License for the specific language governing permissions and
  | limitations under the License.




Introduction
============

GnuPG application for Ledger Blue and Nano S

This application implements "The OpenPGP card" specification revision 3.0. This specification is available in doc directory and at https://g10code.com/p-card.html .

The application supports:

   - RSA with key up to 4096 bits
   - ECDSA with secp256k1, secp256r1, brainpool 256r1 and brainpool 256t1 curves
   - EDDSA with Ed25519 curve
   - ECDH with secp256k1, secp256r1, brainpool 256r1, brainpool 256t1 and 
     curve25519 curves
   
This release has known missing parts (see also [GPGADD]) :

   - Ledger Blue support
   - Seed mode ON/OFF via apdu



How to install GPG Application
==============================

Nano S / Blue
-------------

For both, source and binary installation, use the most recent tag.

From Binary
~~~~~~~~~~~~~

Use the "Ledger Manager" Chrome App. See https://www.ledgerwallet.com/apps/manager for details.

As the "OpenPGP card" application is not fully compliant with UI and documentation guidelines, the application is in developer section: click on "Show delevopers items" on the bottom right corner to see it.

   - Launch the Ledger Manager. See `Ledger Manager <https://www.ledgerwallet.com/apps/manager>`_  
     and  ` <https://ledger.groovehq.com/knowledge_base/topics/ledger-manager>`_ 
     for details about installing and using  the manager;
   - Connect your Nano S or your Blue, enter your PIN, and stay on the 
     dashboard;
   - Click on *show developer items* on the bottom right corner;
   - Click on the green bottom arrow icon near the Ledger *Open PGP* logo;
   - Confirm the installation when required on your device by pressing the 
     right button above the checkmark;
   - Quit the Ledger Manager


The application is ready to use!


From source
~~~~~~~~~~~~~

Building from sources requires the the Nano S SDK 1.3.1.4 on firmware 1.3.1. See https://github.com/LedgerHQ/nanos-secure-sdk

The SDK must be slightly modified:

   - replace lib_stusb/STM32_USB_Device_Library/Class/CCID/src/usbd_ccid_if.c
     and lib_stusb/STM32_USB_Device_Library/Class/CCID/inc/usbd_ccid_if.h by the 
     one provided in sdk/ directory
   - edit script.ld and modify the stack size : STACK_SIZE = 832;


Refer to the SDK documentation for the compiling/loading...

System Configuration
--------------------

For Linux and MAC, until version 1.4.27, Ledger CCID interface is not supported 
by default by pcscd and must be manually added 

For windows....

Linux
~~~~~

You have to have to add the NanoS to /etc/libccid_Info.plist

    In  <key>ifdVendorID</key>      add the entry  <string>0x2C97</string>
    In  <key>ifdProductID</key>     add the entry  <string>0x0001</string>
    In  <key>ifdFriendlyName</key>  add the entry  <string>Ledger Token</string>
  
These 3 entries must be added at the end of each list.

MAC
~~~

1. First it is necessary to [disable SIP](https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) That doesn't allow the editing of files in /usr/.

2. You have to add the Nano S to /usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents/Info.plist


       In  <key>ifdVendorID</key>      add the entry  <string>0x2C97</string>
       In  <key>ifdProductID</key>     add the entry  <string>0x0001</string>
       In  <key>ifdFriendlyName</key>  add the entry  <string>Ledger Token</string>
  
This 3 entries must be added at the end of each list.

3. [Enable SIP](https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)

Windows
~~~~~~~

TODO



Nano S OpenPGP Card application explained
=========================================

Menu Overview
-------------

The full menu layout is :


| \ *Device Info*
| Select Slot
|      \ *Choose:*
|       Slot 1 #+
|       Slot 2
|       Slot 3
|       Set Default
| Settings
|       Key Template
|             Choose Key...
|                    Signature
|                    Decryption
|                    Authentication
|             Choose Type...
|                    RSA 2048
|                    RSA 3072
|                    RSA 4096
|                    NIST P256
|                    Brainpool 256R1
|                    ED25519
|             Set Template
|       Seed mode
|    \ *<ON|OFF>*
|             Set on
|             Set off
|       PIN mode
|    \ *Choose:*
|             Host
|             On Screen
|             Confirm only #+
|             Trust
|       Reset
| About 
|      \ *OpenPGP Card*
|      \ *(c) Ledger SAS*
|      \ *Spec 3.0*
|      \ *App 1.0.1*

| Emphasis entries are not selectable and just provide information. 
| A "**#**" after the entry label means default value on reset.
| A "**+**" after the entry label means current value.


Device Info
-------------

The *Device Info* provides current user and slot information. The format is:

|      <User: **name**/ Slot: **n** / Serial: **s** >

with:

 * **name** is the one provided to ``gpg --card-edit``. See [GPGSC].
 * **n** is the current slot, see below.
 * **s** is the 32 bits card serial number. Note that the last three bits always
encode the current slot value.


Select Slot
-------------

A Slot is a set of
three key pairs *Signature, Decryption, Authentication* as defined by gnupg 
specification.

Usually a GPG card application only manages a single set. Ledger version enhances
this and allows you to manage three key sets.  

The *Select Slot* menu allows you to select the slot you want to play with,  and 
to set the default slot when the application start.

To change the current slot, display the slot you want and  select it

To change the default slot, first select it, and then select the *Set Default*
entry.


Settings
--------

Key Template
~~~~~~~~~~~~

A key template is defined by the OpenGPG card application specification. It 
describes the key to be generated with the ``generate`` command in 
``gpg --card-edit``

The problem is there is no way with the ``gpg`` command line to easily set
up the desired template. The menu fixes that.

First under *Choose Key* menu, select the one of three keys for which you want to modify
the template. Then under "Choose Type", select the desired key template. 
Finally select "Set Template" entry to set it.

To show the current template use the  ``gpg --card-status`` command.


Seed mode
~~~~~~~~~

When generating new keys on NanoS, those keys can be generated randomly
or in a deterministic way. The deterministic way is specified in [GPGADD].
The current mode is displayed in the first sub menu. To activate the seeded
 mode select *ON*, to deactivate the seeded mode select *OFF*.

When the application starts, the seeded mode is always set to *OFF*


PIN mode
~~~~~~~~

Some operations require the user to enter his PIN code. 
The default PIN values are:

    - user: ``123456``
    - admin: ``12345678``

The PIN entry can be done using four methods, named 
"*Host*", "*On Screen*", "*Confirm only*", "*Trust*".

After each mode a *+* or *#* symbol may appear to tell which mode is the current one
and which one is the default when the application starts.
The default mode can be changed by first selecting the desired mode and then
selecting the *Set default" menu. Note that *Trust*  can not be set as default mode.


Note that *On Screen*", "*Confirm only*" and "*Trust*" may not work if the 
client application does not support it. In that case the "*Host*" should be 
automatically used by the client in a transparent way.

**Host**

The PIN is entered on the external computer.


**On Screen**

The PIN is entered on the Nano S or Blue screen. For  entering the PIN choose the
next digit by using the left or right button. When the digit you expect is displayed
select it by pressing both buttons ar the same time

.. image:: pin_entry.png
    :align: middle


Once all digits are selected, validate the PIN by selecting the **'V'** (Validate)
letter

.. image:: pin_validate.png
    :align: middle
 

If you want to change the previous digit select the **'C'** (Cancel) letter.

.. image:: pin_cancel.png
    :align: middle
  

Finnaly if you want to abort the PIN entry, select the **'A'** (Abort) letter.

.. image:: pin_abort.png
    :align: middle
  

**Confirm only**

The user is requested, on the NanoS or Blue screen, to confirm 
the PIN validation. The PIN value is not required, the user just has
to push the *REJECT* or *OK*  button on the device. 

This is the default mode after application installation. 

.. image:: pin_confirm.png
    :align: middle
  

**Trust**

Act as if the PIN is always validated. This is a dangerous mode which should only be
used in a highly secure environment.  

Reset
~~~~~

Selecting the menu will erase all OpenPGP Card Application data and will 
reset the application in its '*just installed*' state.
 


Nano S OpenPGP Card application usage
=====================================


GPG
---

The OpenGPG Card application need at least version 2.1.19 for full support.
A version prior to 2.1.19 will fail when using ECC.

You should test with a test key and make a backup of your
keyring before starting, except if your are sure about what you do.


Configuration
~~~~~~~~~~~~~

In order to use a Ledger device with gpg it is needed to explicitly setup 
the reader and the delegated PIN support. 
Edit the file ~/.gnupg/scdaemon.conf and add the following lines:

 | ``reader-port "Ledger Token [Nano S] (0001) 01 00"``
 | ``allow-admin``
 | ``enable-pinpad-varlen``


If you do not set the ``enable-pinpad-varlen`` option, even if Nano S is
configured in *On Screen* mode, gpg will keep requesting the PIN on the host.

You can check ``the reader-port`` value by running the command line ``pcsc_scan``:

 | ``$ pcsc_scan ``
 | ``PC/SC device scanner``
 | ``V 1.4.27 (c) 2001-2011, Ludovic Rousseau <ludovic.rousseau@free.fr>``
 | ``Compiled with PC/SC lite version: 1.8.14``
 | ``Using reader plug'n play mechanism``
 | ``Scanning present readers...``
 | ``0: Alcor Micro AU9560 00 00``
 | ``1: Ledger Token [Nano S] (0001) 01 00``
 | ``Reader 0: Alcor Micro AU9560 00 00``
 | ``Card state: Card removed, ``
 | ``Reader 1: Ledger Token [Nano S] (0001) 01 00``
 | ``Card state: Card inserted, ``
 | ``ATR: 3B 00``
 | ``+ TS = 3B --> Direct Convention``
 | ``+ T0 = 00, Y(1): 0000, K: 0 (historical bytes)``



Get/Set basic information
~~~~~~~~~~~~~~~~~~~~~~~~~

The ``gpg --card-status`` command provides default card information. Just after
installation it should look like this:

 | ``$ gpg --card-status``
 | ``Reader ...........: Ledger Token [Nano S] (0001) 01 00``
 | ``Application ID ...: D2760001240103002C97AFB114290000``
 | ``Version ..........: 3.0``
 | ``Manufacturer .....: unknown``
 | ``Serial number ....: AFB11429``
 | ``Name of cardholder: [not set]``
 | ``Language prefs ...: [not set]``
 | ``Sex ..............: unspecified``
 | ``URL of public key : [not set]``
 | ``Login data .......: [not set]``
 | ``Signature PIN ....: not forced``
 | ``Key attributes ...: rsa2048 rsa2048 rsa2048``
 | ``Max. PIN lengths .: 12 12 12``
 | ``PIN retry counter : 3 0 3``
 | ``Signature counter : 0``
 | ``Signature key ....: [none]``
 | ``Encryption key....: [none]``
 | ``Authentication key: [none]``
 | ``General key info..: [none]``

You can set the user information with the ``gpg --card-edit`` command and 
``name``, ``url``, ``login``, ``lang``, ``sex`` subcommands. For example if you
want to set up your name:

 | ``$ gpg --card-edit``
 | ``gpg/card> admin``
 | ``Admin commands are allowed``
 | ````
 | ``gpg/card> name``
 | ``Cardholder's surname: Mesnil``
 | ``Cardholder's given name: Cedric``
 | ````
 | ``gpg/card> sex``
 | ``Sex ((M)ale, (F)emale or space): M``
 | ````
 | ``gpg/card> list``
 | ````
 | ``Reader ...........: Ledger Token [Nano S] (0001) 01 00``
 | ``Application ID ...: D2760001240103002C97AFB114290000``
 | ``Version ..........: 3.0``
 | ``Manufacturer .....: unknown``
 | ``Serial number ....: AFB11429``
 | ``Name of cardholder: Cedric Mesnil``
 | ``Language prefs ...: [not set]``
 | ``Sex ..............: unspecified``
 | ``URL of public key : [not set]``
 | ``Login data .......: [not set]``
 | ``Signature PIN ....: not forced``
 | ``Key attributes ...: rsa2048 rsa2048 rsa2048``
 | ``Max. PIN lengths .: 12 12 12``
 | ``PIN retry counter : 3 0 3``
 | ``Signature counter : 0``
 | ``Signature key ....: [none]``
 | ``Encryption key....: [none]``
 | ``Authentication key: [none]``
 | ``General key info..: [none]``


Notes:
  
  * Modifying the user information will prompt you to enter ``User PIN``.
  * Setting user information is not required  for using gpg client. 


Generate new key pair
~~~~~~~~~~~~~~~~~~~~~

For generating a new key pair follow those steps:

    - Select the desired NanoS OpenPGP Card application slot
    - Setup the desired key template for this slot
    - Generate the new key set 


**Step 1**

Starting from main menu:

    - Select *Select slot* menu
    - Scroll to desired slot
    - Select it
    - Optionally set it as default by selecting *Set Default* menu
    - Select *Back* to return to main menu.


**Step 2**

The default template for each three keys (*signature*, *decryption*, 
*authentication*) is ``RSA 2048``. If you want another kind of key
you have to set the template before generating keys.

!WARNING!: changing the current template of a key automatically erases 
the associated key.

Starting from main menu:

    - Select *Settings* menu
    - Select *Key template* menu 
    - Select *Choose Key...* menu (a)
    - Scroll and select which key you want to set the new template for
    - Select *Choose type...* menu
    - Scroll and select among the supported key types and sizes
    - Select *Set template*
    - Repeat this process from (a) if you want to modify another key 
      template
    - Select *Back* to return to main menu.


**Step 3**

Once the template has been set, it's possible to generate new key pairs
with ``gpg``. 

!WARNING!: gpg will generate the three key pairs and
will overwrite any key already present in the selected slot.

Here after is a detailed log of key generation of ECC keys, assuming
the three key templates are ``NIST P256``.

**Edit Card**


 | ``$ gpg2 --edit-card``
 | ``Reader ...........: Ledger Token [Nano S] (0001) 01 00``
 | ``Application ID ...: D2760001240103002C97AFB1142B0000``
 | ``Version ..........: 3.0``
 | ``Manufacturer .....: unknown``
 | ``Serial number ....: AFB1142B``
 | ``Name of cardholder: Cedric Mesnil``
 | ``Language prefs ...: [not set]``
 | ``Sex ..............: male``
 | ``URL of public key : [not set]``
 | ``Login data .......: [not set]``
 | ``Signature PIN ....: not forced``
 | ``Key attributes ...: nistp256 nistp256 nistp256``
 | ``Max. PIN lengths .: 12 12 12``
 | ``PIN retry counter : 3 0 3``
 | ``Signature counter : 0``
 | ``Signature key ....: [none]``
 | ``Encryption key....: [none]``
 | ``Authentication key: [none]``
 | ``General key info..: [none]``

**Switch to admin mode:**

 | ``gpg/card>`` *admin*
 | ``Admin commands are allowed``

**Request new key generation without backup**

 | ``gpg/card>`` *generate*
 | ``Make off-card backup of encryption key? (Y/n)`` **n**               

**Unlock user level ``81``**

 | ``Please unlock the card``  
 | ````
 | ``Number: 2C97 AFB1142B``
 | ``Holder: Cedric Mesnil``
 | ````
 | ``Use the reader's pinpad for input.``
 | ``  OK``
 | ``Press any key to continue.  ``                                      

**Set key validity**

 | ``Please specify how long the key should be valid.``
 | ``         0 = key does not expire``
 | ``      <n>  = key expires in n days``
 | ``      <n>w = key expires in n weeks``
 | ``      <n>m = key expires in n months``
 | ``     <n>y = key expires in n years``
 | ``Key is valid for? (0)`` *0*
 | ``Key does not expire at all``
 | ``Is this correct? (y/N)``*y*

**Set user ID**
                     
 | ``GnuPG needs to construct a user ID to identify your key.``
 | ````
 | ``Real name: Cedric Mesnil``
 | ``Email address: cedric@ledger.fr``
 | ``Comment:     ``                  
 | ``You selected this USER-ID:``
 | ``    "Cedric Mesnil <cedric@ledger.fr>"``
 | ````
 | ``Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?``  *O*
 | ````
 | ``You selected this USER-ID:``
 | ``    "Cedric Mesnil <cedric@ledger.fr>"``

**Unlock admin level ``83``**

 | ``Please enter the Admin PIN  ``                         
 | ````
 | ``Number: 2C97 AFB1142B``
 | ``Holder: Cedric Mesnil``
 | ````
 | ``Use the reader's pinpad for input.``
 | ``  OK``
 | ``Press any key to continue.``

**Unlock user level ``82``**

 | ``Please unlock the card``
 | ````
 | ``Number: 2C97 AFB1142B``
 | ``Holder: Cedric Mesnil``
 | ``Counter: 8``
 | ````
 | ``Use the reader's pinpad for input.``
 | ``  OK``
 | ``Press any key to continue.``

**Final confirmation**

 | ``Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?`` *O*
 | ``gpg: key DF3FA4A33EF00E47 marked as ultimately trusted``
 | ``gpg: revocation certificate stored as '/home/gnuk/.gnupg/openpgp-revocs.d/89F772243C9A3E583CB59AB5DF3FA4A33EF00E47.rev'``
 | ``public and secret key created and signed.``

**Get information after key generation**

 | ``gpg/card> list``
 | ````
 | ``Reader ...........: Ledger Token [Nano S] (0001) 01 00``
 | ``Application ID ...: D2760001240103002C97AFB1142B0000``
 | ``Version ..........: 3.0``
 | ``Manufacturer .....: unknown``
 | ``Serial number ....: AFB1142B``
 | ``Name of cardholder: Cedric Mesnil``
 | ``Language prefs ...: [not set]``
 | ``Sex ..............: male``
 | ``URL of public key : [not set]``
 | ``Login data .......: [not set]``
 | ``Signature PIN ....: not forced``
 | ``Key attributes ...: nistp256 nistp256 nistp256``
 | ``Max. PIN lengths .: 12 12 12``
 | ``PIN retry counter : 3 0 3``
 | ``Signature counter : 12``
 | ``Signature key ....: F844 38BB CA87 F9A7 6830  F002 F8A4 A353 3CBF CAA5``
 | ``      created ....: 2017-08-22 15:59:36``
 | ``Encryption key....: B1D3 C9F2 C3C5 87CA 36A7  F02E E137 28E9 13B8 77E1``
 | ``      created ....: 2017-08-22 15:59:36``
 | ``Authentication key: F87D EF02 9C38 C43D 41F0  6872 2345 A677 CE9D 8223``
 | ``      created ....: 2017-08-22 15:59:36``
 | ``General key info..: pub  nistp256/F8A4A3533CBFCAA5 2017-08-22 cedric mesnilCedric Mesnil <cedric@ledger>``
 | ``sec>  nistp256/F8A4A3533CBFCAA5  created: 2017-08-22  expires: never     ``
 | ``                                 card-no: 2C97 AFB1142B``
 | ``ssb>  nistp256/2345A677CE9D8223  created: 2017-08-22  expires: never   ``  
 | ``                                 card-no: 2C97 AFB1142B``
 | ``ssb>  nistp256/E13728E913B877E1  created: 2017-08-22  expires: never  ``   
 | ``                                 card-no: 2C97 AFB1142B``

**Say goodbye

 | ``gpg/card> quit``**



At this point it's possible to check that the key has been generated on card with the following command:

 | ``$ gpg2 --list-secret-keys cedric@ledger``
 | ``gpg: checking the trustdb``
 | ````
 | ``sec>  nistp256 2017-08-22 [SC]``
 | ``      F84438BBCA87F9A76830F002F8A4A3533CBFCAA5``
 | ``      Card serial no. = 2C97 AFB1142B``
 | ``uid           [ultimate] cedric mesnilCedric Mesnil <cedric@ledger>``
 | ``ssb>  nistp256 2017-08-22 [A]``
 | ``ssb>  nistp256 2017-08-22 [E]``



Moving existing key pair
~~~~~~~~~~~~~~~~~~~~~~~~

This section shows how to move an existing key onto the Ledger device.

The key to transfer here is a RSA 4096 bits key:

 | ``$ gpg2 --list-secret-keys "RSA 4096"``
 | ``sec   rsa4096 2017-04-26 [SC]``
 | ``      FB6C6C75FB016635872ED3E49B93CB47F954FB53``
 | ``uid           [ultimate] RSA 4096``
 | ``ssb   rsa4096 2017-04-26 [E]``


In case of transfer it is not necessary to previously set the template.
It will be automatically changed.
When generating a new key, the three keys (*signature*, *decryption*, 
*authentication*)) are automatically generated.
When transferring existing ones, it is possible to choose which one will be
moved.

**Edit Key**

 | ``$ gpg2 --edit-key "RSA 4096"``
 | ``gpg (GnuPG) 2.1.19; Copyright (C) 2017 Free Software Foundation, Inc.``
 | ``This is free software: you are free to change and redistribute it.``
 | ``There is NO WARRANTY, to the extent permitted by law.``
 | ````
 | ``Secret key is available.``
 | ````
 | ``sec  rsa4096/9B93CB47F954FB53``
 | ``     created: 2017-04-26  expires: never       usage: SC `` 
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa4096/49EE12B0F5CBDF26``
 | ``     created: 2017-04-26  expires: never       usage: E   ``
 | ``[ultimate] (1). RSA 4096``

**Select the key to move, here the *encryption* one.**

 | ``gpg> `` *key 1*
 | ``          ``
 | ``sec  rsa4096/9B93CB47F954FB53``
 | ``    created: 2017-04-26  expires: never       usage: SC  ``
 | ``    trust: ultimate      validity: ultimate``
 | ``ssb* rsa4096/49EE12B0F5CBDF26``
 | ``     created: 2017-04-26  expires: never       usage: E   ``
 | ``[ultimate] (1). RSA 4096``

**Move** 

 | ``gpg> `` **keytocard**
 | ``Please select where to store the key:``
 | ``   (2) Encryption key``
 | ``Your selection?`` *2*

**Unlock admin level ``83``**

 | ``Please enter the Admin PIN``
 | ````
 | ``Number: 2C97 1D49B409``
 | ``Holder: ``
 | ````
 | ``Use the reader's pinpad for input.``
 | ``  OK``
 | ``Press any key to continue.``

**Unlock admin level ``83`` (maybe twice....)**

 | ``Please enter the Admin PIN``
 | ````
 | ``Number: 2C97 1D49B409``
 | ``Holder: ``
 | ````
 | ``Use the reader's pinpad for input.``
 | `` OK``
 | ``Press any key to continue.``

 | ``sec  rsa4096/9B93CB47F954FB53``
 | ``    created: 2017-04-26  expires: never       usage: SC  ``
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb* rsa4096/49EE12B0F5CBDF26``
 | ``     created: 2017-04-26  expires: never       usage: E   ``
 | ``[ultimate] (1). RSA 4096``

**Say goobye with saving!**

 | ``gpg> `` *save*

**check**

 | ``$ gpg2 --edit-keys cedric``
 | ``gpg: error reading key: No public key``
 | ``gnuk@Lulu:~$ /opt/gnupg2.1.19/bin/gpg2 --edit-key "RSA 4096"``
 | ``gpg (GnuPG) 2.1.19; Copyright (C) 2017 Free Software Foundation, Inc.``
 | ``This is free software: you are free to change and redistribute it.``
 | ``There is NO WARRANTY, to the extent permitted by law.``
 | ````
 | ``Secret key is available.``
 | ````
 | ``sec  rsa4096/9B93CB47F954FB53``
 | ``     created: 2017-04-26  expires: never       usage: SC  ``
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa4096/49EE12B0F5CBDF26``
 | ``     created: 2017-04-26  expires: never       usage: E   ``
 | ``    card-no: 2C97 7BB895B9``
 | ``[ultimate] (1). RSA 4096``
 | ````
 | ``gpg> `` *quit*


The encryption key is now associated with a card.

Decrypting and Signing
~~~~~~~~~~~~~~~~~~~~~~


Decrypting and Signing will act exactly the same way as if keys were not on
the card. The only difference is ``gpg`` will request the PIN code instead 
of the passphrase. 


SSH
---


Overview
~~~~~~~~

In order to use gpg for SSH authentication, an "authentication" is needed.
There are two solutions for that, either generate one on the device 
or add an authentication sub-key to your existing master gpg key.

Once done, it is necessary to configure ssh to point to the right key and
delegate the authentication to *gpg-ssg-agent* instead of *ssh-agent*.


Generate new key on device
~~~~~~~~~~~~~~~~~~~~~~~~~~

The important thing to keep in mind here is there is no way to tell gpg to
only generate the authentication key. So generating this key will also
generate the two other under a new identity and will erase existing keys 
on the current slot on the device.

Nevertheless, if you want to use a different identity for ssh login, you can use
another slot on the device. See `Nano S OpenPGP Card application explained`_
and `Generate new key pair`_.


Add sub-key
~~~~~~~~~~~

**Edit pgp key set**

 | ``$ gpg --expert --edit-key  cedric``
 | ``gpg (GnuPG) 2.1.15; Copyright (C) 2016 Free Software Foundation, Inc.``
 | ``This is free software: you are free to change and redistribute it.``
 | ``There is NO WARRANTY, to the extent permitted by law.``

 | ``Secret key is available.``

 | ``sec  rsa2048/831415DA94A9A15C``
 | ``     created: 2017-08-25  expires: never       usage: SC  ``
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa2048/8E95F2999EEC38C4``
 | ``     created: 2017-08-25  expires: never       usage: E     ``
 | ``[ultimate] (1). cedric``

**Add sub key**

 | ``gpg> *addkey*``

 | ``Please select what kind of key you want:``
 | ``   (3) DSA (sign only)``
 | ``   (4) RSA (sign only)``
 | ``   (5) Elgamal (encrypt only)``
 | ``   (6) RSA (encrypt only)``
 | ``   (7) DSA (set your own capabilities)``
 | ``   (8) RSA (set your own capabilities)``
 | ``  (10) ECC (sign only)``
 | ``  (11) ECC (set your own capabilities)``
 | ``  (12) ECC (encrypt only)``
 | ``  (13) Existing key``
 | ``Your selection? 8``

**Toggle sign/encrypt OFF, Toggle authentication ON**

 | ``Possible actions for a RSA key: Sign Encrypt Authenticate ``
 | ``Current allowed actions: Sign Encrypt ``

 | ``   (S) Toggle the sign capability``
 | ``   (E) Toggle the encrypt capability``
 | ``   (A) Toggle the authenticate capability``
 | ``   (Q) Finished``

 | ``Your selection?`` *S*

 | ``Possible actions for a RSA key: Sign Encrypt Authenticate ``
 | ``Current allowed actions: Encrypt ``

 | ``   (S) Toggle the sign capability``
 | ``   (E) Toggle the encrypt capability``
 | ``   (A) Toggle the authenticate capability``
 | ``   (Q) Finished``

 | ``Your selection?`` *E*

 | ``Possible actions for a RSA key: Sign Encrypt Authenticate ``
 | ``Current allowed actions: ``

 | ``   (S) Toggle the sign capability``
 | ``   (E) Toggle the encrypt capability``
 | ``   (A) Toggle the authenticate capability``
 | ``   (Q) Finished``

 | ``Your selection?`` *A*

 | ``Possible actions for a RSA key: Sign Encrypt Authenticate ``
 | ``Current allowed actions: Authenticate ``

 | ``   (S) Toggle the sign capability``
 | ``   (E) Toggle the encrypt capability``
 | ``   (A) Toggle the authenticate capability``
 | ``   (Q) Finished``

 | ``Your selection? Q``

**Set key options**

 | ``RSA keys may be between 1024 and 4096 bits long.``
 | ``What keysize do you want? (2048)`` *2048*
 | ``Requested keysize is 2048 bits``
 | ``Please specify how long the key should be valid.``
 | ``         0 = key does not expire``
 | ``      <n>  = key expires in n days``
 | ``      <n>w = key expires in n weeks``
 | ``      <n>m = key expires in n months``
 | ``      <n>y = key expires in n years``
 | ``Key is valid for? (0)`` *0*
 | ``Key does not expire at all``
 | ``Is this correct? (y/N)`` *y*
 | ``Really create? (y/N)`` *y*
 | ``We need to generate a lot of random bytes. It is a good idea to perform``
 | ``some other action (type on the keyboard, move the mouse, utilize the``
 | ``disks) during the prime generation; this gives the random number``
 | ``generator a better chance to gain enough entropy.``

 | ``sec  rsa2048/831415DA94A9A15C``
 | ``     created: 2017-08-25  expires: never       usage: SC `` 
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa2048/8E95F2999EEC38C4``
 | ``     created: 2017-08-25  expires: never       usage: E   ``
 | ``ssb  rsa2048/C20B90E12F68F035``
 | ``     created: 2017-08-28  expires: never       usage: A   ``
 | ``[ultimate] (1). cedric``

**Select the key and move it**

 | ``gpg> key`` *2*
 | ````
 | ``sec  rsa2048/831415DA94A9A15C``
 | ``     created: 2017-08-25  expires: never       usage: SC  ``
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa2048/8E95F2999EEC38C4``
 | ``    created: 2017-08-25  expires: never       usage: E   ``
 | ``ssb* rsa2048/C20B90E12F68F035``
 | ``     created: 2017-08-28  expires: never       usage: A   ``
 | ``[ultimate] (1). cedric``
 | ````
 | ``gpg>`` *keytocard*
 | ``Please select where to store the key:``
 | ``   (3) Authentication key``
 | ``Your selection?`` *3*
 | ``                 ``
 | ``sec  rsa2048/831415DA94A9A15C``
 | ``     created: 2017-08-25  expires: never       usage: SC  ``
 | ``     trust: ultimate      validity: ultimate``
 | ``ssb  rsa2048/8E95F2999EEC38C4``
 | ``     created: 2017-08-25  expires: never       usage: E   ``
 | ``ssb* rsa2048/C20B90E12F68F035``
 | ``     created: 2017-08-28  expires: never       usage: A ``  
 | ``[ultimate] (1). cedric``


**Save and Quit**

 | ``gpg>`` save
 | ``$ ``




Configure SSH and GPG
~~~~~~~~~~~~~~~~~~~~~


First, tell gpg-agent to enable ssh-auth feature by adding the following line
to your .gpg-agent.conf:

   ``enable-ssh-support``

Starting with gpg2 it necessary to add some configuration options to make the *pinentry* 
work properly. Add the following line to ~/.bashrc file:

 | ``export SSH_AUTH_SOCK=`gpgconf --list-dirs agent-ssh-socket` ``
 | ``export GPG_TTY=`tty` ``
 | ``gpgconf --launch gpg-agent ``


It may be also necessary to setup the loopback pinentry options.

Add the following line to your ~/.gnupg/gpg-agent.conf:

    ``allow-loopback-pinentry``

And add the following line to your ~/.gnupg/gpg.conf:

    ``pinentry-mode loopback``


Then export your authentication public key. First execute the 
``gpg -k --with-subkey-fingerprint --with-keygrip cedric`` command.


 | ``pub   rsa2048 2017-08-25 [SC]``
 | ``      7886147C4C2E5CE2A4B1546C831415DA94A9A15C``
 | ``      Keygrip = DE2B63C13AB92EBD2D05C1021A9DAA2D40ECB564``
 | ``uid           [ultimate] cedric``
 | ``sub   rsa2048 2017-08-25 [E]``
 | ``      789E56872A0D9A5AC8AF9C2F8E95F2999EEC38C4``
 | ``      Keygrip = 9D7C2EF8D84E3B31371A09DFD9A4B3EF72AB4ACE``
 | ``sub   rsa2048 2017-08-28 [A]``
 | ``      2D0E4FFFAA448AA2770C7F02C20B90E12F68F035``
 | ``      Keygrip = 6D60CB58D9D66EE09804E7FE460E865A91F5E41A``

Add the keygrip of the authentication key, the one identified by ``[A]``,
to .gnupg/sshcontrol file:

 | ``$ echo 6D60CB58D9D66EE09804E7FE460E865A91F5E41A > .gnupg/sshcontrol``

Export your authentication key, identifier by its fingerprint, in a SSH compliant format. 

 | ``$ gpg --export-ssh-key 2D0E4FFFAA448AA2770C7F02C20B90E12F68F035``
 | ``ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCIARKh0IZTHld+I6oA8nwrgnCUQE8f``
 | ``7X3pmI4ZwryT52fKhpcsQJsd3krodXrM//LiK8+m2ZRMneJ9iGlqqE7SCyZkNBj1GUm9s``
 | ``rK3Q5eoR6nU0s+sq17b/FAtQWHBJTqqaOtyA33hFj5twUtWZ6rokX9cNZrD1ne8kRVHDe``
 | ``3uEBsaY5PR1Tuko/GwywLyZu0SwfEobl/RPjL7P8rUSc7DTHpQMw8fjJFb4BNvIHAlaVC``
 | ``5FwZwkuogygaJdN/44MayHFmOZmzx9CAgYgLpTzen35+CcyhlqCqi+HjNlnHL2DDWd4iR``
 | ``d3Y6pY8LjS3xQkECc3Bhedptp17D+H9AVJt openpgp:0x2F68F035``
 
Finaly copy the above export (``ssh-rsa AAAAB...Jt openpgp:0x2F68F035``) into the 
~/.ssh/authorized_keys file on your remote server.


Now, if everything is correctly  setup and running, an ``ssh-add -l`` should show your key:

 | ``$ ssh-add -l``
 | ``2048 SHA256:sLCzsoi5GAG2kJkG6hSp8gTLPxSvo/zNtsks2kQ7vTU cardno:2C979421A9E1 (RSA)``
 | ``2048 SHA256:sLCzsoi5GAG2kJkG6hSp8gTLPxSvo/zNtsks2kQ7vTU (none) (RSA)``

And you should be able to ssh to your remote server with your gpg key!


Trouble/FAQ
-----------

**Q:** pinentry failed with a strange canceled message:

**R:** there is some problem with gpg2 and pinentry-gnome3. You may update your system
to use pinentry-gtk-2. Under Ubuntu-like OS, use ``update-alternatives --config pinentry``

 | ````

**Q:** gpg-connection agent failed

**R:** check that you don't have multiple running agents. After setting-up all SSH stuff, try to fully
logout/login

 | ````

**Q:** It does not work at all, HELP ME!!!

**R**  Please keep calm and do not cry. 
Add the following option to ~/.gnupg/gpg-agent.conf
 
 | ``debug-level guru``
 | ``log-file /tmp/gpgagent.log``

Add the follwing option to ~/.gnupg/scdaemon.conf
 
 | ``log-file /tmp/scd.log``
 | ``debug-level guru``
 | ``debug-all``

Make a nice issue report under github providing log and and command line you run.  
**!*WARNING*!** : this may reveal confidential information such as key values. Do your log with a test key.


Annexes
=======

References
----------

* [GPG]     *The GNU Privacy Guard*, https://gnupg.org/
* [GPGSC]   *The GnuPG Smartcard HOWTO*, https://gnupg.org/howtos/card-howto/en/smartcard-howto.html
* [G10CODE] *The OpenPGP card application*, https://g10code.com/p-card.html
* [GPGADD]  *The OpenPGP card application add-on*, https://github.com/LedgerHQ/blue-app-openpgp-card/blob/master/doc/gpgcard3.0-addon.rst
