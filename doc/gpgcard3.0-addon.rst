License
=======

Author: Cedric Mesnil <cslashm@gmail.com>

License:


  | Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
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

OpenPGP Card Application v3.0 add-ons summary
---------------------------------------------

Key management:
~~~~~~~~~~~~~~~

OpenPGP Application manage four keys for cryptographic operation (PSO) plus two
for secure channel.

The first four keys are defined as follow:
  - One asymmetric signature  private key (RSA or EC), named 'sig';
  - One asymmetric decryption private key (RSA or EC), named 'dec'
  - One asymmetric authentication private key (RSA or EC), named 'aut'
  - One symmetric decryption private key (AES), named 'sym0'

The 3 first asymmetric keys can be either randomly generated on-card or
explicitly put from outside.

The fourth is put from outside.

It's never possible to retrieve private key from the card.

This add-on specification propose a solution to derive those keys from the
master seed managed by the Ledger Token.
This allow owner to restore a broken token without the needs to keep track of keys
outside the card.

Moreover this add-on specification propose to manage multiple set of the
four previously described keys.

Random number generation
~~~~~~~~~~~~~~~~~~~~~~~~

OpenPGP Application provides, as optional feature, to generate random bytes.

This add-on specification propose new type of random generation:
- random prime number generation
- seeded random number
- seeded prime number generation


GPG-ledger
==========

Definitions
-----------

  - The application is named GPG-ledger
  - A  keys set is named 'keys slot'

How
---

Deterministic key derivation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The deterministic key derivation process relies on the BIP32 scheme.
The master install path of GPG-ledger is set to /0x80'GPG', aka /80475047

**Step1**:

For a given keys slot n, starting from 1, a seed is first derived with the following path

Sn = BIP32_derive (/0x80475047/n)

**Step2**:

Then specific seeds are derived with the SHA3-XOF function for each of the four key :

 Sk[i] = SHA3-XOF(SHA256(Sn \| <key_name> \| int16(i)), length)

Sn is the dedicated slot seed from step 1.
key_name is one of 'sig ','dec ', 'aut ', 'sym0', each four characters.
i is the index, starting from 1, of the desired seed (see below)


**Step 3**:

*RSA key are generated as follow* :

Generate two seed Sp, Sq in step2 with :
  - i € {1,2}
  - length equals to half key size

Generate two prime numbers p, q :
  - p = next_prime(Sp)
  - q = next_prime(Sq)

Generate RSA key pair as usual.
  - choose e
  - n = p*q
  - d = inv(e) mod (p-1)(q-1)

*ECC key genration* :

Generate one seed Sd in step2 with :
  - i = 1
  - length equals to curve size

Generate ECC key pair :
  - d = Sd
  - W = d.G


*AES key generation* :

Generate one seed Sd in step2 with :
  - i = 1
  - length equals to 16

Generate AES key :
  - k = Sk

Deterministic random number
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The deterministic random number generation relies on the BIP32 scheme.
The master install path of GPG-ledger is set to /0x80'GPG', aka /80475047

**Random prime number generation** :

 For a given length *L*:

  - generate random number r of *L* bytes.
  - generate rp = next_prime(r)
  - return rp

**Seeded random number** :

For a given length *L* and seed *S*:

  - generate Sr = BIP32_derive(/0x80475047/0x0F0F0F0F)
  - generate r = SHA3-XOF(SHA256(Sr \| 'rnd' \| S), L)
  - return r

**Seeded prime number generation** :

For a given length *L* and seed *S*:

  - generate r as for "Seeded random number"
  - generate rp = next_prime(r)
  - return rp


APDU Modification
-----------------

Key Slot management
~~~~~~~~~~~~~~~~~~~~

Key slots are managed by data object 01F1 and 01F2 witch are 
manageable by PUT/GET DATA command as for others DO and organized as follow.

On application reset, the *01F2* content is set to *Default Slot* value
of *01F1*.

*01F1:*

  +------+--------------------------------------------------+--------+
  |bytes |    description                                   |  R/W   |
  +======+==================================================+========+
  |   1  |  Number of slot                                  |  R     |
  +------+--------------------------------------------------+--------+
  |   2  |  Default slot                                    |  R/W   |
  +------+--------------------------------------------------+--------+
  |   3  |  Allowed slot selection method                   |  R/W   |
  +------+--------------------------------------------------+--------+

Byte 3 is endoced as follow:

  +----+----+----+----+----+----+----+----+-------------------------+
  | b8 | b7 | b6 | b5 | b4 | b3 | b2 | b1 | Meaning                 |
  +----+----+----+----+----+----+----+----+-------------------------+
  | \- | \- | \- | \- | \- | \- | \- | x  | selection by APDU       |
  +----+----+----+----+----+----+----+----+-------------------------+
  | \- | \- | \- | \- | \- | \- | x  | \- | selection by screen     |
  +----+----+----+----+----+----+----+----+-------------------------+

 
  

*01F2:*

  +------+--------------------------------------------------+--------+
  |bytes |  Description                                     |  R/W   |
  +======+==================================================+========+
  |   1  |  Current slot                                    |  R/W   |
  +------+--------------------------------------------------+--------+

*01F0:*

  +------+--------------------------------------------------+--------+
  |bytes |  Description                                     |  R/W   |
  +======+==================================================+========+
  |  1-3 |   01F1 content                                   |  R     |
  +------+--------------------------------------------------+--------+
  |   4  |   01F2 content                                   |  R     |
  +------+--------------------------------------------------+--------+


*Access Conditions:*

  +-------+------------+-------------+
  |   DO  |    Read    |    Write    |
  +=======+============+=============+
  |  01F0 |  Always    |    Never    |
  +-------+------------+-------------+
  |  01F1 |  Always    |  Verify PW3 |
  +-------+------------+-------------+
  |  01F2 |  Always    |  Verify PW1 |
  +-------+------------+-------------+



Deterministic key derivation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

P2 parameter of GENERATE ASYMMETRIC KEY PAIR is set to (hex value):
  - 00 for true random key generation
  - 01 for seeded random key


Deterministic random number
~~~~~~~~~~~~~~~~~~~~~~~~~~~

P1 parameter of GET CHALLENGE is a bits field encoded as follow:

  +----+-----+----+----+----+----+----+----+-------------------------+
  | b8 |  b7 | b6 | b5 | b4 | b3 | b2 | b1 | Meaning                 |
  +----+-----+----+----+----+----+----+----+-------------------------+
  | \- | \-  | \- | \- | \- | \- | \- | x  | prime random            |
  +----+-----+----+----+----+----+----+----+-------------------------+
  | \- | \-  | \- | \- | \- | \- |  x | \- | seeded random           |
  +----+-----+----+----+----+----+----+----+-------------------------+


When bit b2 is set, data field contains the seed and P2 contains
the length of random bytes to generate.


Other minor add-on
------------------

GnuPG use both fingerprints and serial number to identfy key on card.
So, the put data command accept to modify the AID file with '4F' tag.
In that case the data field shall be four bytes length and shall contain 
the new serial number. '4F' is protected by PW3 (admin) PIN.
