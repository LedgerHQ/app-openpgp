#pragma once

#include <stddef.h>

// Toy SHA-256 and SHAKE256, plugged as CMock callbacks: the same input always gives the same output
void fake_digest_install(void);

// Output length in bits of the last SHAKE256
extern size_t fake_shake_bits;
