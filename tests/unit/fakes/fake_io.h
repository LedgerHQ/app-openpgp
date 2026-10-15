#pragma once

#include <stddef.h>
#include <stdint.h>

#include "os_io.h"

// Forget the staged frames and the recorded transmission
void fake_io_reset(void);
// Stage a frame that a next io_exchange() receives
void fake_io_push_rx(const uint8_t *frame, size_t len);

// Last frame transmitted by io_exchange(), and the flags it was called with
extern unsigned char fake_io_tx[OS_IO_BUFFER_SIZE + 1];
extern unsigned short fake_io_tx_len;
extern unsigned char fake_io_flags;
