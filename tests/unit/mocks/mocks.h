#pragma once

#include <stddef.h>
#include <stdint.h>

#include "os.h"

// Forget the staged frames and the recorded transmission
void mock_io_reset(void);
// Stage a frame that a next io_exchange() receives
void mock_io_push_rx(const uint8_t *frame, size_t len);

// Last frame transmitted by io_exchange(), and the flags it was called with
extern unsigned char mock_io_tx[IO_APDU_BUFFER_SIZE];
extern unsigned short mock_io_tx_len;
extern unsigned char mock_io_flags;
