#pragma once

#include <stddef.h>
#include <stdint.h>

#include "os_io.h"

#define FAKE_IO_MAX_FRAMES 8

typedef struct {
    uint8_t data[OS_IO_BUFFER_SIZE + 1];
    size_t len;
    unsigned char flags;  // io_exchange() flags, for a transmitted frame
} fake_io_frame_t;

// Forget the staged frames and the recorded transmissions
void fake_io_reset(void);
// Stage a frame that a next io_exchange() receives
void fake_io_push_rx(const uint8_t *frame, size_t len);

// Frames transmitted by io_exchange(), in order, including empty ones
extern fake_io_frame_t fake_io_tx[FAKE_IO_MAX_FRAMES];
extern size_t fake_io_tx_count;
