#include <stdlib.h>
#include <string.h>

#include "os_io_legacy.h"
#include "os_nvm.h"
#include "fake_io.h"

#define FAKE_IO_RX_FRAMES 8

unsigned char G_io_tx_buffer[OS_IO_BUFFER_SIZE + 1];

unsigned char fake_io_tx[OS_IO_BUFFER_SIZE + 1];
unsigned short fake_io_tx_len;
unsigned char fake_io_flags;

static struct {
    uint8_t data[OS_IO_BUFFER_SIZE + 1];
    size_t len;
} rx_frames[FAKE_IO_RX_FRAMES];
static size_t rx_count;
static size_t rx_next;

void fake_io_reset(void) {
    rx_count = 0;
    rx_next = 0;
    fake_io_tx_len = 0;
    fake_io_flags = 0;
}

void fake_io_push_rx(const uint8_t *frame, size_t len) {
    if ((rx_count >= FAKE_IO_RX_FRAMES) || (len > sizeof(rx_frames[0].data))) {
        abort();
    }
    memcpy(rx_frames[rx_count].data, frame, len);
    rx_frames[rx_count].len = len;
    rx_count++;
}

// Record the transmitted frame, then receive the next staged frame (0 when none is left)
unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len) {
    if (tx_len > sizeof(G_io_apdu_buffer)) {
        abort();
    }
    memcpy(fake_io_tx, G_io_apdu_buffer, tx_len);
    fake_io_tx_len = tx_len;
    fake_io_flags = channel_and_flags;
    if (rx_next >= rx_count) {
        return 0;
    }
    memcpy(G_io_apdu_buffer, rx_frames[rx_next].data, rx_frames[rx_next].len);
    return (unsigned short) rx_frames[rx_next++].len;
}

// Same semantics as the device: copy the source, or zero the destination for a NULL source
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (dst_adr == NULL) {
        abort();
    }
    if (src_adr == NULL) {
        memset(dst_adr, 0, src_len);
    } else {
        memmove(dst_adr, src_adr, src_len);
    }
}
