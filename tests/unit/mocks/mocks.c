
#include "os.h"

unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len) {
    (void) channel_and_flags;
    (void) tx_len;
    return 0;
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    (void) dst_adr;
    (void) src_adr;
    (void) src_len;
    return;
}
