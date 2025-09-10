
#include <stdint.h>
#include <string.h>

#undef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define PRINTF(...)
#define THROW(x)

// send tx_len bytes (atr or rapdu) and retrieve the length of the next command apdu (over the
// requested channel)
#define CHANNEL_APDU       0
#define IO_RETURN_AFTER_TX 0x20
#define IO_ASYNCH_REPLY    0x10  // avoid apdu state reset if tx_len == 0 when we're expected to reply

#define IO_APDU_BUFFER_SIZE (255 + 5 + 64)

extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

extern unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len);
extern void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);
