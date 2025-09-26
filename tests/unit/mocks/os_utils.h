#pragma once

#define U2(hi, lo) ((((hi) &0xFFu) << 8) | ((lo) &0xFFu))
#define U4(hi3, hi2, lo1, lo0) \
    ((((hi3) &0xFFu) << 24) | (((hi2) &0xFFu) << 16) | (((lo1) &0xFFu) << 8) | ((lo0) &0xFFu))
static inline uint16_t U2BE(const uint8_t *buf, size_t off) {
    return (buf[off] << 8) | buf[off + 1];
}
static inline uint32_t U4BE(const uint8_t *buf, size_t off) {
    return (((uint32_t) buf[off]) << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) |
           buf[off + 3];
}

static inline void U2BE_ENCODE(uint8_t *buf, size_t off, uint32_t value) {
    buf[off + 0] = (value >> 8) & 0xFF;
    buf[off + 1] = value & 0xFF;
}
static inline void U4BE_ENCODE(uint8_t *buf, size_t off, uint32_t value) {
    buf[off + 0] = (value >> 24) & 0xFF;
    buf[off + 1] = (value >> 16) & 0xFF;
    buf[off + 2] = (value >> 8) & 0xFF;
    buf[off + 3] = value & 0xFF;
}
