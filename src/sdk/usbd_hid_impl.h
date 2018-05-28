#ifndef USBD_HID_IMPL_H
#define USBD_HID_IMPL_H

// ================================================
// HIDGEN

#define HID_INTF                      0

#define HID_EPIN_ADDR                 0x82
#define HID_EPIN_SIZE                 0x40

#define HID_EPOUT_ADDR                0x02
#define HID_EPOUT_SIZE                0x40

#ifdef HAVE_IO_U2F
// ================================================
// HID U2F

#define U2F_INTF                      1

#define U2F_EPIN_ADDR                 0x81
#define U2F_EPIN_SIZE                 0x40

#define U2F_EPOUT_ADDR                0x01
#define U2F_EPOUT_SIZE                0x40
#endif // HAVE_IO_U2F

#endif // USBD_HID_IMPL_H

