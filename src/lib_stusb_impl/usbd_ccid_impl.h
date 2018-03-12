#ifndef USBD_CCID_IMPL_H
#define USBD_CCID_IMPL_H

#ifdef HAVE_USB_CLASS_CCID

// ================================================
// CCID

#define TPDU_EXCHANGE                  0x01
#define SHORT_APDU_EXCHANGE            0x02
#define EXTENDED_APDU_EXCHANGE         0x04
#define CHARACTER_EXCHANGE             0x00

#define EXCHANGE_LEVEL_FEATURE         SHORT_APDU_EXCHANGE
  
#define CCID_INTF 2
#define CCID_BULK_IN_EP       0x83
#define CCID_BULK_EPIN_SIZE   64
#define CCID_BULK_OUT_EP      0x03
#define CCID_BULK_EPOUT_SIZE  64

#ifdef HAVE_CCID_INTERRUPT
#define CCID_INTR_IN_EP       0x84
#define CCID_INTR_EPIN_SIZE   16
#endif // HAVE_CCID_INTERRUPT

#define IO_CCID_DATA_BUFFER_SIZE IO_APDU_BUFFER_SIZE
#define G_io_ccid_data_buffer G_io_apdu_buffer

#endif // HAVE_USB_CLASS_CCID

#endif // USBD_CCID_IMPL_H
