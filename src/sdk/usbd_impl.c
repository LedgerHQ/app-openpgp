/**
  ******************************************************************************
  * @file    usbd_hid.c
  * @author  MCD Application Team
  * @version V2.2.0
  * @date    13-June-2014
  * @brief   This file provides the HID core functions.
  *
  * @verbatim
  *
  *          ===================================================================
  *                                HID Class  Description
  *          ===================================================================
  *           This module manages the HID class V1.11 following the "Device Class Definition
  *           for Human Interface Devices (HID) Version 1.11 Jun 27, 2001".
  *           This driver implements the following aspects of the specification:
  *             - The Boot Interface Subclass
  *             - Usage Page : Generic Desktop
  *             - Usage : Vendor
  *             - Collection : Application
  *
  * @note     In HS mode and when the DMA is used, all variables and data structures
  *           dealing with the DMA during the transaction process should be 32-bit aligned.
  *
  *
  *  @endverbatim
  *
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2014 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */
#pragma message "Override SDK source file :" __FILE__

#include "os.h"

#include "os_io_usb.h"

/* Includes ------------------------------------------------------------------*/

#include "usbd_hid.h"
#include "usbd_hid_impl.h"

#include "usbd_ctlreq.h"

#include "usbd_core.h"
#include "usbd_conf.h"

#include "usbd_def.h"
#include "os_io_seproxyhal.h"

#ifdef HAVE_IO_U2F
#include "u2f_transport.h"
#include "u2f_impl.h"
#endif // HAVE_IO_U2F

#ifdef HAVE_USB_CLASS_CCID
#include "usbd_ccid_core.h"
#endif // HAVE_USB_CLASS_CCID


/** @addtogroup STM32_USB_DEVICE_LIBRARY
  * @{
  */


/** @defgroup USBD_HID
  * @brief usbd core module
  * @{
  */

/** @defgroup USBD_HID_Private_TypesDefinitions
  * @{
  */
/**
  * @}
  */


/** @defgroup USBD_HID_Private_Defines
  * @{
  */

/**
  * @}
  */


/** @defgroup USBD_HID_Private_Macros
  * @{
  */
/**
  * @}
  */
/** @defgroup USBD_HID_Private_FunctionPrototypes
  * @{
  */


/**
  * @}
  */

/** @defgroup USBD_HID_Private_Variables
  * @{
  */

#define USBD_LANGID_STRING            0x409

#ifdef HAVE_VID_PID_PROBER
#define USBD_VID                      0x2581
#define USBD_PID                      0xf1d1
#else
#define USBD_VID                      0x2C97
#if defined(TARGET_BLUE)
#define USBD_PID                      0x0000
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  4*2+2,
  USB_DESC_TYPE_STRING,
  'B', 0,
  'l', 0,
  'u', 0,
  'e', 0,
};

#elif defined(TARGET_NANOS)
#ifndef HAVE_LEGACY_PID
#define USBD_PID                      0x1000
#else // HAVE_LEGACY_PID
#define USBD_PID                      0x0001
#endif // HAVE_LEGACY_PID
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'N', 0,
  'a', 0,
  'n', 0,
  'o', 0,
  ' ', 0,
  'S', 0,
};
#elif defined(TARGET_ARAMIS)
#ifndef HAVE_LEGACY_PID
#define USBD_PID                      0x2000
#else // HAVE_LEGACY_PID
#define USBD_PID                      0x0002
#endif // HAVE_LEGACY_PID
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'A', 0,
  'r', 0,
  'a', 0,
  'm', 0,
  'i', 0,
  's', 0,
};
#elif defined(TARGET_HW2)
#ifndef HAVE_LEGACY_PID
#define USBD_PID                      0x3000
#else // HAVE_LEGACY_PID
#define USBD_PID                      0x0003
#endif // HAVE_LEGACY_PID
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  3*2+2,
  USB_DESC_TYPE_STRING,
  'H', 0,
  'W', 0,
  '2', 0,
};
#elif defined(TARGET_NANOX)
#ifndef HAVE_LEGACY_PID
#define USBD_PID                      0x4000
#else // HAVE_LEGACY_PID
#define USBD_PID                      0x0004
#endif // HAVE_LEGACY_PID
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'N', 0,
  'a', 0,
  'n', 0,
  'o', 0,
  ' ', 0,
  'X', 0,
};
#elif defined(TARGET_NANOS2)
#ifndef HAVE_LEGACY_PID
#define USBD_PID                      0x5000
#else // HAVE_LEGACY_PID
#define USBD_PID                      0x0005
#endif // HAVE_LEGACY_PID
static uint8_t const USBD_PRODUCT_FS_STRING[] = {
  7*2+2,
  USB_DESC_TYPE_STRING,
  'N', 0,
  'a', 0,
  'n', 0,
  'o', 0,
  ' ', 0,
  'S', 0,
  'P', 0,
};
#else
#error unknown TARGET_ID
#endif
#endif

/* USB Standard Device Descriptor */
static uint8_t const USBD_LangIDDesc[]=
{
  USB_LEN_LANGID_STR_DESC,
  USB_DESC_TYPE_STRING,
  LOBYTE(USBD_LANGID_STRING),
  HIBYTE(USBD_LANGID_STRING),
};

static uint8_t const USB_SERIAL_STRING[] =
{
  4*2+2,
  USB_DESC_TYPE_STRING,
  '0', 0,
  '0', 0,
  '0', 0,
  '1', 0,
};

static uint8_t const USBD_MANUFACTURER_STRING[] = {
  6*2+2,
  USB_DESC_TYPE_STRING,
  'L', 0,
  'e', 0,
  'd', 0,
  'g', 0,
  'e', 0,
  'r', 0,
};

#define USBD_INTERFACE_FS_STRING USBD_PRODUCT_FS_STRING
#define USBD_CONFIGURATION_FS_STRING USBD_PRODUCT_FS_STRING

static uint8_t const HID_ReportDesc[] = {
  0x06, 0xA0, 0xFF,       // Usage page (vendor defined)
  0x09, 0x01,     // Usage ID (vendor defined)
  0xA1, 0x01,     // Collection (application)

  // The Input report
  0x09, 0x03,             // Usage ID - vendor defined
  0x15, 0x00,             // Logical Minimum (0)
  0x26, 0xFF, 0x00,   // Logical Maximum (255)
  0x75, 0x08,             // Report Size (8 bits)
  0x95, HID_EPIN_SIZE,             // Report Count (64 fields)
  0x81, 0x08,             // Input (Data, Variable, Absolute)

  // The Output report
  0x09, 0x04,             // Usage ID - vendor defined
  0x15, 0x00,             // Logical Minimum (0)
  0x26, 0xFF, 0x00,   // Logical Maximum (255)
  0x75, 0x08,             // Report Size (8 bits)
  0x95, HID_EPOUT_SIZE,             // Report Count (64 fields)
  0x91, 0x08,             // Output (Data, Variable, Absolute)
  0xC0
};

#ifdef HAVE_IO_U2F
static uint8_t const HID_ReportDesc_fido[] = {
  0x06, 0xD0, 0xF1,       // Usage page (vendor defined)
  0x09, 0x01,     // Usage ID (vendor defined)
  0xA1, 0x01,     // Collection (application)

  // The Input report
  0x09, 0x03,             // Usage ID - vendor defined
  0x15, 0x00,             // Logical Minimum (0)
  0x26, 0xFF, 0x00,   // Logical Maximum (255)
  0x75, 0x08,             // Report Size (8 bits)
  0x95, U2F_EPIN_SIZE,             // Report Count (64 fields)
  0x81, 0x08,             // Input (Data, Variable, Absolute)

  // The Output report
  0x09, 0x04,             // Usage ID - vendor defined
  0x15, 0x00,             // Logical Minimum (0)
  0x26, 0xFF, 0x00,   // Logical Maximum (255)
  0x75, 0x08,             // Report Size (8 bits)
  0x95, U2F_EPOUT_SIZE,             // Report Count (64 fields)
  0x91, 0x08,             // Output (Data, Variable, Absolute)
  0xC0
};
#endif // HAVE_IO_U2F

#define ARRAY_U2LE(l) (l)&0xFF, (l)>>8

/* USB HID device Configuration Descriptor */
static __ALIGN_BEGIN uint8_t const N_USBD_CfgDesc[] __ALIGN_END =
{
  0x09, /* bLength: Configuration Descriptor size */
  USB_DESC_TYPE_CONFIGURATION, /* bDescriptorType: Configuration */
  ARRAY_U2LE(0x9  /* wTotalLength: Bytes returned */
   +0x9+0x9+0x7+0x7
#ifdef HAVE_IO_U2F
   +0x9+0x9+0x7+0x7
#endif // HAVE_IO_U2F
#ifdef HAVE_USB_CLASS_CCID
   +0x9+0x36+0x7+0x7
#endif // HAVE_USB_CLASS_CCID
#ifdef HAVE_WEBUSB
   +0x9+0x7+0x7
#endif // HAVE_WEBUSB
   ),
  1
#ifdef HAVE_IO_U2F
  +1
#endif // HAVE_IO_U2F
#ifdef HAVE_USB_CLASS_CCID
  +1
#endif // HAVE_USB_CLASS_CCID
#ifdef HAVE_WEBUSB
  +1
#endif // HAVE_WEBUSB
  ,         /*bNumInterfaces */
  0x01,         /*bConfigurationValue: Configuration value*/
  USBD_IDX_PRODUCT_STR, /*iConfiguration: Index of string descriptor describing the configuration*/
  0xC0,         /*bmAttributes: bus powered */
  0x32,         /*MaxPower 100 mA: this current is used for detecting Vbus*/

  /* HIDGEN ################################################################################################ */

  /************** Descriptor of KBD HID interface ****************/
  0x09,         /*bLength: Interface Descriptor size*/
  USB_DESC_TYPE_INTERFACE,/*bDescriptorType: Interface descriptor type*/
  HID_INTF,         /*bInterfaceNumber: Number of Interface*/
  0x00,         /*bAlternateSetting: Alternate setting*/
  0x02,         /*bNumEndpoints*/
  0x03,         /*bInterfaceClass: HID*/
  0x00,         /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
  0x00,         /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
  USBD_IDX_PRODUCT_STR,            /*iInterface: Index of string descriptor*/

  /******************** Descriptor of HID *************************/
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bHIDUSTOM_HID: HID Class Spec release number*/
  0x01,
  0x00,         /*bCountryCode: Hardware target country*/
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  sizeof(HID_ReportDesc),/*wItemLength: Total length of Report descriptor*/
  0x00,

  /******************** Descriptor of Custom HID endpoints ********************/
  0x07,          /*bLength: Endpoint Descriptor size*/
  USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
  HID_EPIN_ADDR,     /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,          /*bmAttributes: Interrupt endpoint*/
  HID_EPIN_SIZE, /*wMaxPacketSize: 2 Byte max */
  0x00,
  0x01,          /*bInterval: Polling Interval (20 ms)*/

  0x07,          /* bLength: Endpoint Descriptor size */
  USB_DESC_TYPE_ENDPOINT, /* bDescriptorType: */
  HID_EPOUT_ADDR,  /*bEndpointAddress: Endpoint Address (OUT)*/
  0x03, /* bmAttributes: Interrupt endpoint */
  HID_EPOUT_SIZE,  /* wMaxPacketSize: 2 Bytes max  */
  0x00,
  0x01, /* bInterval: Polling Interval (20 ms) */

#ifdef HAVE_IO_U2F
  /* HID FIDO ################################################################################################ */

  /************** Descriptor of HID FIDO interface ****************/
  0x09,         /*bLength: Interface Descriptor size*/
  USB_DESC_TYPE_INTERFACE,/*bDescriptorType: Interface descriptor type*/
  U2F_INTF,         /*bInterfaceNumber: Number of Interface*/
  0x00,         /*bAlternateSetting: Alternate setting*/
  0x02,         /*bNumEndpoints*/
  0x03,         /*bInterfaceClass: HID*/
  0x01,         /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
  0x01,         /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
  USBD_IDX_PRODUCT_STR,            /*iInterface: Index of string descriptor*/

  /******************** Descriptor of HID *************************/
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bHIDUSTOM_HID: HID Class Spec release number*/
  0x01,
  0x21,         /*bCountryCode: Hardware target country*/ // 0x21: US, 0x08: FR, 0x0D: ISO Intl
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  sizeof(HID_ReportDesc_fido),/*wItemLength: Total length of Report descriptor*/
  0x00,
  /******************** Descriptor of Custom HID endpoints ********************/
  0x07,          /*bLength: Endpoint Descriptor size*/
  USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
  U2F_EPIN_ADDR,     /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,          /*bmAttributes: Interrupt endpoint*/
  U2F_EPIN_SIZE, /*wMaxPacketSize: */
  0x00,
  0x01,          /*bInterval: Polling Interval */

  0x07,          /* bLength: Endpoint Descriptor size */
  USB_DESC_TYPE_ENDPOINT, /* bDescriptorType: */
  U2F_EPOUT_ADDR,  /*bEndpointAddress: Endpoint Address (OUT)*/
  0x03, /* bmAttributes: Interrupt endpoint */
  U2F_EPOUT_SIZE,  /* wMaxPacketSize: */
  0x00,
  0x01,/* bInterval: Polling Interval */
#endif // HAVE_IO_U2F

#ifdef HAVE_USB_CLASS_CCID
  /* CCID ################################################################################################ */

  /********************  CCID **** interface ********************/
  0x09,   /* bLength: Interface Descriptor size */
  0x04,   /* bDescriptorType: */
  CCID_INTF,   /* bInterfaceNumber: Number of Interface */
  0x00,   /* bAlternateSetting: Alternate setting */
  0x02,   /* bNumEndpoints: endpoints used */
  0x0B,   /* bInterfaceClass: user's interface for CCID */
  0x00,   /* bInterfaceSubClass : */
  0x00,   /* nInterfaceProtocol : None */
  0x05,   /* iInterface: */

  /*******************  CCID class descriptor ********************/
  0x36,   /* bLength: CCID Descriptor size */
  0x21,   /* bDescriptorType: Functional Descriptor type. */
  0x10,   /* bcdCCID(LSB): CCID Class Spec release number (1.00) */
  0x01,   /* bcdCCID(MSB) */

  0x00,   /* bMaxSlotIndex :highest available slot on this device */
  0x03,   /* bVoltageSupport: bit Wise OR for 01h-5.0V 02h-3.0V
                                    04h 1.8V*/

  0x01,0x00,0x00,0x00,  /* dwProtocols: 0001h = Protocol T=0 */
  0x10,0x0E,0x00,0x00,  /* dwDefaultClock: 3.6Mhz = 3600kHz = 0x0E10,
                             for 4 Mhz the value is (0x00000FA0) :
                            This is used in ETU and waiting time calculations*/
  0x10,0x0E,0x00,0x00,  /* dwMaximumClock: Maximum supported ICC clock frequency
                             in KHz. So, 3.6Mhz = 3600kHz = 0x0E10,
                                           4 Mhz (0x00000FA0) : */
  0x00,     /* bNumClockSupported : no setting from PC
                             If the value is 00h, the
                            supported clock frequencies are assumed to be the
                            default clock frequency defined by dwDefaultClock
                            and the maximum clock frequency defined by
                            dwMaximumClock */

  0xCD,0x25,0x00,0x00,  /* dwDataRate: Default ICC I/O data rate in bps
                            9677 bps = 0x25CD
                            for example 10752 bps (0x00002A00) */

  0xCD,0x25,0x00,0x00,  /* dwMaxDataRate: Maximum supported ICC I/O data
                            rate in bps */
  0x00,                 /* bNumDataRatesSupported :
                         The number of data rates that are supported by the CCID
                         If the value is 00h, all data rates between the default
                         data rate dwDataRate and the maximum data rate
                         dwMaxDataRate are supported.
                         Dont support GET_CLOCK_FREQUENCIES
                        */
  //46
  0x00,0x00,0x00,0x00,   /* dwMaxIFSD: 0 (T=0 only)   */
  0x00,0x00,0x00,0x00,   /* dwSynchProtocols  */
  0x00,0x00,0x00,0x00,   /* dwMechanical: no special characteristics */

  0xBA, 0x06, 0x02, 0x00,
  //0x38,0x00,EXCHANGE_LEVEL_FEATURE,0x00,
                         /* dwFeatures: clk, baud rate, voltage : automatic */
                         /* 00000008h Automatic ICC voltage selection
                         00000010h Automatic ICC clock frequency change
                         00000020h Automatic baud rate change according to
                         active parameters provided by the Host or self
                         determined 00000100h CCID can set
                         ICC in clock stop mode

                         Only one of the following values may be present to
                         select a level of exchange:
                         00010000h TPDU level exchanges with CCID
                         00020000h Short APDU level exchange with CCID
                         00040000h Short and Extended APDU level exchange
                         If none of those values : character level of exchange*/
  0x0F,0x01,0x00,0x00,  /* dwMaxCCIDMessageLength: Maximum block size + header*/
                        /* 261 + 10   */

  0x00,     /* bClassGetResponse*/
  0x00,     /* bClassEnvelope */
  0x00,0x00,    /* wLcdLayout : 0000h no LCD. */
  0x00,     /* bPINSupport : no PIN verif and modif  */
  0x01,     /* bMaxCCIDBusySlots  */

  /********************  CCID   Endpoints ********************/
  0x07,   /*Endpoint descriptor length = 7*/
  0x05,   /*Endpoint descriptor type */
  CCID_BULK_IN_EP,   /*Endpoint address (IN, address 1) */
  0x02,   /*Bulk endpoint type */
  LOBYTE(CCID_BULK_EPIN_SIZE),
  HIBYTE(CCID_BULK_EPIN_SIZE),
  0x00,   /*Polling interval in milliseconds */

  0x07,   /*Endpoint descriptor length = 7 */
  0x05,   /*Endpoint descriptor type */
  CCID_BULK_OUT_EP,   /*Endpoint address (OUT, address 1) */
  0x02,   /*Bulk endpoint type */
  LOBYTE(CCID_BULK_EPOUT_SIZE),
  HIBYTE(CCID_BULK_EPOUT_SIZE),
  0x00,   /*Polling interval in milliseconds*/
#endif // HAVE_USB_CLASS_CCID

#ifdef HAVE_WEBUSB
  /* WEBUSB ################################################################################################ */

  /************** Descriptor of WEBUSB interface ****************/
  0x09,         /*bLength: Interface Descriptor size*/
  USB_DESC_TYPE_INTERFACE,/*bDescriptorType: Interface descriptor type*/
  WEBUSB_INTF,         /*bInterfaceNumber: Number of Interface*/
  0x00,         /*bAlternateSetting: Alternate setting*/
  0x02,         /*bNumEndpoints*/
  0xFF,         /*bInterfaceClass: WINUSB*/
  0xFF,         /*bInterfaceSubClass : WINUSB*/
  0xFF,         /*nInterfaceProtocol : WINUSB*/
  USBD_IDX_PRODUCT_STR,            /*iInterface: Index of string descriptor*/

  /******************** Descriptor of endpoints ********************/
  0x07,          /*bLength: Endpoint Descriptor size*/
  USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
  WEBUSB_EPIN_ADDR,     /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,          /*bmAttributes: Interrupt endpoint*/
  WEBUSB_EPIN_SIZE, /*wMaxPacketSize: */
  0x00,
  0x01,          /*bInterval: Polling Interval */

  0x07,          /* bLength: Endpoint Descriptor size */
  USB_DESC_TYPE_ENDPOINT, /* bDescriptorType: */
  WEBUSB_EPOUT_ADDR,  /*bEndpointAddress: Endpoint Address (OUT)*/
  0x03, /* bmAttributes: Interrupt endpoint */
  WEBUSB_EPOUT_SIZE,  /* wMaxPacketSize: */
  0x00,
  0x01,/* bInterval: Polling Interval */
#endif // HAVE_WEBUSB
} ;

#ifdef HAVE_IO_U2F
/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN uint8_t const USBD_HID_Desc_fido[] __ALIGN_END =
{
  /******************** Descriptor of HID *************************/
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bHIDUSTOM_HID: HID Class Spec release number*/
  0x01,
  0x21,         /*bCountryCode: Hardware target country*/ // 0x21: US, 0x08: FR, 0x0D: ISO Intl
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  sizeof(HID_ReportDesc_fido),/*wItemLength: Total length of Report descriptor*/
  0x00,
};
#endif // HAVE_IO_U2F

/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN uint8_t const USBD_HID_Desc[] __ALIGN_END =
{
  /* 18 */
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bHIDUSTOM_HID: HID Class Spec release number*/
  0x01,
  0x00,         /*bCountryCode: Hardware target country*/
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  sizeof(HID_ReportDesc),/*wItemLength: Total length of Report descriptor*/
  0x00,
};

/* USB Standard Device Descriptor */
static __ALIGN_BEGIN uint8_t const USBD_DeviceQualifierDesc[] __ALIGN_END =
{
  USB_LEN_DEV_QUALIFIER_DESC,
  USB_DESC_TYPE_DEVICE_QUALIFIER,
  0x00,
  0x02,
  0x00,
  0x00,
  0x00,
  0x40,
  0x01,
  0x00,
};

/* USB Standard Device Descriptor */
static uint8_t const USBD_DeviceDesc[]= {
  0x12,                       /* bLength */
  USB_DESC_TYPE_DEVICE,       /* bDescriptorType */
#ifdef HAVE_WEBUSB
  0x10,                       /* bcdUSB */
#else // HAVE_WEBUSB
  0x00,                       /* bcdUSB */
#endif // HAVE_WEBUSB
  0x02,
  0x00,                       /* bDeviceClass */
  0x00,                       /* bDeviceSubClass */
  0x00,                       /* bDeviceProtocol */
  USB_MAX_EP0_SIZE,           /* bMaxPacketSize */
  LOBYTE(USBD_VID),           /* idVendor */
  HIBYTE(USBD_VID),           /* idVendor */
#if defined(HAVE_VID_PID_PROBER) || defined(HAVE_LEGACY_PID)
  LOBYTE(USBD_PID),           /* idProduct */
#else  // HAVE_VID_PID_PROBER || defined(HAVE_LEGACY_PID)
  LOBYTE(USBD_PID | 0x01
#ifdef HAVE_IO_U2F
    | 0x04
#endif // HAVE_IO_U2F
#ifdef HAVE_USB_CLASS_CCID
    | 0x08
#endif // HAVE_USB_CLASS_CCID
#ifdef HAVE_WEBUSB
    | 0x10
#endif // HAVE_WEBUSB
  ),
#endif // HAVE_VID_PID_PROBER || HAVE_LEGACY_PID
  HIBYTE(USBD_PID),           /* idProduct */


  // Change this ID to make windows WINUSB/WEBUSB reenumerate when the
  // descriptor changes and the PID/VID are not changed.
  0x01,                       /* bcdDevice rel. 2.01 */
  0x02,
  USBD_IDX_MFC_STR,           /* Index of manufacturer string */
  USBD_IDX_PRODUCT_STR,       /* Index of product string */
  USBD_IDX_SERIAL_STR,        /* Index of serial number string */
  1                           /* bNumConfigurations */
}; /* USB_DeviceDescriptor */


/**
  * @brief  Returns the device descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_DeviceDesc);
  return (uint8_t*)USBD_DeviceDesc;
}

/**
  * @brief  Returns the LangID string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_LangIDDesc);
  return (uint8_t*)USBD_LangIDDesc;
}

/**
  * @brief  Returns the product string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_PRODUCT_FS_STRING);
  return (uint8_t*)USBD_PRODUCT_FS_STRING;
}

/**
  * @brief  Returns the manufacturer string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_MANUFACTURER_STRING);
  return (uint8_t*)USBD_MANUFACTURER_STRING;
}

/**
  * @brief  Returns the serial number string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USB_SERIAL_STRING);
  return (uint8_t*)USB_SERIAL_STRING;
}

/**
  * @brief  Returns the configuration string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_ConfigStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_CONFIGURATION_FS_STRING);
  return (uint8_t*)USBD_CONFIGURATION_FS_STRING;
}

/**
  * @brief  Returns the interface string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_InterfaceStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
  *length = sizeof(USBD_INTERFACE_FS_STRING);
  return (uint8_t*)USBD_INTERFACE_FS_STRING;
}

/**
* @brief  DeviceQualifierDescriptor
*         return Device Qualifier descriptor
* @param  length : pointer data length
* @retval pointer to descriptor buffer
*/
uint8_t  *USBD_GetDeviceQualifierDesc_impl (uint16_t *length)
{
  *length = sizeof (USBD_DeviceQualifierDesc);
  return (uint8_t*)USBD_DeviceQualifierDesc;
}

/**
  * @brief  USBD_CUSTOM_HID_GetCfgDesc
  *         return configuration descriptor
  * @param  speed : current device speed
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
uint8_t  *USBD_GetCfgDesc_impl (uint16_t *length)
{
  *length = sizeof (N_USBD_CfgDesc);
  return (uint8_t*)N_USBD_CfgDesc;
}

uint8_t* USBD_HID_GetHidDescriptor_impl(uint16_t* len) {
  switch (USBD_Device.request.wIndex&0xFF) {
#ifdef HAVE_IO_U2F
    case U2F_INTF:
      *len = sizeof(USBD_HID_Desc_fido);
      return (uint8_t*)USBD_HID_Desc_fido;
#endif // HAVE_IO_U2F
    case HID_INTF:
      *len = sizeof(USBD_HID_Desc);
      return (uint8_t*)USBD_HID_Desc;
  }
  *len = 0;
  return 0;
}

uint8_t* USBD_HID_GetReportDescriptor_impl(uint16_t* len) {
  switch (USBD_Device.request.wIndex&0xFF) {
#ifdef HAVE_IO_U2F
  case U2F_INTF:

    // very dirty work due to lack of callback when USB_HID_Init is called
    USBD_LL_OpenEP(&USBD_Device,
                   U2F_EPIN_ADDR,
                   USBD_EP_TYPE_INTR,
                   U2F_EPIN_SIZE);

    USBD_LL_OpenEP(&USBD_Device,
                   U2F_EPOUT_ADDR,
                   USBD_EP_TYPE_INTR,
                   U2F_EPOUT_SIZE);

    /* Prepare Out endpoint to receive 1st packet */
    USBD_LL_PrepareReceive(&USBD_Device, U2F_EPOUT_ADDR, U2F_EPOUT_SIZE);


    *len = sizeof(HID_ReportDesc_fido);
    return (uint8_t*)HID_ReportDesc_fido;
#endif // HAVE_IO_U2F
  case HID_INTF:
    *len = sizeof(HID_ReportDesc);
    return (uint8_t*)HID_ReportDesc;
  }
  *len = 0;
  return 0;
}

/**
  * @}
  */


/**
  * @brief  USBD_HID_DataOut
  *         handle data OUT Stage
  * @param  pdev: device instance
  * @param  epnum: endpoint index
  * @retval status
  *
  * This function is the default behavior for our implementation when data are sent over the out hid endpoint
  */

#ifdef HAVE_IO_U2F

/**
  * @brief  USBD_HID_Init
  *         Initialize the HID interface
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */
uint8_t  USBD_U2F_Init (USBD_HandleTypeDef *pdev,
                               uint8_t cfgidx)
{
  UNUSED(cfgidx);

  /* Open EP IN */
  USBD_LL_OpenEP(pdev,
                 U2F_EPIN_ADDR,
                 USBD_EP_TYPE_INTR,
                 U2F_EPIN_SIZE);

  /* Open EP OUT */
  USBD_LL_OpenEP(pdev,
                 U2F_EPOUT_ADDR,
                 USBD_EP_TYPE_INTR,
                 U2F_EPOUT_SIZE);

        /* Prepare Out endpoint to receive 1st packet */
  USBD_LL_PrepareReceive(pdev, U2F_EPOUT_ADDR, U2F_EPOUT_SIZE);

  return USBD_OK;
}

uint8_t  USBD_U2F_DataIn_impl (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  UNUSED(pdev);
  // only the data hid endpoint will receive data
  switch (epnum) {
  // FIDO endpoint
  case (U2F_EPIN_ADDR&0x7F):
    // advance the u2f sending machine state
    u2f_transport_sent(&G_io_u2f, U2F_MEDIA_USB);
    break;
  }
  return USBD_OK;
}

uint8_t  USBD_U2F_DataOut_impl (USBD_HandleTypeDef *pdev,
                              uint8_t epnum, uint8_t* buffer)
{
  switch (epnum) {
  // FIDO endpoint
  case (U2F_EPOUT_ADDR&0x7F):
      USBD_LL_PrepareReceive(pdev, U2F_EPOUT_ADDR , U2F_EPOUT_SIZE);
      u2f_transport_received(&G_io_u2f, buffer, io_seproxyhal_get_ep_rx_size(U2F_EPOUT_ADDR), U2F_MEDIA_USB);
    break;
  }

  return USBD_OK;
}
#endif // HAVE_IO_U2F

uint8_t  USBD_HID_DataIn_impl (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  UNUSED(pdev);
  switch (epnum) {
    // HID gen endpoint
    case (HID_EPIN_ADDR&0x7F):
      io_usb_hid_sent(io_usb_send_apdu_data);
      break;
  }

  return USBD_OK;
}

uint8_t  USBD_HID_DataOut_impl (USBD_HandleTypeDef *pdev,
                              uint8_t epnum, uint8_t* buffer)
{
  // only the data hid endpoint will receive data
  switch (epnum) {

  // HID gen endpoint
  case (HID_EPOUT_ADDR&0x7F):
    // prepare receiving the next chunk (masked time)
    USBD_LL_PrepareReceive(pdev, HID_EPOUT_ADDR , HID_EPOUT_SIZE);

    // avoid troubles when an apdu has not been replied yet
    if (G_io_app.apdu_media == IO_APDU_MEDIA_NONE) {
      // add to the hid transport
      switch(io_usb_hid_receive(io_usb_send_apdu_data, buffer, io_seproxyhal_get_ep_rx_size(HID_EPOUT_ADDR))) {
        default:
          break;

        case IO_USB_APDU_RECEIVED:
          G_io_app.apdu_media = IO_APDU_MEDIA_USB_HID; // for application code
          G_io_app.apdu_state = APDU_USB_HID; // for next call to io_exchange
          G_io_app.apdu_length = G_io_usb_hid_total_length;
          break;
      }
    }
    break;
  }

  return USBD_OK;
}

#ifdef HAVE_WEBUSB

uint8_t  USBD_WEBUSB_Init (USBD_HandleTypeDef *pdev,
                               uint8_t cfgidx)
{
  UNUSED(cfgidx);

  /* Open EP IN */
  USBD_LL_OpenEP(pdev,
                 WEBUSB_EPIN_ADDR,
                 USBD_EP_TYPE_INTR,
                 WEBUSB_EPIN_SIZE);

  /* Open EP OUT */
  USBD_LL_OpenEP(pdev,
                 WEBUSB_EPOUT_ADDR,
                 USBD_EP_TYPE_INTR,
                 WEBUSB_EPOUT_SIZE);

        /* Prepare Out endpoint to receive 1st packet */
  USBD_LL_PrepareReceive(pdev, WEBUSB_EPOUT_ADDR, WEBUSB_EPOUT_SIZE);

  return USBD_OK;
}

uint8_t  USBD_WEBUSB_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx) {
  UNUSED(pdev);
  UNUSED(cfgidx);
  return USBD_OK;
}

uint8_t  USBD_WEBUSB_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req)
{
  UNUSED(pdev);
  UNUSED(req);
  return USBD_OK;
}

uint8_t  USBD_WEBUSB_DataIn (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  UNUSED(pdev);
  switch (epnum) {
    // HID gen endpoint
    case (WEBUSB_EPIN_ADDR&0x7F):
      io_usb_hid_sent(io_usb_send_apdu_data_ep0x83);
      break;
  }
  return USBD_OK;
}

uint8_t USBD_WEBUSB_DataOut (USBD_HandleTypeDef *pdev,
                              uint8_t epnum, uint8_t* buffer)
{
  // only the data hid endpoint will receive data
  switch (epnum) {

  // HID gen endpoint
  case (WEBUSB_EPOUT_ADDR&0x7F):
    // prepare receiving the next chunk (masked time)
    USBD_LL_PrepareReceive(pdev, WEBUSB_EPOUT_ADDR, WEBUSB_EPOUT_SIZE);

    // avoid troubles when an apdu has not been replied yet
    if (G_io_app.apdu_media == IO_APDU_MEDIA_NONE) {
      // add to the hid transport
      switch(io_usb_hid_receive(io_usb_send_apdu_data_ep0x83, buffer, io_seproxyhal_get_ep_rx_size(WEBUSB_EPOUT_ADDR))) {
        default:
          break;

        case IO_USB_APDU_RECEIVED:
          G_io_app.apdu_media = IO_APDU_MEDIA_USB_WEBUSB; // for application code
          G_io_app.apdu_state = APDU_USB_WEBUSB; // for next call to io_exchange
          G_io_app.apdu_length = G_io_usb_hid_total_length;
          break;
      }
    }
    break;
  }

  return USBD_OK;
}
// arbitrary vendor choosen
#define WEBUSB_VENDOR_CODE 0x1E

// from https://wicg.github.io/webusb/#webusb-platform-capability-descriptor
// see also this (for endianness explanation)
// https://github.com/WICG/webusb/issues/115#issuecomment-352206549
#define WEBUSB_UUID 0x38, 0xB6, 0x08, 0x34, 0xA9, 0x09, 0xA0, 0x47,0x8B, 0xFD, 0xA0, 0x76, 0x88, 0x15, 0xB6, 0x65

#define WEBUSB_REQ_GET_URL             0x02

#define WEBUSB_DT_DESCRIPTOR_SET_HEADER 0
#define WEBUSB_DT_CONFIGURATION_SUBSET_HEADER 1
#define WEBUSB_DT_FUNCTION_SUBSET_HEADER 2
#define WEBUSB_DT_URL 3

#define WEBUSB_URL_SCHEME_HTTP 0
#define WEBUSB_URL_SCHEME_HTTPS 1
#define WEBUSB_URL_SCHEME_CUSTOM 255

unsigned char const C_webusb_url_descriptor[] = {
  // bLength
  3 + WEBUSB_URL_SIZE_B,
  // bDescriptorType
  WEBUSB_DT_URL,
  // bScheme
  WEBUSB_URL_SCHEME_HTTPS,
  // URL
  WEBUSB_URL
};

/* USB 3.1 Descriptor Types - Table 9-6 */
#define USB_DT_BOS            15
#define USB_DT_DEVICE_CAPABILITY    16

#define USB_DT_BOS_SIZE 5

/* USB Device Capability Types - USB 3.1 Table 9-14 */
#define USB_DC_PLATFORM         5

#define MS_OS_20_DESCRIPTOR_LENGTH (0xb2)

#define WINUSB_VENDOR_CODE 0x77

unsigned char const C_usb_bos[] = {
    USB_DT_BOS_SIZE, // bLength (5)
    USB_DT_BOS, // bDescriptorType
    0x39, 0x00, // wTotalLength
    2, //bNumberDeviceCapabilities

    // capability descriptor
    8+16, // bLength
    USB_DT_DEVICE_CAPABILITY, // bDescriptorType
    USB_DC_PLATFORM, // bDevCapability
    0, // bReserved
    WEBUSB_UUID, // UUID[16]
    0x00, // bcdVersion
    0x01,
    WEBUSB_VENDOR_CODE, // bVencordCode
#if WEBUSB_URL_SIZE_B > 0
    1, // iLandingPage
#else // WEBUSB_URL_SIZE_B
    0, // iLandingPage, no url to retrieve
#endif // WEBUSB_URL_SIZE_B

    // Microsoft OS 2.0 Platform Capability Descriptor
    0x1C, // Descriptor size (28 bytes)
    0x10, // Descriptor type (Device Capability)
    0x05, // Capability type (Platform)
    0x00, // Reserved

    // MS OS 2.0 Platform Capability ID (D8DD60DF-4589-4CC7-9CD2-659D9E648A9F)
    0xDF, 0x60, 0xDD, 0xD8,
    0x89, 0x45,
    0xC7, 0x4C,
    0x9C, 0xD2,
    0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F,

    0x00, 0x00, 0x03, 0x06, // Windows version (8.1) (0x06030000)
    MS_OS_20_DESCRIPTOR_LENGTH, 0x00,
    WINUSB_VENDOR_CODE, // Vendor-assigned bMS_VendorCode
    0x00               // Doesn’t support alternate enumeration
};
#endif // HAVE_WEBUSB
static uint8_t *USBD_BOSDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  UNUSED(speed);
#ifdef HAVE_WEBUSB
  *length = sizeof(C_usb_bos);
  return (uint8_t*)C_usb_bos;
#else
  *length = 0;
  return NULL;
#endif
}

/** @defgroup USBD_HID_Private_Functions
  * @{
  */

// note: how core lib usb calls the hid class
USBD_DescriptorsTypeDef const HID_Desc = {
  USBD_DeviceDescriptor,
  USBD_LangIDStrDescriptor,
  USBD_ManufacturerStrDescriptor,
  USBD_ProductStrDescriptor,
  USBD_SerialStrDescriptor,
  USBD_ConfigStrDescriptor,
  USBD_InterfaceStrDescriptor,
  USBD_BOSDescriptor,
};

#ifdef HAVE_IO_U2F
static USBD_ClassTypeDef const USBD_U2F =
{
  USBD_U2F_Init,
  USBD_HID_DeInit,
  USBD_HID_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/ /* STATUS STAGE IN */
  USBD_U2F_DataIn_impl, /*DataIn*/
  USBD_U2F_DataOut_impl, /*DataOut*/
  NULL, /*SOF */
  NULL,
  NULL,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetDeviceQualifierDesc_impl,
};
#endif // HAVE_IO_U2F

static USBD_ClassTypeDef const USBD_HID =
{
  USBD_HID_Init,
  USBD_HID_DeInit,
  USBD_HID_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/ /* STATUS STAGE IN */
  USBD_HID_DataIn_impl, /*DataIn*/
  USBD_HID_DataOut_impl, /*DataOut*/
  NULL, /*SOF */
  NULL,
  NULL,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetDeviceQualifierDesc_impl,
};

#ifdef HAVE_WEBUSB

static const unsigned char C_winusb_string_descriptor[] = {
  // bLength
  0x12,
  // bDescriptorType
  USB_DESC_TYPE_STRING,
  // wData
  'M', 0x00, 'S', 0x00, 'F', 0x00, 'T', 0x00, '1', 0x00, '0', 0x00, '0', 0x00, WINUSB_VENDOR_CODE, 0x00, // MSFT100<VCODE>
};

// Microsoft OS 2.0 descriptor wIndex values
#define MS_OS_20_DESCRIPTOR_INDEX 0x07

// Microsoft OS 2.0 descriptor types
#define MS_OS_20_SUBSET_HEADER_CONFIGURATION 0x01
#define MS_OS_20_SUBSET_HEADER_FUNCTION 0x02
#define MS_OS_20_FEATURE_COMPATIBLE_ID 0x03
#define MS_OS_20_FEATURE_REG_PROPERTY 0x04

static const unsigned char C_winusb_request_descriptor[] = {
    // Microsoft OS 2.0 descriptor set header (table 10)
    0x0A,
    0x00, // Descriptor size (10 bytes)
    0x00,
    0x00, // MS OS 2.0 descriptor set header
    0x00,
    0x00,
    0x03,
    0x06, // Windows version (8.1) (0x06030000)
    MS_OS_20_DESCRIPTOR_LENGTH,
    0x00, // Size, MS OS 2.0 descriptor set

    // Microsoft OS 2.0 configuration subset header
    0x08, 0x00,  // Descriptor size (8 bytes)
    MS_OS_20_SUBSET_HEADER_CONFIGURATION, 0x00,  // MS OS 2.0 configuration subset header
    0x00,        // bConfigurationValue
    0x00,        // Reserved
    0xA8, 0x00,  // Size, MS OS 2.0 configuration subset

    // Microsoft OS 2.0 function subset header
    0x08, 0x00,  // Descriptor size (8 bytes)
    MS_OS_20_SUBSET_HEADER_FUNCTION, 0x00,  // MS OS 2.0 function subset header
    WEBUSB_INTF,  // first Interface impacted by this function

    0x00,        // Reserved
    0xA0, 0x00,  // Size, MS OS 2.0 function subset

    // Microsoft OS 2.0 compatible ID descriptor (table 13)
    0x14, 0x00,  // wLength
    MS_OS_20_FEATURE_COMPATIBLE_ID, 0x00,  // MS_OS_20_FEATURE_COMPATIBLE_ID
    'W',  'I',  'N',  'U',  'S',  'B',  0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x84, 0x00,   //wLength:
    MS_OS_20_FEATURE_REG_PROPERTY, 0x00,   // wDescriptorType: MS_OS_20_FEATURE_REG_PROPERTY: 0x04 (Table 9)
    0x07, 0x00,   //wPropertyDataType: REG_MULTI_SZ (Table 15)
    0x2a, 0x00,   //wPropertyNameLength:
    //bPropertyName: “DeviceInterfaceGUID”
    'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00, 'I', 0x00, 'n', 0x00, 't', 0x00, 'e', 0x00,
    'r', 0x00, 'f', 0x00, 'a', 0x00, 'c', 0x00, 'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00, 'D', 0x00, 's', 0x00,
    0x00, 0x00,
    0x50, 0x00,   // wPropertyDataLength
    //bPropertyData: “{CE809264-4B24-4E81-A8B2-57ED01D580E1}”.
    '{', 0x00, 'C', 0x00, 'E', 0x00, '8', 0x00, '0', 0x00, '9', 0x00, '2', 0x00, '6', 0x00, '4', 0x00, '-', 0x00,
    '4', 0x00, 'B', 0x00, '2', 0x00, '4', 0x00, '-', 0x00, '4', 0x00, 'E', 0x00, '8', 0x00, '1', 0x00, '-', 0x00,
    'A', 0x00, '8', 0x00, 'B', 0x00, '2', 0x00, '-', 0x00, '5', 0x00, '7', 0x00, 'E', 0x00, 'D', 0x00, '0', 0x00,
    '1', 0x00, 'D', 0x00, '5', 0x00, '8', 0x00, '0', 0x00, 'E', 0x00, '1', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00
};

#define WINUSB_GET_COMPATIBLE_ID_FEATURE 0x04
static const unsigned char C_winusb_wcid[] = {
  // header
  0x28, 0x00, 0x00, 0x00,                    // dwLength
  0x00, 0x01,                                // bcdVersion
  0x04, 0x00,                                // wIndex
  0x01,                                      // bNumSections
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // reserved
  // functions
  WEBUSB_INTF,  // bInterfaceNumber
  0x01,  // reserved
  'W', 'I', 'N', 'U', 'S', 'B', 0x00, 0x00,  // compatibleId
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00,                                // subCompatibleId
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // reserved
};

#define WINUSB_GET_EXTENDED_PROPERTIES_OS_FEATURE 0x05
static const unsigned char C_winusb_guid[] = {
  // header
  0x92, 0x00, 0x00, 0x00,  // dwLength
  0x00, 0x01,              // bcdVersion
  0x05, 0x00,              // wIndex
  0x01, 0x00,              // wNumFeatures
  // features
  0x88, 0x00, 0x00, 0x00,  // dwLength
  0x07, 0x00, 0x00, 0x00,  // dwPropertyDataType
  0x2A, 0x00,              // wNameLength
  'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00,
  'I', 0x00, 'n', 0x00, 't', 0x00, 'e', 0x00, 'r', 0x00, 'f', 0x00,
  'a', 0x00, 'c', 0x00, 'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00,
  'D', 0x00, 's', 0x00, 0x00, 0x00, // .name, unicode nul terminated
  0x50, 0x00, 0x00, 0x00,            // dwPropertyDataLength
  // Same as BLE char: 13d63400-2C97-0004-0000-4c6564676572
  '{', 0x00, '1', 0x00, '3', 0x00, 'd', 0x00, '6', 0x00, '3', 0x00,
  '4', 0x00, '0', 0x00, '0', 0x00, '-', 0x00, '2', 0x00, 'C', 0x00,
  '9', 0x00, '7', 0x00, '-', 0x00, '0', 0x00, '0', 0x00, '0', 0x00,
  '4', 0x00, '-', 0x00, '0', 0x00, '0', 0x00, '0', 0x00, '0', 0x00,
  '-', 0x00, '4', 0x00, 'c', 0x00, '6', 0x00, '5', 0x00, '6', 0x00,
  '4', 0x00, '6', 0x00, '7', 0x00, '6', 0x00, '5', 0x00, '7', 0x00,
  '2', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00 // propertyData, double unicode nul terminated
};

// upon unsupported request, check for webusb request
void USBD_CtlError( USBD_HandleTypeDef *pdev , USBD_SetupReqTypedef *req) {
#if WEBUSB_URL_SIZE_B > 0
  if ((req->bmRequest & 0x80) && req->bRequest == WEBUSB_VENDOR_CODE && req->wIndex == WEBUSB_REQ_GET_URL
    // HTTPS url
    && req->wValue == 1) {
    // return the URL descriptor
    USBD_CtlSendData (pdev, (unsigned char*)C_webusb_url_descriptor, MIN(req->wLength, sizeof(C_webusb_url_descriptor)));
  }
  else
#endif // WEBUSB_URL_SIZE_B
    // SETUP (LE): 0x80 0x06 0x03 0x77 0x00 0x00 0xXX 0xXX
    if ((req->bmRequest & 0x80)
    && req->bRequest == USB_REQ_GET_DESCRIPTOR
    && (req->wValue>>8) == USB_DESC_TYPE_STRING
    && (req->wValue & 0xFF) == 0xEE) {
    USBD_CtlSendData(pdev, (unsigned char*)C_winusb_string_descriptor, MIN(req->wLength, sizeof(C_winusb_string_descriptor)));
  }
  // SETUP (LE): 0x80 0x77 0x04 0x00 0x00 0x00 0xXX 0xXX
  else if ((req->bmRequest & 0x80)
    && req->bRequest == WINUSB_VENDOR_CODE
    && req->wIndex == WINUSB_GET_COMPATIBLE_ID_FEATURE) {
    USBD_CtlSendData(pdev, (unsigned char*)C_winusb_wcid, MIN(req->wLength, sizeof(C_winusb_wcid)));
  }
  // SETUP (LE): 0x80 0x77 0x05 0x00 0x00 0x00 0xXX 0xXX
  else if ((req->bmRequest & 0x80)
    && req->bRequest == WINUSB_VENDOR_CODE
    && req->wIndex == WINUSB_GET_EXTENDED_PROPERTIES_OS_FEATURE
  ) {
    USBD_CtlSendData(pdev, (unsigned char*)C_winusb_guid, MIN(req->wLength, sizeof(C_winusb_guid)));
  }
  // Microsoft OS 2.0 Descriptors for Windows 8.1 and Windows 10
  else if ((req->bmRequest & 0x80)
      && req->bRequest == WINUSB_VENDOR_CODE
      && req->wIndex == MS_OS_20_DESCRIPTOR_INDEX) {
    USBD_CtlSendData(pdev, (unsigned char*)C_winusb_request_descriptor, MIN(req->wLength, sizeof(C_winusb_request_descriptor)));
  }
  else {
    USBD_CtlStall(pdev);
  }
}

static const USBD_ClassTypeDef USBD_WEBUSB =
{
  USBD_WEBUSB_Init,
  USBD_WEBUSB_DeInit,
  USBD_WEBUSB_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/
  USBD_WEBUSB_DataIn,
  USBD_WEBUSB_DataOut,
  NULL, /*SOF */
  NULL, /*ISOIn*/
  NULL, /*ISOOut*/
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetDeviceQualifierDesc_impl,
};

#endif // HAVE_WEBUSB

#ifdef HAVE_USB_CLASS_CCID
static const USBD_ClassTypeDef USBD_CCID =
{
  USBD_CCID_Init,
  USBD_CCID_DeInit,
  USBD_CCID_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/
  USBD_CCID_DataIn,
  USBD_CCID_DataOut,
  NULL, /*SOF */
  NULL, /*ISOIn*/
  NULL, /*ISOOut*/
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetCfgDesc_impl,
  USBD_GetDeviceQualifierDesc_impl,
};

uint8_t SC_AnswerToReset (uint8_t voltage, uint8_t* atr_buffer) {
  UNUSED(voltage);
  // return the atr length
  atr_buffer[0] = 0x3B;
  atr_buffer[1] = 0;
  return 2;
}

void SC_Poweroff(void) {
  // nothing to do ?
}

uint8_t SC_ExecuteEscape (uint8_t* escapePtr, uint32_t escapeLen,
                          uint8_t* responseBuff,
                          uint16_t* responseLen) {
  UNUSED(escapePtr);
  UNUSED(escapeLen);
  UNUSED(responseBuff);
  UNUSED(responseLen);
  // nothing to do ?
  return 0;
}
#endif // HAVE_USB_CLASS_CCID

void USB_power(unsigned char enabled) {
  os_memset(&USBD_Device, 0, sizeof(USBD_Device));

//#if TARGET_ID == 0x33000004
  // init timeouts and other global fields
  os_memset(G_io_app.usb_ep_xfer_len, 0, sizeof(G_io_app.usb_ep_xfer_len));
  os_memset(G_io_app.usb_ep_timeouts, 0, sizeof(G_io_app.usb_ep_timeouts));
//#endif

  if (enabled) {
    os_memset(&USBD_Device, 0, sizeof(USBD_Device));
    /* Init Device Library */
    USBD_Init(&USBD_Device, (USBD_DescriptorsTypeDef*)&HID_Desc, 0);

    /* Register the HID class */
    USBD_RegisterClassForInterface(HID_INTF,  &USBD_Device, (USBD_ClassTypeDef*)&USBD_HID);
#ifdef HAVE_IO_U2F
    USBD_RegisterClassForInterface(U2F_INTF,  &USBD_Device, (USBD_ClassTypeDef*)&USBD_U2F);
    // initialize the U2F tunnel transport
    u2f_transport_init(&G_io_u2f, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
#endif // HAVE_IO_U2F
#ifdef HAVE_USB_CLASS_CCID
    USBD_RegisterClassForInterface(CCID_INTF, &USBD_Device, (USBD_ClassTypeDef*)&USBD_CCID);
#endif // HAVE_USB_CLASS_CCID

#ifdef HAVE_WEBUSB
    USBD_RegisterClassForInterface(WEBUSB_INTF, &USBD_Device, (USBD_ClassTypeDef*)&USBD_WEBUSB);
    USBD_LL_PrepareReceive(&USBD_Device, WEBUSB_EPOUT_ADDR , WEBUSB_EPOUT_SIZE);
#endif // HAVE_WEBUSB

    /* Start Device Process */
    USBD_Start(&USBD_Device);
  }
  else {
    USBD_DeInit(&USBD_Device);
  }
}

/**
  * @}
  */


/**
  * @}
  */


/**
  * @}
  */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
