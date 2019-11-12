/**
  ******************************************************************************
  * @file    usbd_ccid_if.c
  * @author  MCD Application Team
  * @version V1.0.1
  * @date    31-January-2014
  * @brief   This file provides all the functions for USB Interface for CCID
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

/* Includes ------------------------------------------------------------------*/
#include "os.h"

#ifdef HAVE_USB_CLASS_CCID

#include "usbd_ccid_if.h"

#if CCID_BULK_EPIN_SIZE > USB_SEGMENT_SIZE
  #error configuration error, the USB MAX SEGMENT SIZE does not support the CCID endpoint (CCID_BULK_EPIN_SIZE vs USB_SEGMENT_SIZE)
#endif

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
usb_class_ccid_t G_io_ccid;

/* Private function prototypes -----------------------------------------------*/
static void CCID_Response_SendData (USBD_HandleTypeDef  *pdev,
                              uint8_t* pbuf,
                              uint16_t len);
/* Private function ----------------------------------------------------------*/
/**
  * @brief  CCID_Init
  *         Initialize the CCID USB Layer
  * @param  pdev: device instance
  * @retval None
  */
void CCID_Init (USBD_HandleTypeDef  *pdev)
{
  memset(&G_io_ccid, 0, sizeof(G_io_ccid));

  /* CCID Related Initialization */
#ifdef HAVE_CCID_INTERRUPT
  CCID_SetIntrTransferStatus(1);  /* Transfer Complete Status */
#endif // HAVE_CCID_INTERRUPT
  CCID_UpdSlotChange(1);
  SC_InitParams();

  /* Prepare Out endpoint to receive 1st packet */
  G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;
  USBD_LL_PrepareReceive(pdev, CCID_BULK_OUT_EP, CCID_BULK_EPOUT_SIZE);

  // send the smartcard as inserted state at boot time
  io_usb_ccid_set_card_inserted(1);
}

/**
  * @brief  CCID_DeInit
  *         Uninitialize the CCID Machine
  * @param  pdev: device instance
  * @retval None
  */
void CCID_DeInit (USBD_HandleTypeDef  *pdev)
{
   UNUSED(pdev);
   G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;
}

/**
  * @brief  CCID_Message_In
  *         Handle Bulk IN & Intr IN data stage
  * @param  pdev: device instance
  * @param  uint8_t epnum: endpoint index
  * @retval None
  */
void CCID_BulkMessage_In (USBD_HandleTypeDef  *pdev,
                     uint8_t epnum)
{
  if (epnum == (CCID_BULK_IN_EP & 0x7F))
  {/* Filter the epnum by masking with 0x7f (mask of IN Direction)  */

    /*************** Handle Bulk Transfer IN data completion  *****************/

    switch (G_io_ccid.Ccid_BulkState)
    {
    case CCID_STATE_SEND_RESP: {
      unsigned int remLen = G_io_ccid.UsbMessageLength;

      // advance with acknowledged sent chunk
      if (G_io_ccid.pUsbMessageBuffer == &G_io_ccid.bulk_header) {
        // first part of the bulk in sent.
        // advance in the data buffer to transmit. (mixed source leap)
        G_io_ccid.pUsbMessageBuffer = G_io_ccid_data_buffer+MIN(CCID_BULK_EPIN_SIZE, G_io_ccid.UsbMessageLength)-CCID_HEADER_SIZE;
      }
      else {
        G_io_ccid.pUsbMessageBuffer += MIN(CCID_BULK_EPIN_SIZE, G_io_ccid.UsbMessageLength);
      }
      G_io_ccid.UsbMessageLength -= MIN(CCID_BULK_EPIN_SIZE, G_io_ccid.UsbMessageLength);

      // if remaining length is > EPIN_SIZE: send a filled bulk packet
      if (G_io_ccid.UsbMessageLength >= CCID_BULK_EPIN_SIZE) {
        CCID_Response_SendData(pdev, G_io_ccid.pUsbMessageBuffer,
                                      // use the header declared size packet must be well formed
                                      CCID_BULK_EPIN_SIZE);
      }

      // if remaining length is 0; send an empty packet and prepare to receive a new command
      else if (G_io_ccid.UsbMessageLength == 0 && remLen == CCID_BULK_EPIN_SIZE) {
        CCID_Response_SendData(pdev, G_io_ccid.pUsbMessageBuffer,
                                      // use the header declared size packet must be well formed
                                      0);
        goto last_xfer; // won't wait ack to avoid missing a command
      }
      // else if no more data, then last packet sent, go back to idle (done on transfer ack)
      else if (G_io_ccid.UsbMessageLength == 0) { // robustness only
      last_xfer:
        G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;

        /* Prepare EP to Receive First Cmd */
        // not timeout compliant // USBD_LL_PrepareReceive(pdev, CCID_BULK_OUT_EP, CCID_BULK_EPOUT_SIZE);

        // mark transfer as completed
        G_io_app.apdu_state = APDU_IDLE;
      }

      // if remaining length is < EPIN_SIZE: send packet and prepare to receive a new command
      else if (G_io_ccid.UsbMessageLength < CCID_BULK_EPIN_SIZE) {
        CCID_Response_SendData(pdev, G_io_ccid.pUsbMessageBuffer,
                                      // use the header declared size packet must be well formed
                                      G_io_ccid.UsbMessageLength);
        goto last_xfer; // won't wait ack to avoid missing a command
      }

      break;
    }

    default:
      break;
    }
  }
#ifdef HAVE_CCID_INTERRUPT
  else if (epnum == (CCID_INTR_IN_EP & 0x7F))
  {
    /* Filter the epnum by masking with 0x7f (mask of IN Direction)  */
    CCID_SetIntrTransferStatus(1);  /* Transfer Complete Status */
  }
#endif // HAVE_CCID_INTERRUPT
}

void CCID_Send_Reply(USBD_HandleTypeDef  *pdev) {
  /********** Decide for all commands ***************/
  if (G_io_ccid.Ccid_BulkState == CCID_STATE_SEND_RESP)
  {
    G_io_ccid.UsbMessageLength = G_io_ccid.bulk_header.bulkin.dwLength+CCID_HEADER_SIZE;   /* Store for future use */

    /* Expected Data Length Packet Received */
    G_io_ccid.pUsbMessageBuffer = (uint8_t*) &G_io_ccid.bulk_header;

    // send bulk header and first pat of the message at once
    os_memmove(G_io_usb_ep_buffer, &G_io_ccid.bulk_header, CCID_HEADER_SIZE);
    if (G_io_ccid.UsbMessageLength>CCID_HEADER_SIZE) {
      // copy start of data if bigger size than a header
      os_memmove(G_io_usb_ep_buffer+CCID_HEADER_SIZE, G_io_ccid_data_buffer, MIN(CCID_BULK_EPIN_SIZE, G_io_ccid.UsbMessageLength)-CCID_HEADER_SIZE);
    }
    // send the first mixed source chunk
    CCID_Response_SendData(pdev, G_io_usb_ep_buffer,
                                  // use the header declared size packet must be well formed
                                  MIN(CCID_BULK_EPIN_SIZE, G_io_ccid.UsbMessageLength));
  }
}

/**
  * @brief  CCID_BulkMessage_Out
  *         Proccess CCID OUT data
  * @param  pdev: device instance
  * @param  uint8_t epnum: endpoint index
  * @retval None
  */
void CCID_BulkMessage_Out (USBD_HandleTypeDef  *pdev,
                           uint8_t epnum, uint8_t* buffer, uint16_t dataLen)
{
  if (epnum == (CCID_BULK_OUT_EP & 0x7F)) {
    switch (G_io_ccid.Ccid_BulkState)
    {

      // after a timeout, could be in almost any state :) therefore, clean it and process the newly received command
    default:
      G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;
      // no break is intentional

    case CCID_STATE_IDLE:
      // prepare to receive another packet later on (to avoid troubles with timeout due to other hid command timeouting the ccid endpoint reply)
      USBD_LL_PrepareReceive(pdev, CCID_BULK_OUT_EP, CCID_BULK_EPOUT_SIZE);

      if (dataLen == 0x00)
      { /* Zero Length Packet Received, end of transfer */
        G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;
      }
      else  if (dataLen >= CCID_HEADER_SIZE)
      {
        G_io_ccid.UsbMessageLength = dataLen;   /* Store for future use */

        /* Expected Data Length Packet Received */
        // endianness is little :) useful for our ARM convention
        G_io_ccid.pUsbMessageBuffer = (uint8_t*) &G_io_ccid.bulk_header;

        // copy the ccid bulk header only
        os_memmove(G_io_ccid.pUsbMessageBuffer, buffer, CCID_HEADER_SIZE);
        // copy remaining part in the data buffer (split from the ccid to allow for overlaying with another ressource buffer)
        if (dataLen>CCID_HEADER_SIZE) {
          os_memmove(G_io_ccid_data_buffer, buffer+CCID_HEADER_SIZE, dataLen-CCID_HEADER_SIZE);
          // we're now receiving in the data buffer (all subsequent calls)
          G_io_ccid.pUsbMessageBuffer = G_io_ccid_data_buffer;
        }

        if (G_io_ccid.bulk_header.bulkout.dwLength > IO_CCID_DATA_BUFFER_SIZE)
        { /* Check if length of data to be sent by host is > buffer size */

          /* Too long data received.... Error ! */
          G_io_ccid.Ccid_BulkState = CCID_STATE_UNCORRECT_LENGTH;
        }
        else
        // everything received in the first packet
        if (G_io_ccid.UsbMessageLength == (G_io_ccid.bulk_header.bulkout.dwLength + CCID_HEADER_SIZE)) {
          /* Short message, less than the EP Out Size, execute the command,
          if parameter like dwLength is too big, the appropriate command will
          give an error */
          CCID_CmdDecode(pdev);
        }
        else
        { /* Long message, receive additional data with command */
          G_io_ccid.Ccid_BulkState = CCID_STATE_RECEIVE_DATA;
          G_io_ccid.pUsbMessageBuffer += dataLen-CCID_HEADER_SIZE;  /* Point to new offset */
        }
      }
      break;

    case CCID_STATE_RECEIVE_DATA:

      USBD_LL_PrepareReceive(pdev, CCID_BULK_OUT_EP, CCID_BULK_EPOUT_SIZE);

      G_io_ccid.UsbMessageLength += dataLen;

      if (dataLen < CCID_BULK_EPOUT_SIZE)
      {/* Short message, less than the EP Out Size, execute the command,
          if parameter like dwLength is too big, the appropriate command will
          give an error */

        /* Full command is received, process the Command */
        os_memmove(G_io_ccid.pUsbMessageBuffer, buffer, dataLen);
        CCID_CmdDecode(pdev);
      }
      else //if (dataLen == CCID_BULK_EPOUT_SIZE)
      {
        if (G_io_ccid.UsbMessageLength < (G_io_ccid.bulk_header.bulkout.dwLength + CCID_HEADER_SIZE))
        {
          os_memmove(G_io_ccid.pUsbMessageBuffer, buffer, dataLen);
          G_io_ccid.pUsbMessageBuffer += dataLen;
          /* Increment the pointer to receive more data */

          /* Prepare EP to Receive next Cmd */
          // not timeout compliant // USBD_LL_PrepareReceive(pdev, CCID_BULK_OUT_EP, CCID_BULK_EPOUT_SIZE);
        }
        else if (G_io_ccid.UsbMessageLength == (G_io_ccid.bulk_header.bulkout.dwLength + CCID_HEADER_SIZE))
        {
          /* Full command is received, process the Command */
          os_memmove(G_io_ccid.pUsbMessageBuffer, buffer, dataLen);
          CCID_CmdDecode(pdev);
        }
        else
        {
          /* Too long data received.... Error ! */
          G_io_ccid.Ccid_BulkState = CCID_STATE_UNCORRECT_LENGTH;
        }
      }

      break;

    /*
    case CCID_STATE_UNCORRECT_LENGTH:
      G_io_ccid.Ccid_BulkState = CCID_STATE_IDLE;
      break;

    default:

      break;
    */
    }
  }
}

/**
  * @brief  CCID_CmdDecode
  *         Parse the commands and Proccess command
  * @param  pdev: device instance
  * @retval None
  */
void CCID_CmdDecode(USBD_HandleTypeDef  *pdev)
{
  uint8_t errorCode;

  switch (G_io_ccid.bulk_header.bulkout.bMessageType)
  {
  case PC_TO_RDR_ICCPOWERON:
    errorCode = PC_to_RDR_IccPowerOn();
    RDR_to_PC_DataBlock(errorCode);
    break;
  case PC_TO_RDR_ICCPOWEROFF:
    errorCode = PC_to_RDR_IccPowerOff();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_GETSLOTSTATUS:
    errorCode = PC_to_RDR_GetSlotStatus();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_XFRBLOCK:
    errorCode = PC_to_RDR_XfrBlock();
    // asynchronous // RDR_to_PC_DataBlock(errorCode);
    break;
  case PC_TO_RDR_GETPARAMETERS:
    errorCode = PC_to_RDR_GetParameters();
    RDR_to_PC_Parameters(errorCode);
    break;
  case PC_TO_RDR_RESETPARAMETERS:
    errorCode = PC_to_RDR_ResetParameters();
    RDR_to_PC_Parameters(errorCode);
    break;
  case PC_TO_RDR_SETPARAMETERS:
    errorCode = PC_to_RDR_SetParameters();
    RDR_to_PC_Parameters(errorCode);
    break;
  case PC_TO_RDR_ESCAPE:
    errorCode = PC_to_RDR_Escape();
    RDR_to_PC_Escape(errorCode);
    break;
  case PC_TO_RDR_ICCCLOCK:
    errorCode = PC_to_RDR_IccClock();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_ABORT:
    errorCode = PC_to_RDR_Abort();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_T0APDU:
    errorCode = PC_TO_RDR_T0Apdu();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_MECHANICAL:
    errorCode = PC_TO_RDR_Mechanical();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_SETDATARATEANDCLOCKFREQUENCY:
    errorCode = PC_TO_RDR_SetDataRateAndClockFrequency();
    RDR_to_PC_DataRateAndClockFrequency(errorCode);
    break;
  case PC_TO_RDR_SECURE:
    errorCode = PC_TO_RDR_Secure();
    // asynchronous // RDR_to_PC_DataBlock(errorCode);
    break;
  default:
    RDR_to_PC_SlotStatus(SLOTERROR_CMD_NOT_SUPPORTED);
    break;
  }

  CCID_Send_Reply(pdev);
}

/**
  * @brief  Transfer_Data_Request
  *         Prepare the request response to be sent to the host
  * @param  uint8_t* dataPointer: Pointer to the data buffer to send
  * @param  uint16_t dataLen : number of bytes to send
  * @retval None
  */
void Transfer_Data_Request(void)
{
   /**********  Update Global Variables ***************/
   G_io_ccid.Ccid_BulkState = CCID_STATE_SEND_RESP;
}


/**
  * @brief  CCID_Response_SendData
  *         Send the data on bulk-in EP
  * @param  pdev: device instance
  * @param  uint8_t* buf: pointer to data buffer
  * @param  uint16_t len: Data Length
  * @retval None
  */
static void  CCID_Response_SendData(USBD_HandleTypeDef  *pdev,
                              uint8_t* buf,
                              uint16_t len)
{
    UNUSED(pdev);
    // don't ask the MCU to perform bulk split, we could quickly get into a buffer overflow
    if (len > CCID_BULK_EPIN_SIZE) {
      THROW(EXCEPTION_IO_OVERFLOW);
    }

    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EP_PREPARE;
    G_io_seproxyhal_spi_buffer[1] = (3+len)>>8;
    G_io_seproxyhal_spi_buffer[2] = (3+len);
    G_io_seproxyhal_spi_buffer[3] = CCID_BULK_IN_EP;
    G_io_seproxyhal_spi_buffer[4] = SEPROXYHAL_TAG_USB_EP_PREPARE_DIR_IN;
    G_io_seproxyhal_spi_buffer[5] = len;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 6);
    io_seproxyhal_spi_send(buf, len);
}

#ifdef HAVE_CCID_INTERRUPT
/**
  * @brief  CCID_IntMessage
  *         Send the Interrupt-IN data to the host
  * @param  pdev: device instance
  * @retval None
  */
void CCID_IntMessage(USBD_HandleTypeDef  *pdev)
{
  UNUSED(pdev);
  /* Check if there us change in Smartcard Slot status */
  if ( CCID_IsSlotStatusChange() && CCID_IsIntrTransferComplete() )
  {
#ifdef HAVE_CCID_INTERRUPT
    /* Check Slot Status is changed. Card is Removed/ Fitted  */
    RDR_to_PC_NotifySlotChange();
#endif // HAVE_CCID_INTERRUPT

    CCID_SetIntrTransferStatus(0);  /* Reset the Status */
    CCID_UpdSlotChange(0);    /* Reset the Status of Slot Change */

    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_USB_EP_PREPARE;
    G_io_seproxyhal_spi_buffer[1] = (3+2)>>8;
    G_io_seproxyhal_spi_buffer[2] = (3+2);
    G_io_seproxyhal_spi_buffer[3] = CCID_INTR_IN_EP;
    G_io_seproxyhal_spi_buffer[4] = SEPROXYHAL_TAG_USB_EP_PREPARE_DIR_IN;
    G_io_seproxyhal_spi_buffer[5] = 2;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 6);
    io_seproxyhal_spi_send(G_io_ccid.UsbIntMessageBuffer, 2);
  }
}

/**
  * @brief  CCID_IsIntrTransferComplete
  *         Provides the status of previous Interrupt transfer status
  * @param  None
  * @retval uint8_t PrevXferComplete_IntrIn: Value of the previous transfer status
  */
uint8_t CCID_IsIntrTransferComplete (void)
{
  return G_io_ccid.PrevXferComplete_IntrIn;
}

/**
  * @brief  CCID_IsIntrTransferComplete
  *         Set the value of the Interrupt transfer status
  * @param  uint8_t xfer_Status: Value of the Interrupt transfer status to set
  * @retval None
  */
void CCID_SetIntrTransferStatus (uint8_t xfer_Status)
{
  G_io_ccid.PrevXferComplete_IntrIn = xfer_Status;
}
#endif // HAVE_CCID_INTERRUPT






uint8_t SC_Detect(void) {
  return G_io_ccid.ccid_card_inserted;
}

void SC_InitParams (void) {
  // nothing to do
}

uint8_t SC_SetParams (Protocol0_DataStructure_t* pt0) {
  UNUSED(pt0);
  return SLOT_NO_ERROR;
}


uint8_t SC_SetClock (uint8_t bClockCommand) {
  UNUSED(bClockCommand);
  return SLOT_NO_ERROR;
}

uint8_t SC_Request_GetClockFrequencies(uint8_t* pbuf, uint16_t* len);
uint8_t SC_Request_GetDataRates(uint8_t* pbuf, uint16_t* len);
uint8_t SC_T0Apdu(uint8_t bmChanges, uint8_t bClassGetResponse,
                  uint8_t bClassEnvelope) {
  UNUSED(bmChanges);
  UNUSED(bClassGetResponse);
  UNUSED(bClassEnvelope);
  return SLOTERROR_CMD_NOT_SUPPORTED;
}
uint8_t SC_Mechanical(uint8_t bFunction) {
  UNUSED(bFunction);
  return SLOTERROR_CMD_NOT_SUPPORTED;
}
uint8_t SC_SetDataRateAndClockFrequency(uint32_t dwClockFrequency,
                                        uint32_t dwDataRate) {
  UNUSED(dwClockFrequency);
  UNUSED(dwDataRate);
  return SLOT_NO_ERROR;
}
uint8_t SC_Secure(uint32_t dwLength, uint8_t bBWI, uint16_t wLevelParameter,
                    uint8_t* pbuf, uint32_t* returnLen )  {
  UNUSED(bBWI);
  UNUSED(wLevelParameter);
  UNUSED(returnLen);
  // return SLOTERROR_CMD_NOT_SUPPORTED;
  uint16_t ret_len,off;
  switch(pbuf[0]) {
  case 0: // verify pin
    off = 15;
    //ret_len = dwLength - 15;
    ret_len = 5;
    break;
  case 1: // modify pin
    switch(pbuf[11])  {
    case 3:
      off = 20;
      break;
    case 2:
    case 1:
      off = 19;
      break;
    // 0 and 4-0xFF
    default:
      off = 18;
      break;
    }
    //ret_len = dwLength - off;
    ret_len = 5;
    break;
  default: // unsupported
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
    RDR_to_PC_DataBlock(SLOTERROR_CMD_NOT_SUPPORTED);
    CCID_Send_Reply(&USBD_Device);
    return SLOTERROR_CMD_NOT_SUPPORTED;
  }
  pbuf += off;
  pbuf[0] = 0xEF;
  return SC_XferBlock(pbuf, ret_len, &ret_len);
}

// prepare the apdu to be processed by the application
uint8_t SC_XferBlock (uint8_t* ptrBlock, uint32_t blockLen, uint16_t* expectedLen) {
  UNUSED(expectedLen);

  // check for overflow
  if (blockLen > IO_APDU_BUFFER_SIZE) {
    return SLOTERROR_BAD_LENTGH;
  }

  // copy received apdu // if G_io_ccid_data_buffer is the buffer apdu, then the memmove will do nothing
  os_memmove(G_io_apdu_buffer, ptrBlock, blockLen);
  G_io_app.apdu_length = blockLen;
  G_io_app.apdu_media = IO_APDU_MEDIA_USB_CCID;  // for application code
  G_io_app.apdu_state = APDU_USB_CCID; // for next call to io_exchange

  return SLOT_NO_ERROR;
}

void io_usb_ccid_reply(unsigned char* buffer, unsigned short length) {
  // avoid memory overflow
  if (length > IO_CCID_DATA_BUFFER_SIZE) {
    THROW(EXCEPTION_IO_OVERFLOW);
  }
  // copy the responde apdu
  os_memmove(G_io_ccid_data_buffer, buffer, length);
  G_io_ccid.bulk_header.bulkin.dwLength = length;
  // forge reply
  RDR_to_PC_DataBlock(SLOT_NO_ERROR);

  // start sending rpely
  CCID_Send_Reply(&USBD_Device);
}

// ask for power on
void io_usb_ccid_set_card_inserted(unsigned int inserted) {
  G_io_ccid.ccid_card_inserted = inserted;
  CCID_UpdSlotChange(1);
#ifdef HAVE_CCID_INTERRUPT
  CCID_IntMessage(&USBD_Device);
#endif // HAVE_CCID_INTERRUPT
}







#endif // HAVE_USB_CLASS_CCID

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
