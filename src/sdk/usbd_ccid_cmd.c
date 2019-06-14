/**
  ******************************************************************************
  * @file    usbd_ccid_cmd.c
  * @author  MCD Application Team
  * @version V1.0.1
  * @date    31-January-2014
  * @brief   CCID Commands handling 
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

#ifdef HAVE_USB_CLASS_CCID

#include "sdk_compat.h"

/* Includes ------------------------------------------------------------------*/
#include "usbd_ccid_cmd.h"

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
#define CCID_UpdateCommandStatus(cmd_status,icc_status)\
 G_io_ccid.bulk_header.bulkin.bStatus=(cmd_status|icc_status)
  /* 
  The Above Macro can take any of following Values 
  #define BM_ICC_PRESENT_ACTIVE 0x00
  #define BM_ICC_PRESENT_INACTIVE 0x01
  #define BM_ICC_NO_ICC_PRESENT   0x02

  #define BM_COMMAND_STATUS_OFFSET 0x06
  #define BM_COMMAND_STATUS_NO_ERROR 0x00 
  #define BM_COMMAND_STATUS_FAILED   (0x01 << BM_COMMAND_STATUS_OFFSET)
  #define BM_COMMAND_STATUS_TIME_EXTN  (0x02 << BM_COMMAND_STATUS_OFFSET)
  */

/* Private function prototypes -----------------------------------------------*/
static uint8_t CCID_CheckCommandParams (uint32_t param_type);

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  PC_to_RDR_IccPowerOn
  *         PC_TO_RDR_ICCPOWERON message execution, apply voltage and get ATR	
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t PC_to_RDR_IccPowerOn(void)
{
  /* Apply the ICC VCC
     Fills the Response buffer with ICC ATR 
     This Command is returned with RDR_to_PC_DataBlock(); 
  */
  
  uint8_t voltage;
  uint8_t sc_voltage = 0;
  uint8_t error;
  
  G_io_ccid.bulk_header.bulkin.dwLength = 0;  /* Reset Number of Bytes in abData */
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_DWLENGTH | \
                                  CHK_PARAM_abRFU2 |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_ABORT );
  if (error != 0) 
  {
    return error;
  }
  
  /* Voltage that is applied to the ICC
  00h – Automatic Voltage Selection
  01h – 5.0 volts
  02h – 3.0 volts
  03h – 1.8 volts
  */
  /* G_io_ccid.bulk_header.bulkout.bSpecific_0 Contains bPowerSelect */
  voltage = G_io_ccid.bulk_header.bulkout.bSpecific_0;
  if (voltage >= VOLTAGE_SELECTION_1V8)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
    return SLOTERROR_BAD_POWERSELECT; /* The Voltage specified is out of Spec */
  }
  
  /* Correct Voltage Requested by the Host */
  if ((voltage == VOLTAGE_SELECTION_AUTOMATIC) || 
      (voltage == VOLTAGE_SELECTION_3V))
  {
    /* voltage == 00 Voltage Automatic 
    voltage == 01 Voltage Automatic = 5.0V
    voltage == 02 Voltage Automatic = 3V
    voltage == 03 Voltage Automatic = 1.8V
    */
    sc_voltage = SC_VOLTAGE_3V;
  }
  else if (voltage == VOLTAGE_SELECTION_5V)
  {
    sc_voltage = SC_VOLTAGE_5V;
  }
  
  G_io_ccid.bulk_header.bulkin.dwLength = SC_AnswerToReset(sc_voltage, G_io_ccid_data_buffer);
  
  /* Check if the Card has come to Active State*/
  error = CCID_CheckCommandParams(CHK_ACTIVE_STATE);
  if (error != 0)
  {
    /* Check if Voltage is not Automatic */ 
    if (voltage != 0)
    { /* If Specific Voltage requested by Host i.e 3V or 5V*/
      return error;
    }
    else
    {/* Automatic Voltage selection requested by Host */
      
      if (sc_voltage != SC_VOLTAGE_5V)
      { /* If voltage selected was Automatic and 5V is not yet tried */
        sc_voltage = SC_VOLTAGE_5V;
        G_io_ccid.bulk_header.bulkin.dwLength = SC_AnswerToReset(sc_voltage, G_io_ccid_data_buffer);
  
        /* Check again the State */      
        error = CCID_CheckCommandParams(CHK_ACTIVE_STATE);
        if (error != 0) 
         return error;

      }
      else 
      { /* Voltage requested from Host was 5V already*/
        CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_INACTIVE);
        return error;
      }
    } /* Voltage Selection was automatic */
  } /* If Active State */  
  
  /* ATR is received, No Error Condition Found */
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  
  return SLOT_NO_ERROR;
}

/**
  * @brief  PC_to_RDR_IccPowerOff
  *         Icc VCC is switched Off 
  * @param  None 
  * @retval uint8_t error: status of the command execution 
  */
uint8_t PC_to_RDR_IccPowerOff(void)
{
  /*  The response to this command message is the RDR_to_PC_SlotStatus 
  response message. */
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_abRFU3 |\
                                  CHK_PARAM_DWLENGTH );
  if (error != 0) 
  {
    return error;
  }
  
  /* Command is ok, Check for Card Presence */ 
  if (SC_Detect())
  { 
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR,BM_ICC_PRESENT_INACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR,BM_ICC_NO_ICC_PRESENT);
  }
  
  /* Power OFF the card */
  SC_Poweroff();
  
  return SLOT_NO_ERROR;
}

/**
  * @brief  PC_to_RDR_GetSlotStatus
  *         Provides the Slot status to the host 
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_GetSlotStatus(void)
{
    uint8_t error;

  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_DWLENGTH |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU3 );
  if (error != 0) 
  {
    return error;
  }
  
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR,BM_ICC_PRESENT_ACTIVE);
  return SLOT_NO_ERROR;
}


/**
  * @brief  PC_to_RDR_XfrBlock
  *         Handles the Block transfer from Host. 
  *         Response to this command message is the RDR_to_PC_DataBlock 
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_XfrBlock(void)
{
  uint16_t expectedLength, reqlen;
  
      uint8_t error;

  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU3 |\
                                  CHK_PARAM_ABORT |\
                                  CHK_ACTIVE_STATE );
  if (error != 0) 
    return error;
    
    if (G_io_ccid.bulk_header.bulkout.dwLength > IO_CCID_DATA_BUFFER_SIZE)
    { /* Check amount of Data Sent by Host is > than memory allocated ? */
     
      return SLOTERROR_BAD_DWLENGTH;
    }


    /* wLevelParameter = Size of expected data to be returned by the 
                          bulk-IN endpoint */
    expectedLength = (G_io_ccid.bulk_header.bulkout.bSpecific_2 << 8) | 
                      G_io_ccid.bulk_header.bulkout.bSpecific_1;   

    reqlen = G_io_ccid.bulk_header.bulkout.dwLength;
    
    G_io_ccid.bulk_header.bulkin.dwLength = (uint16_t)expectedLength;  


    error = SC_XferBlock(&G_io_ccid_data_buffer[0], 
                     reqlen, 
                     &expectedLength); 

   if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
    error = SLOT_NO_ERROR;
  }
  
  return error;
}


/**
  * @brief  PC_to_RDR_GetParameters
  *         Provides the ICC parameters to the host 
  *         Response to this command message is the RDR_to_PC_Parameters
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_GetParameters(void)
{
  uint8_t error;

  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_DWLENGTH |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU3 );
  if (error != 0) 
    return error;
      
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);

  return SLOT_NO_ERROR;
}


/**
  * @brief  PC_to_RDR_ResetParameters
  *         Set the ICC parameters to the default 
  *         Response to this command message is the RDR_to_PC_Parameters
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_ResetParameters(void)
{
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_DWLENGTH |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU3 |\
                                  CHK_ACTIVE_STATE);
  if (error != 0) 
    return error;
  
  /* This command resets the slot parameters to their default values */
  G_io_ccid.Protocol0_DataStructure.bmFindexDindex = DEFAULT_FIDI;
  G_io_ccid.Protocol0_DataStructure.bmTCCKST0 = DEFAULT_T01CONVCHECKSUM;
  G_io_ccid.Protocol0_DataStructure.bGuardTimeT0 = DEFAULT_EXTRA_GUARDTIME;
  G_io_ccid.Protocol0_DataStructure.bWaitingIntegerT0 = DEFAULT_WAITINGINTEGER;
  G_io_ccid.Protocol0_DataStructure.bClockStop = DEFAULT_CLOCKSTOP;
  
  error = SC_SetParams(&G_io_ccid.Protocol0_DataStructure);
  
   if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
    error = SLOT_NO_ERROR;
  }
  
  return error;
}


/**
  * @brief  PC_to_RDR_SetParameters
  *         Set the ICC parameters to the host defined parameters
  *         Response to this command message is the RDR_to_PC_Parameters
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_SetParameters(void)
{
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU2 |\
                                  CHK_ACTIVE_STATE);
  if (error != 0) 
    return error;
  
  error = SLOT_NO_ERROR;
  
  /* for Protocol T=0 (bProtocolNum=0) (dwLength=00000005h) */
  if ( (G_io_ccid.bulk_header.bulkout.dwLength == 5) &&
      (G_io_ccid.bulk_header.bulkout.bSpecific_0 != 0))
    error = SLOTERROR_BAD_PROTOCOLNUM;
  
  /* for Protocol T=1 (bProtocolNum=1) (dwLength=00000007h) */
  if ( (G_io_ccid.bulk_header.bulkout.dwLength == 7) &&
      (G_io_ccid.bulk_header.bulkout.bSpecific_0 != 1))
    error = SLOTERROR_CMD_NOT_SUPPORTED;
    
  /* For T0, Waiting Integer 0 supported */
  if (G_io_ccid_data_buffer[3] != 0)
    error = SLOTERROR_BAD_WAITINGINTEGER;
      
  if (G_io_ccid_data_buffer[4] != DEFAULT_CLOCKSTOP)
     error = SLOTERROR_BAD_CLOCKSTOP;
   
  if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  } 
  
  os_memmove(&G_io_ccid.Protocol0_DataStructure, (Protocol0_DataStructure_t*)(&(G_io_ccid_data_buffer[0])), sizeof(Protocol0_DataStructure_t));
  error = SC_SetParams(&G_io_ccid.Protocol0_DataStructure);
  
   if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
    error = SLOT_NO_ERROR;
  }
  
  return error;
}


/**
  * @brief  PC_to_RDR_Escape
  *         Execute the Escape command. This is user specific Implementation
  *         Response to this command message is the RDR_to_PC_Escape
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_Escape(void)
{
  uint8_t error;
  uint16_t size;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU3 |\
                                  CHK_PARAM_ABORT |\
                                  CHK_ACTIVE_STATE);
  
  if (error != 0) 
    return error;
  
  error = SC_ExecuteEscape(&G_io_ccid_data_buffer[0],
                           G_io_ccid.bulk_header.bulkout.dwLength,
                           &G_io_ccid_data_buffer[0],
                           &size);
  
  G_io_ccid.bulk_header.bulkin.dwLength = size;
  
  if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}


/**
  * @brief  PC_to_RDR_IccClock
  *         Execute the Clock specific command from host 
  *         Response to this command message is the RDR_to_PC_SlotStatus
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_IccClock(void)
{
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU2 |\
                                  CHK_PARAM_DWLENGTH|\
                                  CHK_ACTIVE_STATE);
  if (error != 0) 
    return error;

  /* bClockCommand • 00h restarts Clock
                   • 01h Stops Clock in the state shown in the bClockStop 
                       field of the PC_to_RDR_SetParameters command 
                       and RDR_to_PC_Parameters message.*/
  if (G_io_ccid.bulk_header.bulkout.bSpecific_0 > 1)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
    return SLOTERROR_BAD_CLOCKCOMMAND;
  }
  
  error = SC_SetClock(G_io_ccid.bulk_header.bulkout.bSpecific_0);
  
  if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}


/**
  * @brief  PC_to_RDR_Abort
  *         Execute the Abort command from host, This stops all Bulk transfers 
  *         from host and ICC
  *         Response to this command message is the RDR_to_PC_SlotStatus
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_to_RDR_Abort(void)
{
    uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_abRFU3 |\
                                  CHK_PARAM_DWLENGTH);
  if (error != 0) 
    return error;
  
  CCID_CmdAbort (G_io_ccid.bulk_header.bulkout.bSlot, G_io_ccid.bulk_header.bulkout.bSeq);
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR,BM_ICC_PRESENT_ACTIVE);               
  return SLOT_NO_ERROR;
}

/**
  * @brief  CCID_CmdAbort
  *         Execute the Abort command from Bulk EP or from Control EP,
  *          This stops all Bulk transfers from host and ICC
  * @param  uint8_t slot: slot number that host wants to abort
  * @param  uint8_t seq : Seq number for PC_to_RDR_Abort
  * @retval uint8_t status of the command execution 
  */
uint8_t CCID_CmdAbort(uint8_t slot, uint8_t seq)
{
   /* This function is called for REQUEST_ABORT & PC_to_RDR_Abort */
  
   if (slot >= CCID_NUMBER_OF_SLOTS)
   { /* This error condition is possible only from CLASS_REQUEST, otherwise
     Slot is already checked in parameters from PC_to_RDR_Abort request */
     /* Slot requested is more than supported by Firmware */
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_NO_ICC_PRESENT);
      return SLOTERROR_BAD_SLOT;
   }
    
  if ( G_io_ccid.usb_ccid_param.bAbortRequestFlag == 1)
  { /* Abort Command was already received from ClassReq or PC_to_RDR */
    if (( G_io_ccid.usb_ccid_param.bSeq == seq) && (G_io_ccid.usb_ccid_param.bSlot == slot))
    {
      /* CLASS Specific request is already Received, Reset the abort flag */
      G_io_ccid.usb_ccid_param.bAbortRequestFlag = 0;
    }
  }
  else
  {
    /* Abort Command was NOT received from ClassReq or PC_to_RDR, 
       so save them for next ABORT command to verify */
    G_io_ccid.usb_ccid_param.bAbortRequestFlag = 1;
    G_io_ccid.usb_ccid_param.bSeq = seq ;
    G_io_ccid.usb_ccid_param.bSlot = slot;
  }
  
  return 0;
}

/**
  * @brief  PC_TO_RDR_T0Apdu
  *         Execute the PC_TO_RDR_T0APDU command from host
  *         Response to this command message is the RDR_to_PC_SlotStatus
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_TO_RDR_T0Apdu(void)
{
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_DWLENGTH |
                                  CHK_PARAM_ABORT );
  if (error != 0) 
    return error;
  
  if (G_io_ccid.bulk_header.bulkout.bSpecific_0 > 0x03)
  {/* Bit 0 is associated with field bClassGetResponse
      Bit 1 is associated with field bClassEnvelope
      Other bits are RFU.*/
    
   CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE); 
   return SLOTERROR_BAD_BMCHANGES;
  }
  
  error = SC_T0Apdu(G_io_ccid.bulk_header.bulkout.bSpecific_0, 
                    G_io_ccid.bulk_header.bulkout.bSpecific_1, 
                    G_io_ccid.bulk_header.bulkout.bSpecific_2);
  
   if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}

/**
  * @brief  PC_TO_RDR_Mechanical
  *         Execute the PC_TO_RDR_MECHANICAL command from host
  *         Response to this command message is the RDR_to_PC_SlotStatus
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_TO_RDR_Mechanical(void)
{
  uint8_t error;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_abRFU2 |\
                                  CHK_PARAM_DWLENGTH 
                                   );
  if (error != 0) 
    return error;
  
  if (G_io_ccid.bulk_header.bulkout.bSpecific_0 > 0x05)
  {/* 01h – Accept Card
      02h – Eject Card
      03h – Capture Card
      04h – Lock Card
      05h – Unlock Card*/
    
   CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE); 
   return SLOTERROR_BAD_BFUNCTION_MECHANICAL;
  }
  
  error = SC_Mechanical(G_io_ccid.bulk_header.bulkout.bSpecific_0);
  
   if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}

/**
  * @brief  PC_TO_RDR_SetDataRateAndClockFrequency
  *         Set the required Card Frequency and Data rate from the host. 
  *         Response to this command message is the 
  *           RDR_to_PC_DataRateAndClockFrequency
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_TO_RDR_SetDataRateAndClockFrequency(void)
{
  uint8_t error;
  uint32_t clockFrequency;
  uint32_t dataRate;
  uint32_t temp =0;
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
    CHK_PARAM_CARD_PRESENT |\
      CHK_PARAM_abRFU3);
  if (error != 0) 
    return error;
  
  if (G_io_ccid.bulk_header.bulkout.dwLength != 0x08)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_ACTIVE);
    return SLOTERROR_BAD_LENTGH;
  } 
  
  /* HERE we avoiding to an unaligned memory access*/ 
  clockFrequency = U4LE(G_io_ccid_data_buffer, 0);
  dataRate = U4LE(G_io_ccid_data_buffer, 4);
  
  error = SC_SetDataRateAndClockFrequency(clockFrequency, dataRate);
  G_io_ccid.bulk_header.bulkin.bError = error;
  
  if (error != SLOT_NO_ERROR)
  {
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    G_io_ccid.bulk_header.bulkin.dwLength = 8;
    
    (G_io_ccid_data_buffer[0])  = clockFrequency & 0x000000FF ;
    (G_io_ccid_data_buffer[1])  =  (clockFrequency & 0x0000FF00) >> 8;
    (G_io_ccid_data_buffer[2])  =  (clockFrequency & 0x00FF0000) >> 16;
    (G_io_ccid_data_buffer[3])  =  (clockFrequency & 0xFF000000) >> 24;
    (G_io_ccid_data_buffer[4])  =  dataRate & 0x000000FF ;
    (G_io_ccid_data_buffer[5])  =  (dataRate & 0x0000FF00) >> 8;
    (G_io_ccid_data_buffer[6])  =  (dataRate & 0x00FF0000) >> 16;
    (G_io_ccid_data_buffer[7])  =  (dataRate & 0xFF000000) >> 24;
    
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}

/**
  * @brief  PC_TO_RDR_Secure
  *         Execute the Secure Command from the host. 
  *         Response to this command message is the RDR_to_PC_DataBlock
  * @param  None 
  * @retval uint8_t status of the command execution 
  */
uint8_t  PC_TO_RDR_Secure(void)
{
  uint8_t error;
  uint8_t bBWI;
  uint16_t wLevelParameter;
  uint32_t responseLen; 
  
  
  error = CCID_CheckCommandParams(CHK_PARAM_SLOT |\
                                  CHK_PARAM_CARD_PRESENT |\
                                  CHK_PARAM_ABORT );
  
  if (error != 0) {
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
    return error;
  }
  
  bBWI = G_io_ccid.bulk_header.bulkout.bSpecific_0;
  wLevelParameter = (G_io_ccid.bulk_header.bulkout.bSpecific_1 + ((uint16_t)G_io_ccid.bulk_header.bulkout.bSpecific_2<<8));
  
  if ((EXCHANGE_LEVEL_FEATURE == TPDU_EXCHANGE) || 
    (EXCHANGE_LEVEL_FEATURE == SHORT_APDU_EXCHANGE))
  {
    /* TPDU level & short APDU level, wLevelParameter is RFU, = 0000h */
    if (wLevelParameter != 0 )
    {
      G_io_ccid.bulk_header.bulkin.dwLength = 0;
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      error = SLOTERROR_BAD_LEVELPARAMETER;
      return error;
    }
  }

  error = SC_Secure(G_io_ccid.bulk_header.bulkout.dwLength - CCID_HEADER_SIZE, bBWI, wLevelParameter, 
                    &G_io_ccid_data_buffer[0], &responseLen);

  G_io_ccid.bulk_header.bulkin.dwLength = responseLen;
  
  if (error != SLOT_NO_ERROR)
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
  }
  else
  {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  }
  
  return error;
}

/******************************************************************************/
/*		BULK IN ROUTINES															*/
/******************************************************************************/

/**
  * @brief  RDR_to_PC_DataBlock
  *         Provide the data block response to the host 
  *         Response for PC_to_RDR_IccPowerOn, PC_to_RDR_XfrBlock 
  * @param  uint8_t errorCode: code to be returned to the host
  * @retval None 
  */
void RDR_to_PC_DataBlock(uint8_t  errorCode)
{  
  G_io_ccid.bulk_header.bulkin.bMessageType = RDR_TO_PC_DATABLOCK; 
  G_io_ccid.bulk_header.bulkin.bError = errorCode; 
  G_io_ccid.bulk_header.bulkin.bSpecific=0;    /* bChainParameter */
  
  /* void the Length Specified in Command */
  if(errorCode != SLOT_NO_ERROR)
  {
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
  }
  
  Transfer_Data_Request();

}


/**
  * @brief  RDR_to_PC_SlotStatus
  *         Provide the Slot status response to the host 
  *          Response for PC_to_RDR_IccPowerOff 
  *                PC_to_RDR_GetSlotStatus
  *                PC_to_RDR_IccClock
  *                PC_to_RDR_T0APDU
  *                PC_to_RDR_Mechanical
  *         Also the device sends this response message when it has completed 
  *         aborting a slot after receiving both the Class Specific ABORT request 
  *          and PC_to_RDR_Abort command message.
  * @param  uint8_t errorCode: code to be returned to the host
  * @retval None 
  */
void RDR_to_PC_SlotStatus(uint8_t  errorCode)
{
  
  G_io_ccid.bulk_header.bulkin.bMessageType = RDR_TO_PC_SLOTSTATUS; 
  G_io_ccid.bulk_header.bulkin.dwLength =0;
  G_io_ccid.bulk_header.bulkin.bError = errorCode; 
  G_io_ccid.bulk_header.bulkin.bSpecific=0;    /* bClockStatus = 00h Clock running
                                      01h Clock stopped in state L
                                      02h Clock stopped in state H
                                      03h Clock stopped in an unknown state
                                      All other values are RFU. */                                                                            

  Transfer_Data_Request();

}

/**
  * @brief  RDR_to_PC_Parameters
  *         Provide the data block response to the host 
  *         Response for PC_to_RDR_GetParameters, PC_to_RDR_ResetParameters
  *                      PC_to_RDR_SetParameters
  * @param  uint8_t errorCode: code to be returned to the host
  * @retval None 
  */
void RDR_to_PC_Parameters(uint8_t  errorCode)
{
  
  G_io_ccid.bulk_header.bulkin.bMessageType = RDR_TO_PC_PARAMETERS; 
  G_io_ccid.bulk_header.bulkin.bError = errorCode; 
  
  if(errorCode == SLOT_NO_ERROR)
  { 
   G_io_ccid.bulk_header.bulkin.dwLength = LEN_PROTOCOL_STRUCT_T0;
  }
  else
  {
   G_io_ccid.bulk_header.bulkin.dwLength = 0;
  }
    
  os_memmove(G_io_ccid_data_buffer, &G_io_ccid.Protocol0_DataStructure, sizeof(G_io_ccid.Protocol0_DataStructure));
  
  /* bProtocolNum */
  G_io_ccid.bulk_header.bulkin.bSpecific = BPROTOCOL_NUM_T0; 
  
  Transfer_Data_Request();
}

/**
  * @brief  RDR_to_PC_Escape
  *         Provide the Escaped data block response to the host 
  *         Response for PC_to_RDR_Escape
  * @param  uint8_t errorCode: code to be returned to the host
  * @retval None 
  */
void RDR_to_PC_Escape(uint8_t  errorCode)
{ 
  G_io_ccid.bulk_header.bulkin.bMessageType = RDR_TO_PC_ESCAPE; 
  
  G_io_ccid.bulk_header.bulkin.bSpecific=0;    /* Reserved for Future Use */
  G_io_ccid.bulk_header.bulkin.bError = errorCode; 
  
  /* void the Length Specified in Command */
  if(errorCode != SLOT_NO_ERROR)
  {
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
  }  
  
  Transfer_Data_Request();
}



/**
  * @brief  RDR_to_PC_DataRateAndClockFrequency
  *         Provide the Clock and Data Rate information to host 
  *         Response for PC_TO_RDR_SetDataRateAndClockFrequency
  * @param  uint8_t errorCode: code to be returned to the host
  * @retval None 
  */
void RDR_to_PC_DataRateAndClockFrequency(uint8_t  errorCode)
{
  /*
  uint16_t length = CCID_RESPONSE_HEADER_SIZE;
  */
  
  G_io_ccid.bulk_header.bulkin.bMessageType = RDR_TO_PC_DATARATEANDCLOCKFREQUENCY; 
  G_io_ccid.bulk_header.bulkin.bError = errorCode; 
  G_io_ccid.bulk_header.bulkin.bSpecific=0;    /* Reserved for Future Use */
  
  /* void the Length Specified in Command */
  if(errorCode != SLOT_NO_ERROR)
  {
    G_io_ccid.bulk_header.bulkin.dwLength = 0;
  }  
  
  Transfer_Data_Request();
}

#ifdef HAVE_CCID_INTERRUPT
/**
  * @brief  RDR_to_PC_NotifySlotChange
  *         Interrupt message to be sent to the host, Checks the card presence 
  *           status and update the buffer accordingly
  * @param  None 
  * @retval None
  */
void RDR_to_PC_NotifySlotChange(void)
{
  G_io_ccid.UsbIntMessageBuffer[OFFSET_INT_BMESSAGETYPE] = RDR_TO_PC_NOTIFYSLOTCHANGE;
  
  if (SC_Detect() )
  {	
    /* 
    SLOT_ICC_PRESENT 0x01 : LSb : (0b = no ICC present, 1b = ICC present)
    SLOT_ICC_CHANGE 0x02 : MSb : (0b = no change, 1b = change).
    */
    G_io_ccid.UsbIntMessageBuffer[OFFSET_INT_BMSLOTICCSTATE] = SLOT_ICC_PRESENT | 
                                                     SLOT_ICC_CHANGE;	
  }
  else
  {	
    G_io_ccid.UsbIntMessageBuffer[OFFSET_INT_BMSLOTICCSTATE] = SLOT_ICC_CHANGE;
    
    /* Power OFF the card */
    SC_Poweroff();
  }
}
#endif // HAVE_CCID_INTERRUPT


/**
  * @brief  CCID_UpdSlotStatus
  *         Updates the variable for the slot status 
  * @param  uint8_t slotStatus : slot status from the calling function 
  * @retval None
  */
void CCID_UpdSlotStatus (uint8_t slotStatus)
{
   G_io_ccid.Ccid_SlotStatus.SlotStatus = slotStatus;
}

/**
  * @brief  CCID_UpdSlotChange
  *         Updates the variable for the slot change status 
  * @param  uint8_t changeStatus : slot change status from the calling function 
  * @retval None
  */
void CCID_UpdSlotChange (uint8_t changeStatus)
{
   G_io_ccid.Ccid_SlotStatus.SlotStatusChange  = changeStatus;
}

/**
  * @brief  CCID_IsSlotStatusChange
  *         Provides the value of the variable for the slot change status 
  * @param  None
  * @retval uint8_t slot change status 
  */
uint8_t CCID_IsSlotStatusChange (void)
{
  return G_io_ccid.Ccid_SlotStatus.SlotStatusChange;
}

/**
  * @brief  CCID_CheckCommandParams
  *         Checks the specific parameters requested by the function and update 
  *          status accordingly. This function is called from all 
  *          PC_to_RDR functions
  * @param  uint32_t param_type : Parameter enum to be checked by calling function
  * @retval uint8_t status 
  */
static uint8_t CCID_CheckCommandParams (uint32_t param_type)
{
  uint32_t parameter;
  
  G_io_ccid.bulk_header.bulkin.bStatus = BM_ICC_PRESENT_ACTIVE | BM_COMMAND_STATUS_NO_ERROR ;
  
  parameter = (uint32_t)param_type;
  
  if (parameter & CHK_PARAM_SLOT)
  {
    /* 
    The slot number (bSlot) identifies which ICC slot is being addressed 
    by the message, if the CCID supports multiple slots. 
    The slot number is zero-relative, and is in the range of zero to FFh.
    */
    
    /* SLOT Number is 0 onwards, so always < CCID_NUMBER_OF_SLOTs */
    /* Error Condition !!! */
    if (G_io_ccid.bulk_header.bulkout.bSlot >= CCID_NUMBER_OF_SLOTS)
    { /* Slot requested is more than supported by Firmware */
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_NO_ICC_PRESENT);
      return SLOTERROR_BAD_SLOT;
    }
  }
  
    if (parameter & CHK_PARAM_CARD_PRESENT)
  {
    /* Commands Parameters ok, Check the Card Status */  
    if (SC_Detect() == 0)
    { /* Card is Not detected */
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_NO_ICC_PRESENT);
      return SLOTERROR_ICC_MUTE;
    }
  }
  
  /* Check that DwLength is 0 */
  if (parameter & CHK_PARAM_DWLENGTH)
  {
    if (G_io_ccid.bulk_header.bulkout.dwLength != 0)
    {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_LENTGH;
    } 
  }
  
  /* abRFU 2 : Reserved for Future Use*/
  if (parameter & CHK_PARAM_abRFU2)
  {
    
    if ((G_io_ccid.bulk_header.bulkout.bSpecific_1 != 0) ||
        (G_io_ccid.bulk_header.bulkout.bSpecific_2 != 0))
    {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_ABRFU_2B;        /* bSpecific_1 */
    }
  }
  
  if (parameter & CHK_PARAM_abRFU3)
  {
   /* abRFU 3 : Reserved for Future Use*/
    if ((G_io_ccid.bulk_header.bulkout.bSpecific_0 != 0) || 
       (G_io_ccid.bulk_header.bulkout.bSpecific_1 != 0) ||
       (G_io_ccid.bulk_header.bulkout.bSpecific_2 != 0))
    {
       CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_ACTIVE);    
        return SLOTERROR_BAD_ABRFU_3B;    
    }
  }
  
 
  if (parameter & CHK_PARAM_ABORT)
  {
    if( G_io_ccid.usb_ccid_param.bAbortRequestFlag )
    {
       CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_INACTIVE);    
      return SLOTERROR_CMD_ABORTED; 
    }
  }
  
  if (parameter & CHK_ACTIVE_STATE)
  {
     /* Commands Parameters ok, Check the Card Status */  
     /* Card is detected */
    if (! SC_Detect())
    {
      /* Check that from Lower Layers, the SmartCard come to known state */
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED,BM_ICC_PRESENT_INACTIVE);
      return SLOTERROR_HW_ERROR;
    }    
  }
  
  return 0; 
}

#endif // HAVE_USB_CLASS_CCID

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/

