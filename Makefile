#*******************************************************************************
#   Ledger App
#   (c) 2016-2018 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

-include Makefile.env
ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

APP_LOAD_PARAMS=--appFlags 0x40 --path "2152157255'" --curve secp256k1 $(COMMON_LOAD_PARAMS) 

ifeq ($(MULTISLOT),)
MULTISLOT := 0
endif

ifeq ($(MULTISLOT),0)
GPG_MULTISLOT:=0
APPNAME:=OpenPGP
else
GPG_MULTISLOT:=1
APPNAME:=OpenPGP.XL
endif

APP_LOAD_PARAMS=--appFlags 0x40 --path "2152157255'" --curve secp256k1 $(COMMON_LOAD_PARAMS) 

SPECVERSION:="3.3.1"

APPVERSION_M:=1
APPVERSION_N:=3
APPVERSION_P:=1
APPVERSION:=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME=images/icon_pgp_blue.gif
else
ICONNAME=images/icon_pgp.gif
endif

DEFINES   += GPG_MULTISLOT=$(GPG_MULTISLOT) $(GPG_CONFIG) GPG_VERSION=$(APPVERSION) GPG_NAME=$(APPNAME) SPEC_VERSION=$(SPECVERSION)

################
# Default rule #
################

.PHONY: allvariants listvariants 

all: default
	mkdir -p release
	cp -a bin/app.elf   release/$(APPNAME).elf
	cp -a bin/app.hex   release/$(APPNAME).hex
	cp -a debug/app.asm release/$(APPNAME).asm
	cp -a debug/app.map release/$(APPNAME).map


listvariants:
	@echo VARIANTS MULTISLOT 0 1

allvariants:
	make  MULTISLOT=0 clean all
	make  MULTISLOT=1 clean all

############
# Platform #
############
#SCRIPT_LD :=  script.ld

ifneq ($(NO_CONSENT),)
DEFINES   += NO_CONSENT
endif

DEFINES   += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES   += HAVE_BAGL HAVE_SPRINTF
#DEFINES   += HAVE_PRINTF PRINTF=screen_printf
DEFINES   += PRINTF\(...\)=
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=6 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
#DEFINES  += HAVE_BLE
DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"
DEFINES   += CUSTOM_IO_APDU_BUFFER_SIZE=\(255+5+64\)

DEFINES   += HAVE_USB_CLASS_CCID

##############
# Compiler #
##############
#GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
#CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
CC       := $(CLANGPATH)clang 

#CFLAGS   += -O0 -gdwarf-2  -gstrict-dwarf
CFLAGS   += -O3 -Os 
#CFLAGS   += -fno-jump-tables -fno-lookup-tables -fsave-optimization-record
#$(info $(CFLAGS))

AS     := $(GCCPATH)arm-none-eabi-gcc

LD       := $(GCCPATH)arm-none-eabi-gcc
#LDFLAGS  += -O0 -gdwarf-2  -gstrict-dwarf
LDFLAGS  += -O3 -Os
LDLIBS   += -lm -lgcc -lc 

# import rules to compile glyphs(/pone)
include $(BOLOS_SDK)/Makefile.glyphs

### variables processed by the common makefile.rules of the SDK to grab source files and include dirs
APP_SOURCE_PATH  += src
SDK_SOURCE_PATH  += lib_stusb 


load: all
	cp -a release/$(APPNAME).elf bin/app.elf   
	cp -a release/$(APPNAME).hex bin/app.hex   
	cp -a release/$(APPNAME).asm debug/app.asm 
	cp -a release/$(APPNAME).map debug/app.map 
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

run:
	python -m ledgerblue.runApp --appName $(APPNAME)

exit:
	echo -e "0020008206313233343536\n0002000000" |scriptor -r "Ledger Nano S [Nano S] (0001) 01 00" 

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

# import generic rules from the sdk
include Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

