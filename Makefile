#*******************************************************************************
#   Ledger App
#   (c) 2016-2019 Ledger
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

APP_LOAD_PARAMS=--appFlags 0x240 --path "2152157255'" --curve secp256k1 $(COMMON_LOAD_PARAMS)

ifeq ($(APPNAME),)
APPNAME = OpenPGP
endif
ifeq ($(APPNAME),OpenPGP)
GPG_MULTISLOT:=0
else ifeq ($(APPNAME),OpenPGP.XL)
GPG_MULTISLOT:=1
APPNAME:=OpenPGP.XL
else
$(error APPNAME ($(APPNAME)) is not set or unknown)
endif

ifeq ($(TARGET_NAME),TARGET_BLUE)
ICONNAME = images/icon_monero_blue.gif
else ifeq ($(TARGET_NAME),TARGET_NANOX)
ICONNAME = images/icon_pgp_nanox.gif
else
ICONNAME = images/icon_pgp.gif
endif

APPVERSION_M:=1
APPVERSION_N:=4
APPVERSION_P:=1
APPVERSION:=$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)
SPECVERSION:="3.3.1"

DEFINES   += $(OPENPGP_CONFIG)
DEFINES   += OPENPGP_VERSION_MAJOR=$(APPVERSION_M) OPENPGP_VERSION_MINOR=$(APPVERSION_N) OPENPGP_VERSION_MICRO=$(APPVERSION_P)
DEFINES   += OPENPGP_VERSION=$(APPVERSION)
DEFINES   += OPENPGP_NAME=$(APPNAME)
DEFINES   += SPEC_VERSION=$(SPECVERSION)
DEFINES   += GPG_MULTISLOT=$(GPG_MULTISLOT)
#DEFINES   += GPG_LOG


ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES   += UI_NANO_X
DEFINES   += GPG_SHAKE256
else ifeq ($(TARGET_NAME),TARGET_BLUE)
DEFINES   += UI_BLUE
else
DEFINES   += UI_NANO_S
endif



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
	@echo VARIANTS APPNAME OpenPGP OpenPGP.XL

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

DEFINES   += OS_IO_SEPROXYHAL
DEFINES   += HAVE_BAGL HAVE_SPRINTF
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += CUSTOM_IO_APDU_BUFFER_SIZE=\(255+5+64\)
DEFINES   += HAVE_LEGACY_PID

DEFINES   += USB_SEGMENT_SIZE=64
DEFINES   += U2F_PROXY_MAGIC=\"MOON\"
#DEFINES   += HAVE_IO_U2F HAVE_U2F

DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES   += HAVE_USB_CLASS_CCID

ifeq ($(NO_CXNG),)
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/include
SOURCE_PATH   += $(BOLOS_SDK)/lib_cxng/src
endif

# RSA addition.
DEFINES       += HAVE_RSA
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src
SOURCE_PATH   += $(BOLOS_SDK)/lib_cxng/src/cx_rsa.c
SOURCE_PATH   += $(BOLOS_SDK)/lib_cxng/src/cx_pkcs1.c
SOURCE_PATH   += $(BOLOS_SDK)/lib_cxng/src/cx_utils.c
# RSA - End


ifeq ($(TARGET_NAME),TARGET_NANOX)
# DEFINES       += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
# DEFINES       += HAVE_BLE_APDU # basic ledger apdu transport over BLE

DEFINES           += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES       += HAVE_GLO096
DEFINES       += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES       += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
DEFINES           += HAVE_UX_FLOW
DEFINES       += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES       += HAVE_BLE_APDU # basic ledger apdu transport over BLE
else
DEFINES           += IO_SEPROXYHAL_BUFFER_SIZE_B=128
endif

# Enabling debug PRINTF
DEBUG = 0
ifneq ($(DEBUG),0)

        ifeq ($(TARGET_NAME),TARGET_NANOX)
                DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
        else
                DEFINES   += HAVE_PRINTF PRINTF=screen_printf
        endif
	DEFINES += PLINE="PRINTF(\"FILE:%s..LINE:%d\n\",__FILE__,__LINE__)"
else
        DEFINES   += PRINTF\(...\)=
	DEFINES   += PLINE\(...\)=
endif


##############
# Compiler #
##############
ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif
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
SDK_SOURCE_PATH  += lib_stusb lib_stusb_impl
#SDK_SOURCE_PATH  += lib_u2f
ifeq ($(TARGET_NAME),TARGET_NANOX)
SDK_SOURCE_PATH  += lib_ux
SDK_SOURCE_PATH  += lib_blewbxx lib_blewbxx_impl
endif


cformat:
	clang-format -i src/*.c src/*.h

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



# import generic rules from the user and SDK
-include Makefile.rules
#include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile


