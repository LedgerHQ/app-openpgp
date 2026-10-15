cmake_minimum_required(VERSION 3.10)
project(unit_tests
    VERSION 0.1
    DESCRIPTION "Unit tests for Ledger OpenPGP application"
    LANGUAGES C
)

#######################################################################
#                        Setup SDK & LedgerUT                         #
#######################################################################
if(NOT DEFINED ENV{BOLOS_SDK})
    message(FATAL_ERROR "BOLOS_SDK environment variable is not set. Please set it to the path of the Ledger Secure SDK.")
endif()

set(SDK_DIR $ENV{BOLOS_SDK})
include(${SDK_DIR}/cmake/LedgerUT.cmake)

#######################################################################
#             Setup app specific includes & compile defs              #
#######################################################################
set(APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../src)
set(FAKES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fakes)

set(FAKE_SOURCES
    ${FAKES_DIR}/fake_assert.c
    ${FAKES_DIR}/fake_io.c
)

set(UT_INCLUDE_DIRS
    ${FAKES_DIR}
    ${APP_DIR}
    ${UT_INCLUDE_DIRS_SDK}
    ${SDK_DIR}/lib_cxng/src
)

set(UT_COMPILE_DEFS
    ${UT_COMPILE_DEFS_SDK}
    APPNAME="OpenPGP"
    APPVERSION="a.b.c"
    SPEC_VERSION="3.3.1"
    HAVE_RSA
    "CUSTOM_IO_APDU_BUFFER_SIZE=(255+5+64)"
)

#######################################################################
#                           LedgerUT Setup                            #
#######################################################################
ledger_unit_tests_init()

# The app sources live in ../../src: ledger_unit_tests_find_sources() only looks in ../src
file(GLOB APP_SOURCES CONFIGURE_DEPENDS ${APP_DIR}/*.c)
list(FILTER APP_SOURCES EXCLUDE REGEX "/gpg_main\\.c$")

# Built only so that every app source has a .gcno file for the coverage baseline
ledger_unit_tests_build_app_sources_as_lib(
    SOURCES      ${APP_SOURCES}
    INCLUDE_DIRS ${UT_INCLUDE_DIRS}
    COMPILE_DEFS ${UT_COMPILE_DEFS}
)

# generate_coverage filters on ../src: regenerate the report restricted to the app sources
add_custom_command(TARGET generate_coverage POST_BUILD
    COMMAND ${LEDGER_UT_DIR}/gen_coverage.sh ${APP_DIR}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    VERBATIM
)

#######################################################################
#                        LedgerUT test suites                         #
#######################################################################
ledger_unit_tests_add_test(
    NAME         test_io
    SOURCES      ${APP_DIR}/gpg_io.c
                 ${APP_DIR}/gpg_vars.c
                 ${FAKE_SOURCES}
    INCLUDE_DIRS ${UT_INCLUDE_DIRS}
    COMPILE_DEFS ${UT_COMPILE_DEFS}
)
