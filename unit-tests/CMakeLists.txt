cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for Ledger OpenPGP application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

include(CTest)

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra -g -pedantic --coverage)
# Flag depending on the Build Type
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}-O3")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

set(APP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOCK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mocks")

add_compile_definitions(TEST)

include_directories(
  ${MOCK_DIR}
  ${APP_DIR}
)
# include_directories($ENV{BOLOS_SDK}/lib_standard_app)

add_executable(test_io
    ${SRC_DIR}/test_io.c
    ${MOCK_DIR}/mocks.c
    ${APP_DIR}/gpg_io.c
    ${APP_DIR}/gpg_vars.c
)

target_link_libraries(test_io PUBLIC
                      cmocka
                      gcov)

add_test(test_io test_io)
