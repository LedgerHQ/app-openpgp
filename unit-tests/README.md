# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

## Overview

In `unit-tests` folder, compile with:

```shell
cmake -Bbuild -H. && make -C build
```

and run tests with:

```shell
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

To get more verbose output, use:

```shell
CTEST_OUTPUT_ON_FAILURE=1 make -C build test ARGS="-V"
```

Or also directly with:

```shell
CTEST_OUTPUT_ON_FAILURE=1 build/test_io
```

## Generate code coverage

Just execute in `unit-tests` folder:

```shell
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
