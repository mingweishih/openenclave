# Code Coverage Test in OE

This document shows how to do code coverage tests on OE
The code coverage test is based on GCOV, a source-based code coverage implementation provided by GCC.
Currently, both LLVM and GCC supports GCOV.

The workflow of GCOV typically consists of following phases:
- Compile-time intrumentation
- Link compiled binaries against GCOV libraries
- Runtime data collection
- Offline analysis (e.g., create reports)

# Compile-Time Instrumentation

Currently, both LLVM and GCC support the GCOV.

On LLVM, compile the code with `-fprofile-arcs -ftest-coverage` options.

For example,

`clang -fprofile-arcs -ftest-coverage -c foo.c -o foo.o`

When enabling the code coverage, the compiler also generates a `*.gcno` (e.g., `foo.gcno`)
file that contains the static coverage map the of source.

# Link Compiled binary against the GCOV Library

After compilation, the intrumented binary needs to link agaisnt the GCOV library.
The library primarily implements
- An initialize function that registers a callback (via `atexit`) function.
- The callback function that writes the coverage information to file (`*.gcda`) upon enclave termination.

The OE currently includes the source of the GCOV library from [LLVM runtime libraries](http://compiler-rt.llvm.org/).

| Source                   | Description                                       |
|--------------------------|---------------------------------------------------|
| GCDAProfiling.c          | Implements the core GCOV functions                |
| InstrProfData.inc        | Dependency                                        |
| InstrProfiling.c         | Dependency                                        |
| InstrProfiling.h         | Header                                            |
| InstrProfilingInternal.h | Header                                            |
| InstrProfilingPort.h     | Header                                            |
| InstrProfilingUtil.c     | Implement the util function such as `lprocLockFd` |
| InstrProfilingUtil.h     | Header                                            |

The resulting static library `libgcov.a` is generated under `3rdparty/libgcov`.
The following example shows how to link the binary against the library.

`clang foo.o libgcov.a -o foo`

## OE-specific modifications

To support GCOV in OE, few changes are required.
- Initialize the `hostfs` during the GCOV initialization (`llvm_gcov_init()`).
  - Ensure that the following filesystem operations work correctly.
- Replace `mmap` and `ummap` (in `map_file()` and `unmap_file()`)
  - `mmap` is not supported by OE. USe `fread()` instead.
  - Alternatively, OE can support `mmap` only for code coverage testing (if there is a performance gap). Note that `mmap` implies using the host memory.

## Get started on OE

The following instructions shows how to enable the GCOV on OE (assume inside the `openclave` directory).

```
mkdir build
cd build
cmake .. -DCODE_COVERAGE_TEST=ON
```

# Runtime Data Collection

The next step is simply running the binary. Once the execution is done, the associate `.gcda` file will be generated.

On OE, run the test suite as follows.

`ctest`

After finishing the tests, all the associated `.gcda` files will be generated under the same location of `.o` and `.gcno` files in the build tree.
The following examples show the content of `build/enclave/core/CMakeFiles/oecore.dir/sgx/linux` directory:

```
reloc.c.gcda  reloc.c.gcno  reloc.c.o  threadlocal.c.gcda  threadlocal.c.gcno  threadlocal.c.o
```

# Offline Analysis

One way to analysis the result is using [llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html) tool.

For example:

```
llvm-cov-7 gcov -f -b reloc.c.gcda
```

The results are:

```
Function 'oe_apply_relocations'
Lines executed:100.00% of 14
Branches executed:100.00% of 6
Taken at least once:83.33% of 6
No calls

File '/home/mingwei/oe-ms/enclave/core/sgx/linux/reloc.c'
Lines executed:100.00% of 14
Branches executed:100.00% of 6
Taken at least once:83.33% of 6
No calls
```

## Generate report using LCOV

Another way to generate a full code coverage report is using [LCOV](http://ltp.sourceforge.net/coverage/lcov.php).

The following instructions showcase the use of LCOV with OE.

First, create a `llvm-gocv.sh`, which is a wrapper of `llvm-cov` required by `LCOV`

```
echo '#!/bin/bash
exec llvm-cov gcov "$@" > llvm-gocv.sh
```

Note that this is single command. Use `shift`+`enter` to break the line.

Next change the permission of the file.

`chmod +x llvm-gcov.sh`

Then, use `lcov` tool to generate the coverage information (assume the `openclave` is under `/home/acc/`).

```
lcov --directory .  --gcov-tool /home/acc/openenclave/build/llvm-gcov.sh --capture -o cov.info
```

The tool will recursively finds and parse all the `.gcda` files. The aggregagted data is saved into `cov.info`.

After that, we can optionally filter out non-interested files.

```
lcov --remove cov.info \
'/home/acc/openclave/tests/*' \
'/home/acc/openclave/3rdparty/libcxx/libcxx/test/*' \
'/home/acc/openclave/3rdparty/musl/libc-test/*' \
'/home/acc/openclave/3rdparty/libunwind/libunwind/tests/*' \
'/home/acc/openclave/3rdparty/libcxxrt/libcxxrt/test/*' \
'/home/acc/openclave/build-cv/tests/*' \
-o cov_no_tests.info
```

The filtered results will be saved into `cov_no_tests.info`.

The last step is using [genhtml](https://linux.die.net/man/1/genhtml) to generate HTML view from the LCOV coverage files.

```
genhtml --prefix openenclave/build \
--ignore-errors \
source cov_no_tests.info \
--legend --title "Open Enclave Code Coverage Test" \
--output-directory=/home/acc/openclave/build/coverage_report
```

The HTML files will be saved into `/home/acc/openclave/build/coverage_report`. The results can be view via browsers.

## Others

### Remove the `.gcda` files
`find . -type f -name '*.gcda' -delete`

### Known issues
- Smaller enclave heap size may cause the program to fail
- The scheme is not thread-safe
