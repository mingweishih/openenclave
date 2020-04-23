# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../code_coverage.edl)

add_custom_command(
    OUTPUT code_coverage_t.h code_coverage_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET code_coverage_enc UUID 71b0822f-42a3-4543-a97c-ca491f76b82c SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/code_coverage_t.c)

if (CODE_COVERAGE_TEST)
    # Enable code coverage.
    enclave_compile_options(oehostresolver PRIVATE -fprofile-arcs -ftest-coverage)
endif()

enclave_include_directories(code_coverage_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(code_coverage_enc oelibc)
