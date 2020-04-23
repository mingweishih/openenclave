# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../code_coverage.edl)

add_custom_command(
    OUTPUT code_coverage_u.h code_coverage_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(code_coverage_host host.c code_coverage_u.c)

target_include_directories(code_coverage_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(code_coverage_host oehostapp)
