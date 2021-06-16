# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_loading.edl)

add_custom_command(
  OUTPUT symcrypt_loading_u.h symcrypt_loading_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(symcrypt_loading_host host.c symcrypt_loading_u.c)

target_include_directories(symcrypt_loading_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(symcrypt_loading_host oehost)
