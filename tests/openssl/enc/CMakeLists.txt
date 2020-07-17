# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl.edl)

add_custom_command(
  OUTPUT openssl_t.h openssl_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  openssl_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/openssl_t.c)

enclave_include_directories(openssl_enc
    PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl/include
    ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)

#add_library(openssl_crypto STATIC IMPORTED)
#set_target_properties(openssl_crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/3rdparty/openssl/install/lib/libcrypto.a)

enclave_link_libraries(openssl_enc opensslcrypto oelibc)
