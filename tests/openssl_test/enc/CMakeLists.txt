# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl_test.edl)

add_custom_command(
  OUTPUT openssl_test_t.h openssl_test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  openssl_test_enc
  CRYPTO_LIB
  openssl
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/openssl_test_t.c)

enclave_include_directories(
  openssl_test_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OE_INCDIR}/openenclave)

enclave_link_libraries(openssl_test_enc oehostsock oehostfs oehostresolver)
