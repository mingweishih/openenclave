# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_loading.edl)

add_custom_command(
  OUTPUT symcrypt_loading_t.h symcrypt_loading_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET symcrypt_loading_enc CXX SOURCES enc.cpp
            ${CMAKE_CURRENT_BINARY_DIR}/symcrypt_loading_t.c)

enclave_include_directories(
  symcrypt_loading_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/include)

enclave_compile_options(symcrypt_loading_enc PRIVATE -Wno-error)

enclave_compile_definitions(
  symcrypt_loading_enc
  PRIVATE
  -D_AMD64_
  -DINCLUDE_IMPL_CAPI=0
  -DINCLUDE_IMPL_CNG=0
  -DINCLUDE_IMPL_MSBIGNUM=0
  -DINCLUDE_IMPL_RSA32=0)

enclave_link_libraries(
  symcrypt_loading_enc ${CMAKE_CURRENT_SOURCE_DIR}/libsymcrypt.so oelibc
  oehostfs)

configure_file(libsymcrypt.so libsymcrypt.so COPYONLY)
