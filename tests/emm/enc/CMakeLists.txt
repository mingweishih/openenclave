# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../emm.edl)

add_custom_command(
  OUTPUT emm_t.h emm_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  emm_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/emm_t.c)

enclave_include_directories(emm_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
enclave_link_libraries(emm_enc oelibc ${CMAKE_CURRENT_SOURCE_DIR}/libsgx_mm.a)

configure_file(libsgx_mm.a libsgx_mm.a COPYONLY)
