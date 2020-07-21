# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(
  oecryptoopenssl
  STATIC
  ${PROJECT_SOURCE_DIR}/common/asn1.c
  ${PROJECT_SOURCE_DIR}/common/cert.c
  ${PROJECT_SOURCE_DIR}/common/kdf.c
  asn1.c
  cert.c
  cmac.c
  crl.c
  ec.c
  hmac.c
  init.c
  key.c
  sha.c
  rsa.c)

maybe_build_using_clangw(oecryptoopenssl)

enclave_enable_code_coverage(oecryptoopenssl)

enclave_link_libraries(oecryptoopenssl PUBLIC opensslcrypto)

set_enclave_property(TARGET oecryptoopenssl PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)

install_enclaves(
  TARGETS
  oecryptoopenssl
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
