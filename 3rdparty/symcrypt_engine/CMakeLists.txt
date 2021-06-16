# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
set(SYMCRYPT_ENGINE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/SymCryptEngine)

add_enclave_library(
  symcryptengine
  STATIC
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_ciphers.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_dh.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_digests.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_dsa.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_ecc.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_helpers.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_hkdf.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_pkey_asn1_meths.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_pkey_meths.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_rand.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_rsa.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_rsapss.c
  ${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt_tls1prf.c)

set_target_properties(symcryptengine PROPERTIES PUBLIC_HEADER ${SYMCRYPT_ENGINE_DIR}/inc/e_symcrypt.h)

enclave_compile_definitions(
  symcryptengine
  PUBLIC
  -D_AMD64_
  -DDBG)

set_source_files_properties(${SYMCRYPT_ENGINE_DIR}/src/e_symcrypt.c PROPERTIES COMPILE_FLAGS " -fvisibility=default")

enclave_include_directories(
  symcryptengine
  PRIVATE
  ${SYMCRYPT_ENGINE_DIR}/inc
  ${SYMCRYPT_ENGINE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/inc
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include # for opensslconf.h
  ${OPENSSL_DIR}/include)

maybe_build_using_clangw(symcryptengine)

enclave_compile_options(symcryptengine
  PRIVATE
  -Wno-shorten-64-to-32
  -Wno-sign-conversion
  -Wno-pointer-sign
  -Wno-unknown-pragmas
  -Wno-unused-function
  -Wno-unused-variable
  -Wno-bitwise-op-parentheses
  -Wno-unused-parameter
  -Wno-implicit-int-conversion
  -Wno-implicit-int-float-conversion
  -Wno-incompatible-pointer-types-discards-qualifiers
  -Wno-unused-label
  -Wno-sign-compare
  -Wno-shift-op-parentheses)

add_enclave_dependencies(symcryptengine openssl_generated)

enclave_link_libraries(symcryptengine PUBLIC oelibcxx oe_includes)

#install_enclaves(
#    TARGETS
#    symcryptengine
#    EXPORT
#    openenclave-targets)
