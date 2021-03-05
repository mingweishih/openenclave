# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/enc)
  add_subdirectory(sm)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/scmml scmml_host scmml_enc)
