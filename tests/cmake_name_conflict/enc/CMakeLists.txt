# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../name_conflict.edl enclave gen)

add_enclave(TARGET name_conflict_enc
    UUID 15056a35-a9ae-4c5e-a118-3ff174d61579 SOURCES enc.c ${gen})

add_subdirectory(crypto)
add_subdirectory(dl)

target_include_directories(name_conflict_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR}/crypto
                           ${CMAKE_CURRENT_SOURCE_DIR}/dl)
target_link_libraries(name_conflict_enc oelibc crypto dl)
