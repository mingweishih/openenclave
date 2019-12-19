# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../name_conflict.edl host gen)

add_executable(name_conflict_host host.cpp ${gen})

target_include_directories(name_conflict_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(name_conflict_host oehostapp)
