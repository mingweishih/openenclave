# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Adapted from https://crascit.com/2016/04/09/using-ccache-with-cmake/
cmake_minimum_required(VERSION 3.4)

find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
  # Set CCACHE_CPP2 to true to decrease compile times when using ccache with clang.
  # On Windows command lines, the 'export VAR=.. &&' form is invalid; instead rely on
  # environment variable propagation or skip setting it explicitly (clang on Windows
  # with MSVC mode does not need CCACHE_CPP2 in the same way). Just invoke ccache directly.
  if (WIN32)
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  else ()
    set(CMAKE_C_COMPILER_LAUNCHER export CCACHE_CPP2=true && "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER export CCACHE_CPP2=true && "${CCACHE_PROGRAM}")
  endif ()
  message(STATUS "Using CCache")
else ()
  message(STATUS "Not using CCache")
endif ()
