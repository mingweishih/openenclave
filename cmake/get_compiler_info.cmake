# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# This is a helper function to obtain the compiler information
# (e.g., the GNU or clang compiler and its version) that is used
# to generate the pre-built enclave test cases.
#
function(get_compiler_info)
    # Check if the path to the pre-built test cases is specified.
    if (LINUX_BIN_DIR)
        # Search the cmake file that includes the compiler infomation
        # in the auto-generated file from pre-built cmake directories.
        set(target_path ${LINUX_BIN_DIR}/../CMakeFiles)
        file(GLOB subdirs RELATIVE ${target_path} ${target_path}/*)
        # Loop over the sub-directories
        foreach (subdir ${subdirs})
            if(IS_DIRECTORY ${target_path}/${subdir})
                list(APPEND CMAKE_MODULE_PATH ${target_path}/${subdir})
            endif()
        endforeach()
        include(CMakeCXXCompiler OPTIONAL RESULT_VARIABLE found)
        if (found)
            set(ENCLAVE_TESTS_CXX_COMPILER_ID "${CMAKE_CXX_COMPILER_ID}" PARENT_SCOPE)
            set(ENCLAVE_TESTS_CXX_COMPILER_VERSION "${CMAKE_CXX_COMPILER_VERSION}" PARENT_SCOPE)
        endif()
    endif()
endfunction(get_compiler_info)
