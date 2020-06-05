// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file host.h
 *
 * This file defines the internal functions and data-structures used by
 * oeedger8r generated code on the host side.
 * These internals are subject to change without notice.
 *
 */
#ifndef _OE_EDGER8R_HOST_H
#define _OE_EDGER8R_HOST_H

#ifdef _OE_EDGER8R_ENCLAVE_H
#error \
    "edger8r/enclave.h and edger8r/host.h must not be included in the same compilation unit."
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/host.h> // for oe_ocall_func_t

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

OE_EXTERNC_BEGIN

/**
 * Perform a high-level enclave function call (ECALL).
 *
 * Call the enclave function that matches the given function-id.
 * The enclave function is expected to have the following signature:
 *
 *     void (const uint8_t* input_buffer,
 *           size_t input_buffer_size,
 *           uint8_t* output_buffer,
 *           size_t output_buffer_size,
 *           size_t* output_bytes_written);
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme via the arguments or return value.
 *
 * @param function_id The id of the enclave function that will be called.
 * @param input_buffer Buffer containing inputs data.
 * @param input_buffer_size Size of the input data buffer.
 * @param output_buffer Buffer where the outputs of the host function are
 * written to.
 * @param output_buffer_size Size of the output buffer.
 * @param output_bytes_written Number of bytes written in the output buffer.
 *
 * @return OE_OK the call was successful.
 * @return OE_NOT_FOUND if the function_id does not correspond to a function.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_FAILURE the call failed.
 * @return OE_BUFFER_TOO_SMALL the input or output buffer was smaller than
 * expected.
 *
 */
oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint64_t* host_caching_id,
    uint64_t function_hash,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

oe_result_t oe_register_host_functions(
    const oe_ocall_struct_t* ocall_table,
    uint32_t num_ocalls);

#define OE_GLOBAL_ECALL_ID_NULL OE_UINT64_MAX

oe_result_t oe_host_register_enclave_functions(
    oe_enclave_t* enclave,
    const uint64_t* ecall_hash_table,
    uint32_t num_ecalls);

/**
 * Placeholder.
 */
oe_result_t oe_switchless_call_enclave_function(
    oe_enclave_t* enclave,
    uint64_t function_id,
    uint64_t function_hash,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/*
 * In some instances oeedger8r generates the same code for both the host and
 * enclave side. Since enclave applications are not required to link stdc,
 * the edger8r uses oe-specific implementations. For the host side, simply
 * implement these functions as wrappers for the stdc functions since oehost
 * has a hard dependancy on stdc.
 */

OE_INLINE void* oe_malloc(size_t size)
{
    return malloc(size);
}

OE_INLINE size_t oe_strlen(const char* s)
{
    return strlen(s);
}

OE_INLINE size_t oe_wcslen(const wchar_t* s)
{
    return wcslen(s);
}

#if __GNUC__
#define EDGER8R_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))
#elif _MSC_VER
#define EDGER8R_WEAK_ALIAS(OLD, NEW) \
    __pragma(comment(linker, "/alternatename:" #NEW "=" #OLD))
#else
#error OE_WEAK_ALIAS not implemented
#endif

// Statically defined functions which are aliased should be marked as unused
// to prevent compiler warnings in GCC and Clang
#if __GNUC__
#define EDGER8R_UNUSED __attribute__((unused))
#elif _MSC_VER
#define EDGER8R_UNUSED
#else
#error EDGER8R_UNUSED not implemented
#endif

OE_EXTERNC_END

#endif // _OE_EDGER8R_HOST_H
