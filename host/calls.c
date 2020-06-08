// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/raise.h>

#include "calls.h"

/*
**==============================================================================
**
** oe_register_ocall_function_table()
**
** Register an ocall table with the given table_id.
**
**==============================================================================
*/

ocall_table_t _ocall_tables[OE_MAX_OCALL_TABLES];
static oe_mutex _ocall_tables_lock = OE_H_MUTEX_INITIALIZER;

oe_result_t oe_register_ocall_function_table(
    uint64_t table_id,
    const oe_ocall_func_t* ocalls,
    uint32_t num_ocalls)
{
    oe_result_t result = OE_UNEXPECTED;

    printf("[oe_register_ocall_function_table] id: %lu\n", table_id);
    if (table_id >= OE_MAX_OCALL_TABLES || !ocalls)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_mutex_lock(&_ocall_tables_lock);
    _ocall_tables[table_id].ocalls = ocalls;
    _ocall_tables[table_id].num_ocalls = num_ocalls;
    oe_mutex_unlock(&_ocall_tables_lock);

    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** oe_call_enclave_function()
**
** Call the enclave function specified by the given function-id.
**
**==============================================================================
*/

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint64_t* global_function_id,
    uint64_t function_hash,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_enclave_function_args_t args;
    uint64_t function_id = OE_ECALL_ID_NULL;
    static oe_mutex _ecall_lock = OE_H_MUTEX_INITIALIZER;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_mutex_lock(&_ecall_lock);
    if (*global_function_id == OE_GLOBAL_ECALL_ID_NULL)
    {
        OE_CHECK(oe_get_global_enclave_function_id_by_hash(
            enclave, function_hash, global_function_id));
    }
    oe_mutex_unlock(&_ecall_lock);

    OE_CHECK(
        oe_get_enclave_function_id(enclave, *global_function_id, &function_id));
    if (function_id == OE_ECALL_ID_NULL)
    {
        oe_call_enclave_get_function_id_by_hash(
            enclave, function_hash, &function_id);
        OE_CHECK(oe_set_enclave_function_id(
            enclave, *global_function_id, function_id));
    }

    /* Initialize the call_enclave_args structure */
    {
        args.function_id = function_id;
        args.function_hash = function_hash;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t arg_out = 0;

        OE_CHECK(oe_ecall(
            enclave,
            OE_ECALL_CALL_ENCLAVE_FUNCTION,
            (uint64_t)&args,
            &arg_out));
        OE_CHECK((oe_result_t)arg_out);
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_call_enclave_get_function_id_by_hash(
    oe_enclave_t* enclave,
    uint64_t hash,
    uint64_t* id)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Perform the ECALL */
    OE_CHECK(oe_ecall(enclave, OE_ECALL_GET_FUNCTION_ID_BY_HASH, hash, id));

    /* Validate the result */
    if (*id == OE_ECALL_FUNCTION_ID_NULL)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:
    return result;
}
