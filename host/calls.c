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

#define OE_MAX_OCALLS 256
oe_ocall_struct_t _ocall_table[OE_MAX_OCALLS];
static uint64_t table_size;
static oe_mutex _ocall_tables_lock = OE_H_MUTEX_INITIALIZER;

oe_result_t oe_register_host_functions(
    const oe_ocall_struct_t* ocall_table,
    uint32_t num_ocalls)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Nothing to add when the table is empty, fall through. */
    if (!ocall_table || !num_ocalls)
    {
        result = OE_OK;
        goto done;
    }

    uint32_t i;
    oe_mutex_lock(&_ocall_tables_lock);
    for (i = 0; i < num_ocalls; i++)
    {
        uint64_t hash = ocall_table[i].hash;
        printf("[register_ocalls] %u: hash - %lu\n", i, hash);

        /* The table is full. */
        if (table_size >= OE_MAX_OCALLS)
            OE_RAISE(OE_OUT_OF_BOUNDS);

        /* Each table should be registered only once. */
        /* XXX: Consider raising failts. */
        if (oe_get_host_function_id_by_hash(hash) != OE_OCALL_ID_NULL)
            continue;

        _ocall_table[table_size].ocall = ocall_table[i].ocall;
        _ocall_table[table_size].hash = hash;
        printf("Registered at ocall_table: %lu\n", table_size);
        table_size++;
    }
    oe_mutex_unlock(&_ocall_tables_lock);
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_is_host_function_id_valid(uint64_t id)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!table_size || id > table_size)
        goto done;

    result = OE_OK;

done:
    return result;
}

uint64_t oe_get_host_function_id_by_hash(uint64_t hash)
{
    uint64_t id = OE_OCALL_ID_NULL;
    uint64_t i;

    for (i = 0; i < OE_MAX_OCALLS; i++)
    {
        if (_ocall_table[i].hash == hash)
        {
            id = i;
            break;
        }
    }
    return id;
}

void oe_get_function_id_by_hash(uint64_t hash, uint64_t* arg_out)
{
    uint64_t id = oe_get_host_function_id_by_hash(hash);
    printf("[oe_get_function_id_by_hash] hash: %lu, id: %lu\n", hash, id);
    *arg_out = id;
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
