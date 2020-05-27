// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>

#include "calls.h"

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

/*
**==============================================================================
**
** oe_register_ecall_function_table()
**
** Register an ecall table with the given table_id.
**
**==============================================================================
*/

#define OE_MAX_ECALLS 256
oe_ecall_struct_t _ecall_table[OE_MAX_ECALLS];
static uint64_t _table_size;
static oe_spinlock_t _ecall_tables_lock = OE_SPINLOCK_INITIALIZER;

uint64_t oe_get_enclave_function_id_by_hash(uint64_t hash)
{
    uint64_t id = OE_ECALL_FUNCTION_ID_NULL;
    uint64_t i;

    for (i = 0; i < OE_MAX_ECALLS; i++)
    {
        if (_ecall_table[i].hash == hash)
        {
            id = i;
            break;
        }
    }
    return id;
}

oe_result_t oe_register_enclave_functions_internal(
    const oe_ecall_struct_t* ecall_table,
    uint32_t num_ecalls)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t i;

    /* Nothing to add when the table is empty, fall through. */
    if (!ecall_table || !num_ecalls)
    {
        result = OE_OK;
        goto done;
    }

    oe_spin_lock(&_ecall_tables_lock);
    for (i = 0; i < num_ecalls; i++)
    {
        uint64_t hash = ecall_table[i].hash;

        /* The table is full. */
        if (_table_size >= OE_MAX_ECALLS)
            OE_RAISE(OE_OUT_OF_BOUNDS);

        /* Each table should be registered only once. */
        /* XXX: Consider raising faults. */
        if (oe_get_enclave_function_id_by_hash(hash) !=
            OE_ECALL_FUNCTION_ID_NULL)
            continue;

        _ecall_table[_table_size].ecall = ecall_table[i].ecall;
        _ecall_table[_table_size].hash = hash;
        _table_size++;
    }
    oe_spin_unlock(&_ecall_tables_lock);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_is_enclave_function_id_valid(uint64_t id)
{
    oe_result_t result = OE_FAILURE;
    uint64_t table_size;

    oe_spin_lock(&_ecall_tables_lock);
    table_size = _table_size;
    oe_spin_unlock(&_ecall_tables_lock);

    if (!table_size || id > table_size)
        goto done;

    result = OE_OK;

done:
    return result;
}
