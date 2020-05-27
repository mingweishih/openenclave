// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include "hostthread.h"

#ifndef OE_HOST_CALLS_H
#define OE_HOST_CALLS_H

extern oe_ocall_struct_t _ocall_table[];

#define OE_ECALL_ID_NULL OE_UINT64_MAX

oe_result_t oe_handle_call_host_function(uint64_t arg, oe_enclave_t* enclave);
oe_result_t oe_is_host_function_id_valid(uint64_t id);
uint64_t oe_get_host_function_id_by_hash(uint64_t hash);

oe_result_t oe_get_global_enclave_function_id_by_hash(
    oe_enclave_t* enclave,
    uint64_t hash,
    uint64_t* global_id);

void oe_get_function_id_by_hash(uint64_t hash, uint64_t* arg_out);

oe_result_t oe_call_enclave_get_function_id_by_hash(
    oe_enclave_t* enclave,
    uint64_t hash,
    uint64_t* id);

oe_result_t oe_get_enclave_function_id(
    oe_enclave_t* enclave,
    uint64_t global_id,
    uint64_t* id);
oe_result_t oe_set_enclave_function_id(
    oe_enclave_t* enclave,
    uint64_t global_id,
    uint64_t id);

#endif /* OE_HOST_CALLS_H */
