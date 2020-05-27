// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>

#ifndef OE_CALLS_H
#define OE_CALLS_H

extern oe_ecall_struct_t _ecall_table[];

uint64_t oe_get_enclave_function_id_by_hash(uint64_t hash);
oe_result_t oe_is_enclave_function_id_valid(uint64_t id);

#endif /* OE_CALLS_H */
