// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_MODULE_H
#define _OE_INTERNAL_MODULE_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_enclave_module_info
{
    uint64_t base_rva;
    uint64_t init_array_rva;
    uint64_t init_array_size;
    uint64_t fini_array_rva;
    uint64_t fini_array_size;
} oe_enclave_module_info_t;

OE_EXTERNC_END

#endif // _OE_INTERNAL_MODULE_H
