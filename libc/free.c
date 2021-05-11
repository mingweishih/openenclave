// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>

void free(void* ptr)
{
    oe_free(ptr);
}
