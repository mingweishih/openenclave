// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>

int posix_memalign(void** res, size_t align, size_t len)
{
    return oe_posix_memalign(res, align, len);
}
