// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "code_coverage_t.h"

int foo(int x, int y)
{
    return x + y;
}

int bar(int x, int y)
{
    return x * y;
}

int enc_code_coverage(int path, int x, int y)
{
    int result = 0;
    switch (path)
    {
        case 1:
            result = foo(x, y);
            break;
        case 2:
            result = bar(x, y);
            break;
        default:
            break;
    }

    return result;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
