// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "code_coverage_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH arg\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_code_coverage_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    int path = atoi(argv[2]);

    int return_val;

    printf("Test path: %d", path);
    result = enc_code_coverage(enclave, &return_val, path, 10, 20);
    switch (path)
    {
        case 1:
            OE_TEST(return_val == 30); // 10 + 20 == 30
            break;
        case 2:
            OE_TEST(return_val == 200); // 10 * 20 == 200
            break;
        default:
            break;
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (code_coverage)\n");

    return 0;
}
