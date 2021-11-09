// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "../../../host/strings.h"
#include "../../../host/sgx/sgx_enclave_common_wrapper.h"
#include "emm_u.h"

int oe_sgx_mm_alloc_ocall(uint64_t addr, size_t length, int flags)
{
    int ret = oe_sgx_enclave_alloc(addr, length, flags);

    printf("[host] sgx_mm_alloc_ocall ret=%d\n", ret);

    return ret;
}

int oe_sgx_mm_modify_ocall(uint64_t addr, size_t length, int flags_from, int flags_to)
{
    int ret = oe_sgx_enclave_modify(addr, length, flags_from, flags_to);

    printf("[host] sgx_mm_modify_ocall ret=%d\n", ret);

    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_emm_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    int return_val;

    result = enc_emm(enclave, &return_val);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (emm)\n");

    return 0;
}
