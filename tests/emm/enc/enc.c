// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>

#include <stdio.h>
#include <stdlib.h>

#include "emm_t.h"

#define _sgx_mm_mutex _oe_pthread_mutex

#include "emm_private.h"
#include "sgx_mm.h"
#include "sgx_mm_primitives.h"
#include "sgx_mm_rt_abstraction.h"

#define PAGE_SIZE 4096

void oe_emm_init();

typedef struct _oe_sgx_enclave_layout
{
    uint64_t address;
    uint64_t size;
    uint64_t type;
    uint64_t permission;
} oe_sgx_enclave_layout_t;

void sgx_mm_init();

void dump_layout_entries()
{
    size_t entries_count =
        __oe_get_layout_entries_size() / sizeof(oe_sgx_enclave_layout_t);

    oe_sgx_enclave_layout_t* layout_entries =
        (oe_sgx_enclave_layout_t*)__oe_get_layout_entries_base();

    oe_host_printf(
        "[enclave range] 0x%lx - 0x%lx\n",
        (uint64_t)__oe_get_enclave_base_address(),
        (uint64_t)__oe_get_enclave_base_address() + __oe_get_enclave_size());

    for (size_t i = 0; i < entries_count; i++)
    {
        if (!layout_entries[i].address)
            break;

        oe_host_printf(
            "[dump layout entry] #%zu addr=0x%lx, size=%zu, type: %zu, "
            "permission: %zu\n",
            i,
            layout_entries[i].address,
            layout_entries[i].size,
            layout_entries[i].type,
            layout_entries[i].permission);

#if 0
        int ret = mm_init_ema((void*)layout_entries[i].address,
                        PAGE_SIZE,
                        (int)layout_entries[i].type,
                        (int)layout_entries[i].permission,
                        NULL,
                        NULL);
        if (ret != 0)
        {
            oe_host_printf("mm_init_ema failed: ret=%d, addr=0x%lx\n", ret, layout_entries[i].address);
        }
#endif
    }
}

void test_emm()
{
    // Change permissions
    int ret;
    void* addr = NULL;

    oe_host_printf("test sgx_mm_dealloc\n");

    ret = sgx_mm_dealloc(0, PAGE_SIZE);
    if (ret != 22)
    {
        oe_host_printf("sgx_mm_dealloc failed: ret=%d\n", ret);
        abort();
    }

    oe_host_printf("test sgx_mm_dealloc succeeded\n");

    oe_host_printf("test sgx_mm_alloc\n");

    ret = sgx_mm_alloc(NULL, PAGE_SIZE, SGX_EMA_COMMIT_NOW, NULL, NULL, &addr);

    oe_host_printf("test sgx_mm_alloc returned=%d\n", ret);

    if (ret != 0)
    {
        oe_host_printf("sgx_mm_alloc failed: ret=%d\n", ret);
        abort();
    }

    if (addr == NULL)
    {
        oe_host_printf("sgx_mm_alloc failed: addr=0x%lx\n", (uint64_t)addr);
        abort();
    }

    oe_host_printf("test sgx_mm_alloc succeeded: addr=0x%lx\n", (uint64_t)addr);

    uint8_t* data = (uint8_t*)addr;
    data[0] = 10;

    oe_host_printf("data[0] = %u\n", data[0]);

    printf("Change page permission to none...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_NONE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from none to r...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_READ);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from r to w...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_WRITE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission to none...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_NONE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from none to w...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_WRITE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission to none...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_NONE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from none to rw...");
    ret = sgx_mm_modify_permissions(
        addr, PAGE_SIZE, SGX_EMA_PROT_WRITE | SGX_EMA_PROT_READ);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from rw to r...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_READ);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission to none...");
    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_NONE);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");

    printf("Change page permission from none to rwx...");
    ret = sgx_mm_modify_permissions(
        addr, PAGE_SIZE, SGX_EMA_PROT_WRITE | SGX_EMA_PROT_READ | SGX_EMA_PROT_EXEC);
    if (ret != 0)
        printf("failed\n");
    else
        printf("passed\n");
}

static int _handler(const sgx_pfinfo* pfinfo, void* data)
{
    int ret;

    (void)data;

    oe_host_printf("page fault addr=0x%lx\n", pfinfo->maddr);

    ret = sgx_mm_commit((void*)pfinfo->maddr, PAGE_SIZE);
    if (ret != 0)
        oe_host_printf("sgx_mm_commit failed ret=%d\n", ret);

    return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
}

oe_result_t test_emm_alloc_reserve(int custom_handler)
{
    oe_result_t result = OE_UNEXPECTED;
    int ret;
    void* addr = NULL;

    if (custom_handler)
    {
        ret = sgx_mm_alloc(NULL, PAGE_SIZE, SGX_EMA_COMMIT_ON_DEMAND, _handler, NULL, &addr);
        oe_host_printf("sgx_mm_alloc with customized handler\n");
    }
    else
    {
        ret = sgx_mm_alloc(NULL, PAGE_SIZE, SGX_EMA_COMMIT_ON_DEMAND, NULL, NULL, &addr);
        oe_host_printf("sgx_mm_alloc with default handler\n");
    }

    if (ret != 0)
    {
        oe_host_printf("sgx_mm_alloc SGX_EMA_COMMIT_ON_DEMAND failed, r=%d\n", ret);
        goto done;
    }

    oe_host_printf("test accessing to on-demand page addr=0x%p\n", addr);

    uint8_t* data = (uint8_t*)addr;
    data[0] = 10;

    oe_host_printf("test accessing to on-demand page succeeded, data=%u\n", data[0]);

    result = OE_OK;

done:
    return result;
}

int enc_emm()
{
    oe_emm_init();

    dump_layout_entries();

    test_emm();

    test_emm_alloc_reserve(0);

    test_emm_alloc_reserve(1);

    return 0;
}

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    ({0}), /* ExtendedProductID */
    ({0}), /* FamilyID */
    true,  /* Debug */
    true,  /* CapturePFGPExceptions */
    false, /* RequireKSS */
    false, /* CreateZeroBaseEnclave */
    0,     /* StartAddress */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    2);    /* NumTCS */
