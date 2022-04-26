// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>

#include <stdlib.h>

#include "emm_t.h"

#include "sgx_mm.h"
#include "sgx_mm_primitives.h"
#include "sgx_mm_rt_abstraction.h"
#include "emm_private.h"

#define PAGE_SIZE 4096

typedef struct _oe_sgx_enclave_layout
{
    uint64_t address;
    uint64_t size;
    uint64_t type;
    uint64_t permission;
} oe_sgx_enclave_layout_t;

void sgx_mm_init();

int oe_eaccept(const sec_info_t*, size_t);
int oe_eacceptcopy(const sec_info_t*, size_t, size_t);
int oe_emodpe(const sec_info_t*, size_t);

int do_eaccept(const sec_info_t* sec_info, size_t addr)
{
    oe_host_printf("[do_eaccept] sec_info=@0x%lx, addr=0x%lx\n",
                   (uint64_t)sec_info, addr);
    int ret = oe_eaccept(sec_info, addr);

    if (ret != 0)
        oe_host_printf("eaccept failed, ret=%d\n", ret);

    return ret;
}

int do_eacceptcopy(const sec_info_t* sec_info, size_t dst, size_t src)
{
    oe_host_printf("[do_eacceptcopy] sec_info=@0x%lx, dst=0x%lx, src=0x%lx\n",
                   (uint64_t)sec_info, dst, src);

    int ret = oe_eacceptcopy(sec_info, dst, src);

    if (ret != 0)
        oe_host_printf("eacceptcopy failed, ret=%d\n", ret);

    return ret;
}

int do_emodpe(const sec_info_t* sec_info, size_t addr)
{
    oe_host_printf("[do_emodpe] sec_info=@0x%lx, addr=0x%lx\n",
                   (uint64_t)sec_info, addr);

    return oe_emodpe(sec_info, addr);
}

bool sgx_mm_is_within_enclave(const void* addr, size_t size)
{
    return oe_is_within_enclave(addr, size);
}

typedef int (*sgx_mm_pfhandler_t)(const sgx_pfinfo *pfinfo);

bool sgx_mm_register_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    (void)(pfhandler);
    return true;
}

bool sgx_mm_unregister_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    (void)(pfhandler);
    return true;
}

typedef oe_pthread_mutex_t sgx_mm_mutex;

sgx_mm_mutex *sgx_mm_mutex_create(void)
{
    sgx_mm_mutex *m = (sgx_mm_mutex*)malloc(sizeof(sgx_mm_mutex));

    if (!m)
        abort();

    oe_pthread_mutex_init(m, NULL);

    return m;
}

int sgx_mm_mutex_lock(sgx_mm_mutex *mutex)
{
    int ret = oe_pthread_mutex_lock(mutex);

    if (!mutex)
        oe_host_printf("sgx_mm_mutex_lock failed with NULL mutex\n");

    return ret;
}

int sgx_mm_mutex_unlock(sgx_mm_mutex *mutex)
{
    int ret = oe_pthread_mutex_unlock(mutex);

    return ret;
}

int sgx_mm_mutex_destroy(sgx_mm_mutex *mutex)
{
    int ret = oe_pthread_mutex_destroy(mutex);

    free(mutex);
    return ret;
}

int sgx_mm_alloc_ocall(uint64_t addr, size_t length, int flags)
{
    int ret;

    if (oe_sgx_mm_alloc_ocall(&ret, addr, length, flags) != OE_OK)
    {
        oe_host_printf("sgx_mm_alloc_ocall failed\n");
        abort();
    }

    return ret;
}

int sgx_mm_modify_ocall(uint64_t addr, size_t length, int flags_from, int flags_to)
{
    int ret;

    if (oe_sgx_mm_modify_ocall(&ret, addr, length, flags_from, flags_to) != OE_OK)
    {
        oe_host_printf("sgx_mm_modify_ocall failed\n");
        abort();
    }

    return ret;

}


void dump_layout_entries()
{
    size_t entries_count = __oe_get_layout_entries_size() / sizeof(oe_sgx_enclave_layout_t);

    oe_sgx_enclave_layout_t* layout_entries = (oe_sgx_enclave_layout_t*)__oe_get_layout_entries_base();

    oe_host_printf("[enclave range] 0x%lx - 0x%lx\n",
                   (uint64_t)__oe_get_enclave_base_address(),
                   (uint64_t)__oe_get_enclave_base_address() + __oe_get_enclave_size());

    for (size_t i = 0; i < entries_count; i++)
    {
        if (!layout_entries[i].address)
            break;

#ifdef DEBUG
        oe_host_printf("[dump layout entry] #%zu addr=0x%lx, size=%zu, type: %zu, permission: %zu\n",
                       i, layout_entries[i].address, layout_entries[i].size, layout_entries[i].type, layout_entries[i].permission);
#endif

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

    //while(1)
    {
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

    ret = sgx_mm_modify_permissions(addr, PAGE_SIZE, SGX_EMA_PROT_NONE);
    if (ret != 0)
        oe_host_printf("sgx_mm_modify_permissions failed %d\n", ret);

    //data[0] = 20;
    }
}

int enc_emm()
{
    oe_host_printf("Hello from Echo function!\n");

    sgx_mm_init();

    dump_layout_entries();

    test_emm();

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
