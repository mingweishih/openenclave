// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/trace.h>

#define _sgx_mm_mutex _oe_pthread_mutex

#include "sgx_mm_rt_abstraction.h"
#include "emm_private.h"
#include "platform_t.h"

typedef struct _oe_sgx_enclave_layout
{
    uint64_t address;
    uint64_t size;
    uint64_t type;
    uint64_t permission;
} oe_sgx_enclave_layout_t;

static sgx_mm_pfhandler_t _emm_handler_wrapper;

void sgx_mm_init();

bool sgx_mm_is_within_enclave(const void* addr, size_t size)
{
    return oe_is_within_enclave(addr, size);
}

sgx_mm_mutex *sgx_mm_mutex_create(void)
{
    sgx_mm_mutex *m = (sgx_mm_mutex*)oe_malloc(sizeof(sgx_mm_mutex));

    if (!m)
    {
        OE_TRACE_ERROR("sgx_mm_mutex_create failed\n");
        oe_abort();
    }

    oe_pthread_mutex_init(m, NULL);

    return m;
}

int sgx_mm_mutex_lock(sgx_mm_mutex *mutex)
{
    return oe_pthread_mutex_lock(mutex);
}

int sgx_mm_mutex_unlock(sgx_mm_mutex *mutex)
{
    return oe_pthread_mutex_unlock(mutex);
}

int sgx_mm_mutex_destroy(sgx_mm_mutex *mutex)
{
    int ret = oe_pthread_mutex_destroy(mutex);

    oe_free(mutex);

    return ret;
}

int sgx_mm_alloc_ocall(uint64_t addr, size_t length, int flags)
{
    int ret;

    if (oe_sgx_mm_alloc_ocall(&ret, addr, length, flags) != OE_OK)
    {
        OE_TRACE_ERROR("oe_sgx_mm_alloc_ocall failed\n");
        oe_abort();
    }

    return ret;
}

int sgx_mm_modify_ocall(uint64_t addr, size_t length, int flags_from, int flags_to)
{
    int ret;

    if (oe_sgx_mm_modify_ocall(&ret, addr, length, flags_from, flags_to) != OE_OK)
    {
        OE_TRACE_ERROR("oe_sgx_mm_modify_ocall failed\n");
        oe_abort();
    }

    return ret;
}

static uint64_t _oe_emm_handler(oe_exception_record_t* record)
{
    if (record->code == OE_EXCEPTION_PAGE_FAULT && _emm_handler_wrapper)
    {
        sgx_pfinfo pfinfo = {0};
        pfinfo.maddr = record->faulting_address;
        memcpy(&pfinfo.pfec, &record->error_code, sizeof(uint32_t));
        _emm_handler_wrapper(&pfinfo);
    }

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

bool sgx_mm_register_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    if (oe_add_vectored_exception_handler(false, _oe_emm_handler) != OE_OK)
        return false;

    _emm_handler_wrapper = pfhandler;

    return true;
}

bool sgx_mm_unregister_pfhandler(sgx_mm_pfhandler_t pfhandler)
{
    (void)pfhandler;
    oe_remove_vectored_exception_handler(_oe_emm_handler);
    _emm_handler_wrapper = NULL;
    return true;
}

static void oe_register_emm_layout()
{
    size_t entries_count = __oe_get_layout_entries_size() / sizeof(oe_sgx_enclave_layout_t);

    oe_sgx_enclave_layout_t* layout_entries = (oe_sgx_enclave_layout_t*)__oe_get_layout_entries_base();

    OE_TRACE_INFO("enclave range: 0x%lx - 0x%lx\n",
                   (uint64_t)__oe_get_enclave_base_address(),
                   (uint64_t)__oe_get_enclave_base_address() + __oe_get_enclave_size());

    for (size_t i = 0; i < entries_count; i++)
    {
        if (!layout_entries[i].address)
            break;

        OE_TRACE_INFO("register layout: #%zu addr=0x%lx, size=%zu, type: %zu, permission: %zu\n",
                       i, layout_entries[i].address, layout_entries[i].size, layout_entries[i].type, layout_entries[i].permission);

        int ret = mm_init_ema((void*)layout_entries[i].address,
                        OE_PAGE_SIZE,
                        (int)layout_entries[i].type,
                        (int)layout_entries[i].permission,
                        NULL,
                        NULL);
        if (ret != 0)
        {
            OE_TRACE_ERROR("mm_init_ema failed: ret=%d, addr=0x%lx\n", ret, layout_entries[i].address);
        }
    }
}

void oe_emm_init()
{
    sgx_mm_init();
    oe_register_emm_layout();
}
