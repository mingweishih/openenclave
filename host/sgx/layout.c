// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "layout.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/raise.h>

static size_t _layout_entries_index;
static size_t _layout_entries_maxium;

//#define OE_LAYOUT_DEBUG

oe_result_t oe_sgx_add_enclave_layout_entry(
    oe_enclave_t* enclave,
    uint64_t address,
    uint64_t size,
    uint64_t flags)
{
    oe_result_t result = OE_OK;
    uint16_t type = 0;
    uint16_t permission = OE_SGX_EMA_PROT_NONE;

    if (!enclave || !enclave->layout_entries)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!_layout_entries_maxium)
        _layout_entries_maxium =
            enclave->layout_entries_size / sizeof(oe_sgx_enclave_layout_t);

    if (_layout_entries_index >= _layout_entries_maxium)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    type = OE_SGX_EMA_PAGE_TYPE_SYSTEM;
    if (flags & SGX_SECINFO_REG)
        type |= OE_SGX_EMA_PAGE_TYPE_REG;
    else if (flags & SGX_SECINFO_TCS)
        type |= OE_SGX_EMA_PAGE_TYPE_TCS;
    else if (flags & OE_SGX_EMA_PAGE_TYPE_RESERVE)
        type |= OE_SGX_EMA_PAGE_TYPE_RESERVE;
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(type & OE_SGX_EMA_PAGE_TYPE_RESERVE))
    {
        if (flags & SGX_SECINFO_R)
            permission |= OE_SGX_EMA_PROT_READ;

        if (flags & SGX_SECINFO_W)
            permission |= OE_SGX_EMA_PROT_WRITE;

        if (flags & SGX_SECINFO_X)
            permission |= OE_SGX_EMA_PROT_EXEC;
    }

    enclave->layout_entries[_layout_entries_index].address = address;
    enclave->layout_entries[_layout_entries_index].size = size;
    enclave->layout_entries[_layout_entries_index].type = type;
    enclave->layout_entries[_layout_entries_index].permission = permission;

    if (_layout_entries_index > 0)
    {
        uint64_t previous_address =
            enclave->layout_entries[_layout_entries_index - 1].address;
        if (address - previous_address != OE_PAGE_SIZE)
        {
            printf(
                "Found gap between 0x%lx and 0x%lx (%lu pages)\n",
                address,
                previous_address,
                (address - previous_address) / OE_PAGE_SIZE);
            // OE_RAISE(OE_UNEXPECTED);
        }
    }

#ifdef OE_LAYOUT_DEBUG
    printf(
        "[add layout entry] #%zu addr=0x%lx, size=%zu, type: %u, permission: "
        "%u\n",
        _layout_entries_index,
        address,
        size,
        type,
        permission);
#endif

    _layout_entries_index++;

done:

    return result;
}
