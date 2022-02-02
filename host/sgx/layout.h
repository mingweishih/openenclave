// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_SGX_LAYOUT_H
#define _OE_HOST_SGX_LAYOUT_H

#include "enclave.h"

#define OE_SGX_EMA_PAGE_TYPE_RESERVE 0x1
#define OE_SGX_EMA_PAGE_TYPE_SYSTEM  0x80

#define OE_SGX_EMA_PAGE_TYPE_SHIFT 8
#define OE_SGX_EMA_PAGE_TYPE(n) ((n) << OE_SGX_EMA_PAGE_TYPE_SHIFT)
#define OE_SGX_EMA_PAGE_TYPE_MASK      OE_SGX_EMA_PAGE_TYPE(0xFF)
#define OE_SGX_EMA_PAGE_TYPE_TCS       OE_SGX_EMA_PAGE_TYPE(0x1)  /* TCS page type. */
#define OE_SGX_EMA_PAGE_TYPE_REG       OE_SGX_EMA_PAGE_TYPE(0x2)  /* regular page type, default if not specified. */
#define OE_SGX_EMA_PAGE_TYPE_TRIM      OE_SGX_EMA_PAGE_TYPE(0x4)  /* TRIM page type. */
#define OE_SGX_EMA_PAGE_TYPE_SS_FIRST  OE_SGX_EMA_PAGE_TYPE(0x5)  /* the first page in shadow stack. */
#define OE_SGX_EMA_PAGE_TYPE_SS_REST   OE_SGX_EMA_PAGE_TYPE(0x6)  /* the rest pages in shadow stack. */

/* Permissions flags */
#define OE_SGX_EMA_PROT_NONE  0x0
#define OE_SGX_EMA_PROT_READ  0x1
#define OE_SGX_EMA_PROT_WRITE 0x2
#define OE_SGX_EMA_PROT_EXEC  0x4

oe_result_t oe_sgx_add_enclave_layout_entry(
    oe_enclave_t* enclave,
    uint64_t address,
    uint64_t size,
    uint64_t flags);

#endif /* _OE_HOST_SGX_LAYOUT_H */
