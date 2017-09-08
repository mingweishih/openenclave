#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include "td.h"

typedef unsigned long long WORD;

#define WORD_SIZE sizeof(WORD)

/*
**==============================================================================
**
** OE_HostMalloc()
**
**     Allocate N bytes from the host heap (via OCALL)
**
**==============================================================================
*/

void* OE_HostMalloc(size_t size)
{
    uint64_t argIn = size;
    uint64_t argOut = 0;

    if (__OE_OCall(OE_FUNC_MALLOC, argIn, &argOut) != OE_OK)
    {
        return NULL;
    }

    return (void*)argOut;
}

/*
**==============================================================================
**
** OE_HostCalloc()
**
**     Allocate N bytes from the host heap (via OCALL) and zero-fill
**
**==============================================================================
*/

void* OE_HostCalloc(size_t nmemb, size_t size)
{
    void* ptr = OE_HostMalloc(nmemb * size);

    if (ptr)
        OE_Memset(ptr, 0, nmemb * size);

    return ptr;
}

/*
**==============================================================================
**
** OS_HostFree()
**
**     Ask host to OE_Free memory allocated by OE_HostMalloc()
**
**==============================================================================
*/

void OE_HostFree(void* ptr)
{
    __OE_OCall(OE_FUNC_FREE, (uint64_t)ptr, NULL);
}

/*
**==============================================================================
**
** OE_HostStrdup()
**
**==============================================================================
*/

char* OE_HostStrdup(const char* str)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = OE_Strlen(str);

    if (!(p = OE_HostMalloc(len + 1)))
        return NULL;

    OE_Memcpy(p, str, len + 1);

    return p;
}
