// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_MALLOC_H
#define _OE_BITS_MALLOC_H

OE_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return oe_calloc(nmemb, size);
}

OE_INLINE
void* realloc(void* ptr, size_t size)
{
    return oe_realloc(ptr, size);
}

OE_INLINE
void* memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}

OE_INLINE
size_t malloc_usable_size(void* ptr)
{
    return oe_malloc_usable_size(ptr);
}

#endif /* _OE_BITS_MALLOC_H */
