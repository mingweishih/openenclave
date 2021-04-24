// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_get_time()
**
**     Return milliseconds elapsed since the Epoch or (uint64_t)-1 on error.
**
**     The Epoch is defined as: 1970-01-01 00:00:00 +0000 (UTC)
**
**==============================================================================
*/

uint64_t oe_get_time(void);

#ifdef _WIN32
/*
**==============================================================================
**
** gettimeofday()
**
**     Get seconds and useconds elapsed since the Epoch.
**
**==============================================================================
*/

int gettimeofday(struct timeval* tv, struct timezone* tz);
#endif

typedef struct _oe_debug_location_t
{
    const char* file;
    int line;
    const char* function;
} oe_debug_location_t;

uint64_t oe_rdtsc();
void record_tsc(const char* file, int line, const char* function);
void get_timestamps(uint64_t** array, int* count);
void reset_timestamps(void);
oe_debug_location_t* get_location_by_index(int index);

#define RECORD_TSC()                                  \
    do                                                \
    {                                                 \
        record_tsc(__FILE__, __LINE__, __FUNCTION__); \
    } while (0)

OE_EXTERNC_END

#endif /* _OE_INCLUDE_TIME_H */
