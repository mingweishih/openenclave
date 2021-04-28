// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/localtime.h>
#include <openenclave/internal/time.h>
#include <string.h>
#include <time.h>
#include "../ocalls/ocalls.h"

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

/* Return milliseconds elapsed since the Epoch. */
static uint64_t _time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    return ((uint64_t)ts.tv_sec * _SEC_TO_MSEC) +
           ((uint64_t)ts.tv_nsec / _MSEC_TO_NSEC);
}

void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);

    if (arg_out)
        *arg_out = _time();
}

int oe_localtime(time_t* timep, struct tm* result)
{
    return !localtime_r(timep, result);
}

uint64_t timestamps[100];
oe_debug_location_t locations[100];
int timestamps_index;

inline void record_tsc(const char* file, int line, const char* function)
{
    locations[timestamps_index].file = file;
    locations[timestamps_index].line = line;
    locations[timestamps_index].function = function;
    timestamps[timestamps_index] = oe_rdtsc();
    timestamps_index++;
}

void get_timestamps(uint64_t** array, int* count)
{
    *array = timestamps;
    *count = timestamps_index;
}

void reset_timestamps(void)
{
    memset(timestamps, 0, sizeof(timestamps));
    timestamps_index = 0;
}

oe_debug_location_t* get_location_by_index(int index)
{
    return &locations[index];
}
