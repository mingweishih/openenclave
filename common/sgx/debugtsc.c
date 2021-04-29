// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/internal/time.h>
#include "../common.h"

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

void reset_timestamps()
{
    memset(timestamps, 0, sizeof(timestamps));
    timestamps_index = 0;
}

oe_debug_location_t* get_location_by_index(int index)
{
    return &locations[index];
}
