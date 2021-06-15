// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

typedef unsigned long size_t;
typedef struct
{
    unsigned __attr;
} pthread_mutexattr_t;
typedef struct
{
    int __i[10];
} pthread_mutex_t;

/* Forward declarations of necessary symbols required by the
 * SymCrypt module. */
void* memcpy(void*, const void*, size_t);
void* memmove(void*, const void*, size_t);
void* memset(void*, int, size_t);
int memcmp(const void*, const void*, size_t);
void free(void*);
int pthread_mutex_destroy(pthread_mutex_t*);
int pthread_mutex_init(pthread_mutex_t*, const pthread_mutexattr_t*);
int pthread_mutex_lock(pthread_mutex_t*);
int pthread_mutex_unlock(pthread_mutex_t*);
int posix_memalign(void**, unsigned long, size_t);
void qsort(void*, size_t, size_t, int (*)(const void*, const void*));
