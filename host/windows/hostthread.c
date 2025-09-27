// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../hostthread.h"
#include <assert.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/host.h>

typedef DWORD (*start_routine_t)(void*);

#include <stdlib.h>

struct _oe_thread_start
{
    void* (*func)(void*);
    void* arg;
};

struct _oe_once_wrapper
{
    void (*func)(void);
};

static DWORD WINAPI _oe_thread_trampoline(void* param)
{
    struct _oe_thread_start* ctx = (struct _oe_thread_start*)param;
    void* (*f)(void*) = ctx->func;
    void* a = ctx->arg;
    f(a);
    free(ctx);
    return 0;
}

/*
**==============================================================================
**
** oe_thread
**
**==============================================================================
*/

int oe_thread_create(oe_thread_t* thread, void* (*func)(void*), void* arg)
{
    if (!thread || !func)
        return OE_EINVAL;

    struct _oe_thread_start* ctx =
        (struct _oe_thread_start*)malloc(sizeof(struct _oe_thread_start));
    if (!ctx)
        return OE_EINVAL;
    ctx->func = func;
    ctx->arg = arg;

    HANDLE h = CreateThread(NULL, 0, _oe_thread_trampoline, ctx, 0, NULL);
    if (!h)
    {
        free(ctx);
        return OE_EINVAL;
    }
    *thread = (oe_thread_t)h;
    return 0;
}

int oe_thread_join(oe_thread_t thread)
{
    HANDLE handle = (HANDLE)thread;
    if (WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0)
    {
        CloseHandle(handle);
        return 0;
    }
    return OE_EINVAL;
}

oe_thread_t oe_thread_self(void)
{
    return (oe_thread_t)GetCurrentThreadId();
}

int oe_thread_equal(oe_thread_t thread1, oe_thread_t thread2)
{
    return thread1 == thread2;
}

/*
**==============================================================================
**
** oe_once_type
**
**==============================================================================
*/

static BOOL CALLBACK OnceHelper(
    _Inout_ PINIT_ONCE InitOnce,
    _Inout_opt_ PVOID Parameter,
    _Out_opt_ PVOID* Context)
{
    OE_UNUSED(InitOnce);
    OE_UNUSED(Context);
    struct _oe_once_wrapper* wrapper = (struct _oe_once_wrapper*)Parameter;
    void (*f)(void) = wrapper->func;
    f();
    free(wrapper);
    return TRUE;
}

int oe_once(oe_once_type* once, void (*func)(void))
{
    if (!once || !func)
        return OE_EINVAL;
    struct _oe_once_wrapper* wrapper =
        (struct _oe_once_wrapper*)malloc(sizeof(struct _oe_once_wrapper));
    if (!wrapper)
        return OE_EINVAL;
    wrapper->func = func;
    if (!InitOnceExecuteOnce(once, OnceHelper, wrapper, NULL))
    {
        free(wrapper);
        return OE_EINVAL;
    }
    return 0;
}

/*
**==============================================================================
**
** oe_mutex
**
**==============================================================================
*/

int oe_mutex_init(oe_mutex* Lock)
{
    HANDLE h = CreateMutex(NULL, FALSE, NULL);

    if (h != NULL)
    {
        *Lock = h;
        return 0;
    }
    return 1;
}

int oe_mutex_lock(oe_mutex* Lock)
{
    oe_mutex new_lock;

    if (*Lock == OE_H_MUTEX_INITIALIZER)
    {
        if (oe_mutex_init(&new_lock))
            return 1;
        if (InterlockedCompareExchangePointer(
                Lock, new_lock, OE_H_MUTEX_INITIALIZER) !=
            OE_H_MUTEX_INITIALIZER)
        {
            if (oe_mutex_destroy(&new_lock))
                return 1;
        }
    }

    return WaitForSingleObject(*Lock, INFINITE) != WAIT_OBJECT_0;
}

int oe_mutex_unlock(oe_mutex* Lock)
{
    return !ReleaseMutex(*Lock);
}

int oe_mutex_destroy(oe_mutex* Lock)
{
    return !CloseHandle(*Lock);
}

/*
**==============================================================================
**
** oe_thread_key
**
**==============================================================================
*/

int oe_thread_key_create(oe_thread_key* key)
{
    oe_thread_key k;
    k = TlsAlloc();
    if (k == TLS_OUT_OF_INDEXES)
        return 1;

    *key = k;
    return 0;
}

int oe_thread_key_delete(oe_thread_key key)
{
    return !TlsFree(key);
}

int oe_thread_setspecific(oe_thread_key key, void* value)
{
    return !TlsSetValue(key, value);
}

void* oe_thread_getspecific(oe_thread_key key)
{
    return TlsGetValue(key);
}
