// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <pthread.h>
#include "init.h"

static pthread_once_t _once = PTHREAD_ONCE_INIT;
static ENGINE* eng;

static void _finialize(void)
{
    if (eng)
    {
        ENGINE_finish(eng);
        ENGINE_free(eng);
        ENGINE_cleanup();
    }
}

static void _initialize(void)
{
    int rc = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Initialize rdrand engine. */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        goto done;
    }

    rc = ENGINE_init(eng);
    if (rc == 0)
    {
        goto done;
    }

    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    if (rc == 0)
    {
        goto done;
    }

    if (!atexit(_finialize))
        goto done;

    rc = 1;

done:
    if (rc == 0)
    {
        _finialize();
    }
    return;
}

void oe_initialize_openssl(void)
{
    pthread_once(&_once, _initialize);
}
