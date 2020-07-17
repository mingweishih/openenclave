// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <string.h>
#include "openssl_t.h"

void rand_cleanup_int(void);

#if SET_RAND_METHOD
static int sgxssl_read_rand(unsigned char* buf, int len)
{
    if (buf == NULL || len <= 0)
    {
        return 1;
    }

    if (oe_random((void*)buf, (size_t)len) != OE_OK)
        return 1;

    return 0;
}

static int sgx_rand_status(void)
{
    return 1;
}

static int get_sgx_rand_bytes(unsigned char* buf, int num)
{
    if (sgxssl_read_rand(buf, num) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

RAND_METHOD sgxssl_rand_meth = {
    NULL, /* seed */
    get_sgx_rand_bytes,
    NULL, /* cleanup */
    NULL, /* add */
    get_sgx_rand_bytes,
    sgx_rand_status,
};
#endif

#ifdef DRBG_CALLBACK
static size_t sgx_get_entropy(
    RAND_DRBG* drbg,
    unsigned char** pout,
    int entropy,
    size_t min_len,
    size_t max_len,
    int prediction_resistance)
{
    (void)drbg;
    (void)entropy;
    (void)min_len;
    (void)max_len;
    (void)prediction_resistance;
    static const size_t len = 1024;

    unsigned char* buf = malloc(len);
    if (buf == NULL)
    {
        return 0;
    }

    if (oe_random((void*)buf, len) != OE_OK)
    {
        return 0;
    }

    *pout = buf;
    oe_host_printf("get entropy: done\n");
    return len;
}

static void sgx_cleanup_entropy(
    RAND_DRBG* ctx,
    unsigned char* out,
    size_t outlen)
{
    (void)ctx;
    (void)out;
    (void)outlen;
    if (outlen)
    {
        memset(out, 0, outlen);
        free(out);
    }
    oe_host_printf("cleanup entropy: done\n");
}
#endif

void enc_openssl()
{
    int data = 0;

#ifdef SET_RAND_METHOD
    RAND_set_rand_method(&sgxssl_rand_meth);
#endif

#ifdef DRBG_CALLBACK
    RAND_DRBG* master = NULL;
    master = RAND_DRBG_get0_master();
    if (master == NULL)
    {
        oe_host_printf("cannot get master drbg\n");
        goto done;
    }

    if (RAND_DRBG_uninstantiate(master) != 1)
    {
        oe_host_printf("drbg uninstantiate failed\n");
        goto done;
    }

    if (RAND_DRBG_set_callbacks(
            master, sgx_get_entropy, sgx_cleanup_entropy, NULL, NULL) == 0)
    {
        oe_host_printf("drbg set callbacks failed\n");
        goto done;
    }
#endif

    int rc = 0;

    ENGINE_load_rdrand();
    ENGINE* eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        oe_host_printf("ENGINE_by_id failed\n");
        goto done;
    }

    rc = ENGINE_init(eng);
    if (rc == 0)
    {
        oe_host_printf("ENGINE_init failed\n");
        goto done;
    }

    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    if (rc == 0)
    {
        oe_host_printf("ENGINE_set_default failed\n");
        goto done;
    }

    data = 0;
    if (!RAND_bytes((unsigned char*)&data, sizeof(data)))
        oe_host_printf("RAND_bytes failed\n");

    oe_host_printf("test openssl rand: %d\n", data);

    data = 0;
    if (!RAND_priv_bytes((unsigned char*)&data, sizeof(data)))
        oe_host_printf("RAND_priv_bytes failed\n");

    oe_host_printf("test openssl priv rand: %d\n", data);
done:
#ifdef SET_RAND_METHOD
    rand_cleanup_int();
#endif

    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();

    return;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
