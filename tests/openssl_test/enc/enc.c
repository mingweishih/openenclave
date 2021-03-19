// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openssl_test_t.h"

#include <netdb.h>

void test()
{
    BIO_lookup(NULL, NULL, 0, 0, 0, NULL);
}

# if 0
int *__h_errno_location(void)
{
	return NULL;
}


struct servent *getservbyname(const char* name, const char* prots)
{
    (void)name;
    (void)prots;

    return NULL;
}

int pthread_setcancelstate(int a, int *b)
{
    (void)a;
    (void)b;

    return 0;
}

struct __ptcb {
	void (*__f)(void *);
	void *__x;
	struct __ptcb *__next;
};

void _pthread_cleanup_push(struct __ptcb *a, void (*f)(void *), void *b)
{
    (void)a;
    (void)f;
    (void)b;
}

void _pthread_cleanup_pop(struct __ptcb *a, int b)
{
    (void)a;
    (void)b;
}
#endif


OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
