// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

//__attribute__((weak)) int foo(int a);
int foo(int a);
__attribute__((weak)) int add(int a, int b);
__attribute__((weak)) int sub(int a, int b);
int get_global();

int h;

__attribute__((constructor)) void init_h()
{
    h = 20;
}

__attribute__((destructor)) void fini_h()
{
    h = 0;
}

void enc_call_foo()
{
    printf("foo function defined in secondary module\n");
    int value = foo(8);
    printf("foo(8) = %d\n", value);

    if (add)
    {
        printf("add function defined in secondary module\n");
        int value = add(8, 7);
        printf("add(8, 7) = %d (add adds 500 to result)\n", value);
    }
    else
    {
        printf("add not defined\n");
    }

    if (sub)
    {
        printf("sub function defined in secondary module\n");
        int value = sub(8, 7);
        printf("sub(8, 7) = %d\n", value);
    }
    else
    {
        printf("sub not defined\n");
    }

    printf("h: %d\n", h);
    printf("global: %d\n", get_global());
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    3 * 1024, /* NumHeapPages */
    64,       /* NumStackPages */
    2);       /* NumTCS */
