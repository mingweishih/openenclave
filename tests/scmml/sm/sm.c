// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

int global;

__attribute__((constructor)) void init_global()
{
    global = 5;
}

__attribute__((destructor)) void fini_global()
{
    global = 0;
}

int get_global()
{
    return global;
}

int foo(int a)
{
    return a * a;
}

int k = 500;

int add(int a, int b)
{
    return a + b + k;
}

void _start()
{
}
