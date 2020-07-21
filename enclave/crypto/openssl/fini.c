// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/crypto.h>

void oe_cleanup_openssl()
{
    OPENSSL_cleanup();
}