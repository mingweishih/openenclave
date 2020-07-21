// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_RSA_OPENSSL_H
#define _OE_ENCLAVE_CRYPTO_RSA_OPENSSL_H

#include <openssl/evp.h>

#include <openenclave/internal/rsa.h>

/* Caller is responsible for validating parameters */
void oe_rsa_public_key_init(oe_rsa_public_key_t* public_key, EVP_PKEY* pkey);

#endif /* _OE_ENCLAVE_CRYPTO_RSA_OPENSSL_H */
