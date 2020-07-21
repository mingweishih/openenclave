// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_EC_OPENSSL_H
#define _OE_ENCLAVE_CRYPTO_EC_OPENSSL_H

#include <openenclave/internal/crypto/ec.h>
#include <openssl/evp.h>

/* Caller is responsible for validating parameters */
void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey);

void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey);

#endif /* _OE_ENCLAVE_CRYPTO_EC_OPENSSL_H */
