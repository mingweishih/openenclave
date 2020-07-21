// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_CRL_OPENSSL_H
#define _OE_ENCLAVE_CRYPTO_CRL_OPENSSL_H

#include <openenclave/internal/crypto/crl.h>
#include <openssl/x509.h>

typedef struct _crl
{
    uint64_t magic;
    X509_CRL* crl;
} crl_t;

// needed in oe_cert_verify in cert.c
bool crl_is_valid(const crl_t* impl);

#endif /* _OE_ENCLAVE_CRYPTO_CRL_OPENSSL_H */
