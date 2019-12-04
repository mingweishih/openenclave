// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/app.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <stdio.h>
#include <string.h>

oe_result_t oe_app_verify_signature(
    const oe_app_signature_t* signature,
    const oe_app_policy_t* policy,
    const oe_app_hash_t* appid,
    const oe_app_hash_t* apphash)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_rsa_public_key_t pubkey;
    bool pubkey_initialized = false;
    oe_app_hash_t hash;

    /* Check the parameters. */
    if (!signature || !policy || !appid || !apphash)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the composite hash of the appid and apphash. */
    {
        oe_sha256_context_t context;
        OE_SHA256 sha256;

        oe_sha256_init(&context);
        oe_sha256_update(&context, appid->buf, sizeof(*appid));
        oe_sha256_update(&context, apphash->buf, sizeof(*apphash));
        oe_sha256_final(&context, &sha256);

        memcpy(hash.buf, sha256.buf, sizeof(hash));
    }

    if (memcmp(signature->apphash.buf, apphash, OE_APP_HASH_SIZE) != 0)
        OE_RAISE(OE_FAILURE);

    /* Check that the signers are the same. */
    if (memcmp(
            signature->signer.buf, policy->signer.buf, sizeof policy->signer) !=
        0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the RSA key from the policy. */
    OE_CHECK(oe_rsa_public_key_init_from_binary(
        &pubkey,
        policy->pubkey.modulus,
        sizeof(policy->pubkey.modulus),
        policy->pubkey.exponent,
        sizeof(policy->pubkey.exponent)));
    pubkey_initialized = true;

    /* Verify that the signer signed the hash. */
    OE_CHECK(oe_rsa_public_key_verify(
        &pubkey,
        OE_HASH_TYPE_SHA256,
        hash.buf,
        sizeof(hash),
        signature->signature,
        sizeof(signature->signature)));

    result = OE_OK;

done:

    if (pubkey_initialized)
        oe_rsa_public_key_free(&pubkey);

    return result;
}
