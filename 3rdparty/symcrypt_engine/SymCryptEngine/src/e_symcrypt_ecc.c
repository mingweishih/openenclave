#include "e_symcrypt_ecc.h"
#include "e_symcrypt_helpers.h"
#include <symcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*PFN_eckey_sign)(
                            int type, const unsigned char* dgst, int dlen,
                            unsigned char* sig, unsigned int* siglen,
                            const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey);
typedef int (*PFN_eckey_sign_setup)(
                            EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp,
                            BIGNUM** rp);
typedef ECDSA_SIG* (*PFN_eckey_sign_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const BIGNUM* in_kinv, const BIGNUM* in_r,
                            EC_KEY* eckey);
typedef int (*PFN_eckey_verify)(
                            int type, const unsigned char* dgst, int dgst_len,
                            const unsigned char* sigbuf, int sig_len, EC_KEY* eckey);
typedef int (*PFN_eckey_verify_sig)(
                            const unsigned char* dgst, int dgst_len,
                            const ECDSA_SIG* sig, EC_KEY* eckey);
typedef int (*PFN_eckey_init)(EC_KEY *key);
typedef void (*PFN_eckey_finish)(EC_KEY *key);
typedef int (*PFN_eckey_copy)(EC_KEY *dest, const EC_KEY *src);
typedef int (*PFN_eckey_set_group)(EC_KEY *key, const EC_GROUP *grp);
typedef int (*PFN_eckey_set_private)(EC_KEY *key, const BIGNUM *priv_key);
typedef int (*PFN_eckey_set_public)(EC_KEY *key, const EC_POINT *pub_key);

typedef int (*PFN_eckey_keygen)(EC_KEY *key);
typedef int (*PFN_eckey_compute_key)(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh);

typedef struct _SYMCRYPT_ECC_KEY_CONTEXT {
    int initialized;
    // Pointer to memory buffer holding private/public key data as it is transferred between OpenSSL
    // and SymCrypt formats
    // Must be cleared before freeing (using OPENSSL_clear_free)
    PBYTE data;
    SIZE_T cbData;
    PSYMCRYPT_ECKEY key;
} SYMCRYPT_ECC_KEY_CONTEXT;

int eckey_symcrypt_idx = -1;


// If r and s are both 0, the DER encoding would be 8 bytes
// (0x30 0x06 0x02 0x01 0x00 0x02 0x01 0x00)
// integers must contain at least 1 octet of content in DER
#define SYMCRYPT_ECDSA_MIN_DER_SIGNATURE_LEN 8
// Largest supported curve is P521 => 66 * 2 + 4 (int headers) + 3 (seq header)
#define SYMCRYPT_ECDSA_MAX_DER_SIGNATURE_LEN 139

// Smallest supported curve is P256 => 32 * 2 byte SymCrypt signatures
#define SYMCRYPT_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN 64
// Largest supported curve is P521 => 66 * 2 byte SymCrypt signatures
#define SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN 132

// Largest support curve is P521 => 66 * 2 byte Public key
#define SYMCRYPT_ECDH_MAX_PUBLIC_KEY_LEN 132

static int symcrypt_ecdsa_der_check_tag_and_get_value_and_length(
    PCBYTE pbDerField, SIZE_T cbDerField, BYTE expectedTag, PCBYTE* ppbContent, SIZE_T* pcbContent )
{
    PCBYTE pbContent = NULL;
    SIZE_T cbContent = 0;
    int res = 0; // fail

    // Check for tag
    if( pbDerField[0] != expectedTag )
    {
        SYMCRYPT_LOG_ERROR("pbDerField[0] != 0x%x", expectedTag);
        SYMCRYPT_LOG_BYTES_DEBUG("pbDerField", pbDerField, cbDerField);
        goto err;
    }

    // Extract content length and pointer to beginning of content
    cbContent = pbDerField[1];
    pbContent = pbDerField+2;
    if( cbContent > 0x7f )
    {
        // Only acceptable length with long form has 1 byte length
        if( cbContent == 0x81 )
        {
            if( pbDerField[2] > 0x7f )
            {
                cbContent = pbDerField[2];
                pbContent = pbDerField+3;
            }
            else
            {
                SYMCRYPT_LOG_ERROR("Der element length field is not minimal");
                goto err;
            }
        }
        else
        {
            SYMCRYPT_LOG_ERROR("Unexpected length field encoding. pbDerField[1] == 0x%x", cbContent);
            goto err;
        }
    }

    if( (pbContent + cbContent) - pbDerField > cbDerField  )
    {
        SYMCRYPT_LOG_ERROR("Decoded content length does not fit in derField buffer. pbDerField [0x%lx, 0x%lx), pbContent [0x%lx, 0x%lx)",
                            pbDerField, pbDerField+cbDerField, pbContent, pbContent+cbContent);
        goto err;
    }

    *ppbContent = pbContent;
    *pcbContent = cbContent;

    res = 1;
err:
    return res;
}

// Quick hack function to parse precisely the DER encodings which we expect for ECDSA signatures for the NIST prime curves
// Extracts the encoded R and S and places them in a buffer with 2 same-sized big-endian encodings (BER encoding expected by SymCrypt)
static int symcrypt_ecdsa_remove_der(PCBYTE pbDerSignature, SIZE_T cbDerSignature, PBYTE pbSymCryptSignature, SIZE_T cbSymCryptSignature)
{
    PCBYTE pbSeq = NULL;
    SIZE_T cbSeq = 0;
    PCBYTE pbR = NULL;
    SIZE_T cbR = 0;
    PCBYTE pbS = NULL;
    SIZE_T cbS = 0;
    int res = 0; // fail

    // Check the provided lengths are within reasonable bounds
    if( (cbDerSignature < SYMCRYPT_ECDSA_MIN_DER_SIGNATURE_LEN) ||
        (cbDerSignature > SYMCRYPT_ECDSA_MAX_DER_SIGNATURE_LEN) ||
        (cbSymCryptSignature < SYMCRYPT_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature > SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature % 2 == 1) )
    {
        SYMCRYPT_LOG_ERROR("Incorrect size: cbDerSignature %d should be in range [%d, %d]\n" \
                           "                cbSymCryptSignature %d should be even integer in range [%d, %d]",
                           cbDerSignature, SYMCRYPT_ECDSA_MIN_DER_SIGNATURE_LEN, SYMCRYPT_ECDSA_MAX_DER_SIGNATURE_LEN,
                           cbSymCryptSignature, SYMCRYPT_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN, SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN );
        goto err;
    }

    SYMCRYPT_LOG_BYTES_DEBUG("pbDerSignature", pbDerSignature, cbDerSignature);


    if( symcrypt_ecdsa_der_check_tag_and_get_value_and_length(
            pbDerSignature, cbDerSignature, 0x30, &pbSeq, &cbSeq) == 0 )
    {
        goto err;
    }

    if( pbSeq - pbDerSignature != cbDerSignature - cbSeq )
    {
        SYMCRYPT_LOG_ERROR("Sequence length field (0x%x) does not match cbDerSignature (0x%x)", cbSeq, cbDerSignature);
        SYMCRYPT_LOG_BYTES_DEBUG("pbDerSignature", pbDerSignature, cbDerSignature);
        goto err;
    }

    SYMCRYPT_LOG_BYTES_DEBUG("pbSeq", pbSeq, cbSeq);

    if( symcrypt_ecdsa_der_check_tag_and_get_value_and_length(
            pbSeq, cbSeq, 0x02, &pbR, &cbR) == 0 )
    {
        goto err;
    }

    if( cbR > cbSeq - 4 )
    {
        SYMCRYPT_LOG_ERROR("cbR = pbSeq[1] > cbSeq - 4");
        SYMCRYPT_LOG_BYTES_ERROR("pbDerSignature", pbDerSignature, cbDerSignature);
        goto err;
    }

    SYMCRYPT_LOG_BYTES_DEBUG("pbR", pbR, cbR);

    if( symcrypt_ecdsa_der_check_tag_and_get_value_and_length(
            pbR+cbR, (pbSeq+cbSeq)-(pbR+cbR), 0x02, &pbS, &cbS) == 0 )
    {
        goto err;
    }

    SYMCRYPT_LOG_BYTES_DEBUG("pbS", pbS, cbS);

    // Check R's validity
    if( ((pbR[0] & 0x80) == 0x80) || // R is negative
        ((cbR > 1) && (pbR[0] == 0x00) && ((pbR[1] & 0x80) != 0x80)) ) // R is non-zero, and has a redundant leading 0 byte
    {
        SYMCRYPT_LOG_ERROR("pbR is not strict DER encoded non-negative integer");
        SYMCRYPT_LOG_BYTES_ERROR("pbR", pbR, cbR);
        goto err;
    }
    // Trim leading 0 from R
    if( pbR[0] == 0 )
    {
        pbR++;
        cbR--;
    }
    // Check S's validity
    if( ((pbS[0] & 0x80) == 0x80) || // S is negative
        ((cbS > 1) && (pbS[0] == 0x00) && ((pbS[1] & 0x80) != 0x80)) ) // S is non-zero, and has a redundant leading 0 byte
    {
        SYMCRYPT_LOG_ERROR("pbS is not strict DER encoded non-negative integer");
        SYMCRYPT_LOG_BYTES_ERROR("pbS", pbS, cbS);
        goto err;
    }
    // Trim leading 0 from S
    if( pbS[0] == 0 )
    {
        pbS++;
        cbS--;
    }

    if( (cbSymCryptSignature < 2*cbR) || (cbSymCryptSignature < 2*cbS) )
    {
        SYMCRYPT_LOG_ERROR("cbR (%d) or cbS (%d) too big for cbSymCryptSignature (%d)", cbR, cbS, cbSymCryptSignature);
        goto err;
    }

    memset(pbSymCryptSignature, 0, cbSymCryptSignature);
    memcpy(pbSymCryptSignature + (cbSymCryptSignature/2) - cbR, pbR, cbR);
    memcpy(pbSymCryptSignature + cbSymCryptSignature - cbS, pbS, cbS);

    SYMCRYPT_LOG_BYTES_DEBUG("pbSymCryptSignature", pbSymCryptSignature, cbSymCryptSignature);

    res = 1; // success
err:
    return res;
}

// Quick hack function to generate precisely the DER encodings which we want for ECDSA signatures for the NIST prime curves
// Takes 2 same-size big-endian integers output from SymCrypt and encodes them in the minimally sized (strict) equivalent DER encoding
static int symcrypt_ecdsa_apply_der(PCBYTE pbSymCryptSignature, SIZE_T cbSymCryptSignature, PBYTE pbDerSignature, unsigned int* cbDerSignature)
{
    PBYTE  pbWrite = pbDerSignature;
    SIZE_T cbSeq = 0;
    SIZE_T padSeq = 0;
    PCBYTE pbR = NULL;
    SIZE_T cbR = 0;
    SIZE_T padR = 0;
    PCBYTE pbS = NULL;
    SIZE_T cbS = 0;
    SIZE_T padS = 0;
    int res = 0; // fail

    // Check the provided lengths are within reasonable bounds
    if( (cbSymCryptSignature < SYMCRYPT_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature > SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN) ||
        (cbSymCryptSignature % 2 == 1) )
    {
        SYMCRYPT_LOG_ERROR("Incorrect size: cbSymCryptSignature %d should be even integer in range [%d, %d]",
                           cbSymCryptSignature, SYMCRYPT_ECDSA_MIN_SYMCRYPT_SIGNATURE_LEN, SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN );
        goto err;
    }

    SYMCRYPT_LOG_BYTES_DEBUG("pbSymCryptSignature", pbSymCryptSignature, cbSymCryptSignature);

    pbR = pbSymCryptSignature;
    cbR = cbSymCryptSignature/2;
    pbS = pbSymCryptSignature + cbR;
    cbS = cbSymCryptSignature/2;

    while( (*pbR == 0) && cbR > 0 )
    {
        pbR++;
        cbR--;
    }
    if( (*pbR & 0x80) == 0x80)
    {
        padR = 1;
    }

    while( (*pbS == 0) && cbS > 0 )
    {
        pbS++;
        cbS--;
    }
    if( (*pbS & 0x80) == 0x80)
    {
        padS = 1;
    }

    cbSeq = cbR + padR + cbS + padS + 4;
    if( cbSeq > 0x7f )
    {
        // cbSeq must be encoded in 2 bytes - 0x81 <cbSeq>
        padSeq = 1;
    }

    *cbDerSignature = (SIZE_T)cbSeq + padSeq + 2;

    SYMCRYPT_LOG_DEBUG("cbDerSignature %d", *cbDerSignature);

    // Write SEQUENCE header
    *pbWrite = 0x30;
    pbWrite++;
    if( padSeq )
    {
        *pbWrite = 0x81;
        pbWrite++;
    }
    *pbWrite = (BYTE) cbSeq;
    pbWrite++;

    // Write R
    pbWrite[0] = 0x02;
    pbWrite[1] = (BYTE) (cbR + padR);
    pbWrite += 2;
    if( padR )
    {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbR, cbR);
    pbWrite += cbR;

    // Write S
    pbWrite[0] = 0x02;
    pbWrite[1] = (BYTE) (cbS + padS);
    pbWrite += 2;
    if( padS )
    {
        *pbWrite = 0;
        pbWrite++;
    }
    memcpy(pbWrite, pbS, cbS);

    SYMCRYPT_LOG_BYTES_DEBUG("pbDerSignature", pbDerSignature, *cbDerSignature);

    res = 1; // success
err:
    return res;
}

int symcrypt_eckey_init(EC_KEY *key)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    int res = 0; // fail

    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = OPENSSL_zalloc(sizeof(*keyCtx));
    if( !keyCtx )
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc failed");
        goto err;
    }

    if( EC_KEY_set_ex_data(key, eckey_symcrypt_idx, keyCtx) == 0)
    {
        SYMCRYPT_LOG_ERROR("EC_KEY_set_ex_data failed");
        goto err;
    }

    res = 1; // success
end:
    return res;

err:
    if( keyCtx )
    {
        OPENSSL_free( keyCtx );
    }
    goto end;
}

void symcrypt_ecc_free_key_context(SYMCRYPT_ECC_KEY_CONTEXT *keyCtx)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    if( keyCtx->data )
    {
        SYMCRYPT_LOG_DEBUG("OPENSSL_clear_free %lx %d", keyCtx->data, keyCtx->cbData);
        OPENSSL_clear_free(keyCtx->data, keyCtx->cbData);
    }
    if( keyCtx->key )
    {
        SYMCRYPT_LOG_DEBUG("SymCryptEckeyFree %lx", keyCtx->key);
        SymCryptEckeyFree(keyCtx->key);
    }
    keyCtx->initialized = 0;
    return;
}

#define NID_secp192r1 (NID_X9_62_prime192v1)
#define NID_secp256r1 (NID_X9_62_prime256v1)

void symcrypt_eckey_finish(EC_KEY *key)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = EC_KEY_get_ex_data(key, eckey_symcrypt_idx);
    if( keyCtx )
    {
        const EC_GROUP* ecgroup = EC_KEY_get0_group(key);
        int groupNid = EC_GROUP_get_curve_name(ecgroup);

        // Only free the key context if we actually handled it in the engine (NIST Prime curves)
        switch( groupNid )
        {
        case NID_secp192r1:
        case NID_secp224r1:
        case NID_secp256r1:
        case NID_secp384r1:
        case NID_secp521r1:
            symcrypt_ecc_free_key_context(keyCtx);
            OPENSSL_free( keyCtx );
            EC_KEY_set_ex_data(key, eckey_symcrypt_idx, NULL);
            break;
        default:
            // isn't our context to free
            break;
        }
    }
    return;
}

#define SC_OSSL_ECC_GET_CONTEXT_FALLBACK (-1)
#define SC_OSSL_ECC_GET_CONTEXT_ERROR    (0)
#define SC_OSSL_ECC_GET_CONTEXT_SUCCESS  (1)

static PSYMCRYPT_ECURVE _hidden_curve_P192 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P224 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P256 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P384 = NULL;
static PSYMCRYPT_ECURVE _hidden_curve_P521 = NULL;

int symcrypt_generate_keypair(SYMCRYPT_ECC_KEY_CONTEXT* pKeyCtx, PCSYMCRYPT_ECURVE pCurve, EC_KEY* eckey, const EC_GROUP* ecgroup)
{
    SYMCRYPT_LOG_DEBUG(NULL);

    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    BIGNUM* ec_privkey = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;

    int res = SC_OSSL_ECC_GET_CONTEXT_ERROR;

    pKeyCtx->key = SymCryptEckeyAllocate(pCurve);
    if( pKeyCtx->key == NULL )
    {
        SYMCRYPT_LOG_ERROR("SymCryptEckeyAllocate returned NULL.");
        goto err;
    }

    cbPrivateKey = SymCryptEckeySizeofPrivateKey(pKeyCtx->key);
    cbPublicKey = SymCryptEckeySizeofPublicKey(pKeyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

    pKeyCtx->cbData = cbPublicKey + cbPrivateKey;
    pKeyCtx->data = OPENSSL_zalloc(pKeyCtx->cbData);
    if( pKeyCtx->data == NULL )
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc returned NULL.");
        goto err;
    }

    symError = SymCryptEckeySetRandom(
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION,
        pKeyCtx->key );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEckeySetRandom failed", symError);
        goto err;
    }

    pbPrivateKey = pKeyCtx->data;
    pbPublicKey = pKeyCtx->data + cbPrivateKey;

    symError = SymCryptEckeyGetValue(
        pKeyCtx->key,
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0 );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEckeyGetValue failed", symError);
        goto err;
    }

    if( ((ec_privkey = BN_secure_new()) == NULL) ||
        ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SYMCRYPT_LOG_ERROR("BN_new returned NULL.");
        goto err;
    }

    BN_bin2bn(pbPrivateKey, cbPrivateKey, ec_privkey);
    BN_bin2bn(pbPublicKey, cbPublicKey/2, ec_pub_x);
    BN_bin2bn(pbPublicKey + (cbPublicKey/2), cbPublicKey/2, ec_pub_y);

    if( EC_KEY_set_private_key(eckey, ec_privkey) == 0)
    {
        SYMCRYPT_LOG_ERROR("EC_KEY_set_private_key failed.");
        goto err;
    }
    if( EC_KEY_set_public_key_affine_coordinates(eckey, ec_pub_x, ec_pub_y) == 0 )
    {
        SYMCRYPT_LOG_ERROR("EC_KEY_set_public_key_affine_coordinates failed.");
        goto err;
    }

    pKeyCtx->initialized = 1;
    res = SC_OSSL_ECC_GET_CONTEXT_SUCCESS;

cleanup:
    // Always free the temporary BIGNUMs
    if( ec_privkey != NULL )
    {
        BN_clear_free(ec_privkey);
    }
    if( ec_pub_x != NULL )
    {
        BN_free(ec_pub_x);
    }
    if( ec_pub_y != NULL )
    {
        BN_free(ec_pub_y);
    }
    return res;

err:
    // On error free the partially constructed key context
    symcrypt_ecc_free_key_context(pKeyCtx);
    goto cleanup;
}

int symcrypt_import_keypair(const EC_KEY* eckey, const EC_GROUP* ecgroup, SYMCRYPT_ECC_KEY_CONTEXT* pKeyCtx, PCSYMCRYPT_ECURVE pCurve)
{
    SYMCRYPT_LOG_DEBUG(NULL);

    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    PBYTE  pbPrivateKey = NULL;
    SIZE_T cbPrivateKey = 0;
    PBYTE  pbPublicKey = NULL;
    SIZE_T cbPublicKey = 0;

    const BIGNUM*   ec_privkey = NULL;
    const EC_POINT* ec_pubkey = NULL;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;

    int res = SC_OSSL_ECC_GET_CONTEXT_ERROR;

    pKeyCtx->key = SymCryptEckeyAllocate(pCurve);
    if( pKeyCtx->key == NULL )
    {
        SYMCRYPT_LOG_ERROR("SymCryptEckeyAllocate returned NULL.");
        goto err;
    }

    cbPrivateKey = SymCryptEckeySizeofPrivateKey(pKeyCtx->key);
    cbPublicKey = SymCryptEckeySizeofPublicKey(pKeyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);

    ec_privkey = EC_KEY_get0_private_key(eckey);
    ec_pubkey = EC_KEY_get0_public_key(eckey);

    if( ec_pubkey == NULL )
    {
        SYMCRYPT_LOG_ERROR("EC_KEY_get0_public_key returned NULL.");
        goto err;
    }

    if( (ec_privkey != NULL) && (BN_num_bytes(ec_privkey) > cbPrivateKey) )
    {
        SYMCRYPT_LOG_ERROR("ec_privkey too big: BN_num_bytes(ec_privkey) %d, cbPrivateKey %d.",
                           BN_num_bytes(ec_privkey), cbPrivateKey);
        goto err;
    }
    else if( ec_privkey == NULL )
    {
        cbPrivateKey = 0;
    }

    if( (bn_ctx = BN_CTX_new()) == NULL )
    {
        SYMCRYPT_LOG_ERROR("BN_CTX_new returned NULL.");
        goto err;
    }
    BN_CTX_start(bn_ctx);

    if( ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SYMCRYPT_LOG_ERROR("BN_new returned NULL.");
        goto err;
    }

    if( EC_POINT_get_affine_coordinates(ecgroup, ec_pubkey, ec_pub_x, ec_pub_y, bn_ctx) == 0 )
    {
        SYMCRYPT_LOG_ERROR("EC_POINT_get_affine_coordinates failed.");
        goto err;
    }

    if( (2*BN_num_bytes(ec_pub_x) > cbPublicKey) || (2*BN_num_bytes(ec_pub_y) > cbPublicKey) )
    {
        SYMCRYPT_LOG_ERROR("EC_POINT coordinate too big: BN_num_bytes(ec_pub_x) %d, BN_num_bytes(ec_pub_y) %d, cbPublicKey %d.",
                           BN_num_bytes(ec_pub_x), BN_num_bytes(ec_pub_y), cbPublicKey);
        goto err;
    }

    SYMCRYPT_LOG_DEBUG("pKeyCtx %lx pKeyCtx->key %lx pKeyCtx->data %lx", pKeyCtx, pKeyCtx->key, pKeyCtx->data);

    pKeyCtx->cbData = cbPublicKey + cbPrivateKey;
    pKeyCtx->data = OPENSSL_zalloc(pKeyCtx->cbData);
    if( pKeyCtx->data == NULL )
    {
        SYMCRYPT_LOG_ERROR("OPENSSL_zalloc returned NULL.");
        goto err;
    }

    SYMCRYPT_LOG_DEBUG("cbPrivateKey %d, cbPublicKey %d, data %lx, key %lx", cbPrivateKey, cbPublicKey, pKeyCtx->data, pKeyCtx->key);

    if( cbPrivateKey != 0 )
    {
        pbPrivateKey = pKeyCtx->data;
        BN_bn2binpad(ec_privkey, pbPrivateKey, cbPrivateKey);
        SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPrivateKey", pbPrivateKey, cbPrivateKey);
    }

    pbPublicKey = pKeyCtx->data + cbPrivateKey;
    BN_bn2binpad(ec_pub_x, pbPublicKey, cbPublicKey/2);
    BN_bn2binpad(ec_pub_y, pbPublicKey + (cbPublicKey/2), cbPublicKey/2);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPublicKey", pbPublicKey, cbPublicKey);

    SYMCRYPT_LOG_BIGNUM_DEBUG("priv", (BIGNUM*) ec_privkey);
    SYMCRYPT_LOG_BIGNUM_DEBUG("x", ec_pub_x);
    SYMCRYPT_LOG_BIGNUM_DEBUG("y", ec_pub_y);

    symError = SymCryptEckeySetValue(
        pbPrivateKey, cbPrivateKey,
        pbPublicKey, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION | SYMCRYPT_FLAG_KEY_KEYPAIR_REGENERATION_VALIDATION,
        pKeyCtx->key );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEckeySetValue failed", symError);
        goto err;
    }

    pKeyCtx->initialized = 1;
    res = SC_OSSL_ECC_GET_CONTEXT_SUCCESS;

cleanup:
    // Always free the temporary BIGNUMs and BN_CTX
    if( ec_pub_x != NULL )
    {
        BN_free(ec_pub_x);
    }
    if( ec_pub_y != NULL )
    {
        BN_free(ec_pub_y);
    }
    BN_CTX_end(bn_ctx);
    if( bn_ctx != NULL )
    {
        BN_CTX_free(bn_ctx);
    }
    return res;

err:
    // On error free the partially constructed key context
    symcrypt_ecc_free_key_context(pKeyCtx);
    goto cleanup;
}

// returns SC_OSSL_ECC_GET_CONTEXT_FALLBACK when the eckey is not supported by the engine, so we
// should fallback to OpenSSL
// returns SC_OSSL_ECC_GET_CONTEXT_ERROR on an error
// returns SC_OSSL_ECC_GET_CONTEXT_SUCCESS and sets pKeyCtx to a pointer to an initialized
// SYMCRYPT_ECC_KEY_CONTEXT on success
int symcrypt_get_context_ex(EC_KEY* eckey, SYMCRYPT_ECC_KEY_CONTEXT** ppKeyCtx, BOOL generate)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    PCSYMCRYPT_ECURVE pCurve = NULL;

    const EC_GROUP* ecgroup = EC_KEY_get0_group(eckey);

    int groupNid = EC_GROUP_get_curve_name(ecgroup);

    SYMCRYPT_LOG_DEBUG("groupNid %d", groupNid);

    // Only reroute NIST Prime curves to SymCrypt for now
    switch( groupNid )
    {
    case NID_secp192r1:
        if( _hidden_curve_P192 == NULL )
        {
            _hidden_curve_P192 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP192, 0);
        }
        pCurve = _hidden_curve_P192;
        break;
    case NID_secp224r1:
        if( _hidden_curve_P224 == NULL )
        {
            _hidden_curve_P224 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP224, 0);
        }
        pCurve = _hidden_curve_P224;
        break;
    case NID_secp256r1:
        if( _hidden_curve_P256 == NULL )
        {
            _hidden_curve_P256 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0);
        }
        pCurve = _hidden_curve_P256;
        break;
    case NID_secp384r1:
        if( _hidden_curve_P384 == NULL )
        {
            _hidden_curve_P384 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP384, 0);
        }
        pCurve = _hidden_curve_P384;
        break;
    case NID_secp521r1:
        if( _hidden_curve_P521 == NULL )
        {
            _hidden_curve_P521 = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP521, 0);
        }
        pCurve = _hidden_curve_P521;
        break;
    default:
        SYMCRYPT_LOG_INFO("SymCrypt engine does not yet support this group (nid %d) - falling back to OpenSSL.", groupNid);
        return SC_OSSL_ECC_GET_CONTEXT_FALLBACK;
    }

    if( pCurve == NULL )
    {
        SYMCRYPT_LOG_ERROR("SymCryptEcurveAllocate failed.");
        return SC_OSSL_ECC_GET_CONTEXT_ERROR;
    }

    *ppKeyCtx = (SYMCRYPT_ECC_KEY_CONTEXT*) EC_KEY_get_ex_data(eckey, eckey_symcrypt_idx);

    if( *ppKeyCtx == NULL )
    {
        SYMCRYPT_LOG_ERROR("SymCrypt Context Not Found.");
        return SC_OSSL_ECC_GET_CONTEXT_ERROR;
    }

    if( (*ppKeyCtx)->initialized == 1 )
    {
        SYMCRYPT_LOG_DEBUG("pKeyCtx is already initialized");
        return SC_OSSL_ECC_GET_CONTEXT_SUCCESS;
    }

    if( generate )
    {
        return symcrypt_generate_keypair(*ppKeyCtx, pCurve, eckey, ecgroup);
    }
    else
    {
        return symcrypt_import_keypair(eckey, ecgroup, *ppKeyCtx, pCurve);
    }
}

// returns -1 when the eckey is not supported by the engine, so we should fallback to OpenSSL
// returns 0 on an error
// returns 1 and sets pKeyCtx to a pointer to an initialized SYMCRYPT_ECC_KEY_CONTEXT on success
int symcrypt_get_context(EC_KEY* eckey, SYMCRYPT_ECC_KEY_CONTEXT** ppKeyCtx)
{
    return symcrypt_get_context_ex(eckey, ppKeyCtx, FALSE);
}

int symcrypt_eckey_sign(int type, const unsigned char* dgst, int dlen,
    unsigned char* sig, unsigned int* siglen,
    const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    switch( symcrypt_get_context(eckey, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return 0;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign pfn_eckey_sign = NULL;
        EC_KEY_METHOD_get_sign(ossl_eckey_method, &pfn_eckey_sign, NULL, NULL);
        if( !pfn_eckey_sign )
        {
            return 0;
        }
        return pfn_eckey_sign(type, dgst, dlen, sig, siglen, kinv, r, eckey);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return 0;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );
    symError = SymCryptEcDsaSign(
        keyCtx->key,
        dgst,
        dlen,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION,
        buf,
        cbSymCryptSig);
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEcDsaSign failed", symError);
        return 0;
    }

    if( symcrypt_ecdsa_apply_der(buf, cbSymCryptSig, sig, siglen) == 0 )
    {
        SYMCRYPT_LOG_ERROR("symcrypt_ecdsa_apply_der failed");
        return 0;
    }

    return 1;
}


int symcrypt_eckey_sign_setup(EC_KEY* eckey, BN_CTX* ctx_in, BIGNUM** kinvp,
    BIGNUM** rp)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    const EC_KEY_METHOD* ossl_eckey_method = EC_KEY_OpenSSL();
    PFN_eckey_sign_setup pfn_eckey_sign_setup = NULL;

    switch( symcrypt_get_context(eckey, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return 0;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, &pfn_eckey_sign_setup, NULL);
        if( !pfn_eckey_sign_setup )
        {
            return 0;
        }
        return pfn_eckey_sign_setup(eckey, ctx_in, kinvp, rp);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        return 1;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return 0;
    }
}


ECDSA_SIG* symcrypt_eckey_sign_sig(const unsigned char* dgst, int dgst_len,
    const BIGNUM* in_kinv, const BIGNUM* in_r,
    EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    ECDSA_SIG* returnSignature = NULL;
    BIGNUM* r = NULL;
    BIGNUM* s = NULL;
    BYTE buf[SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    switch( symcrypt_get_context(eckey, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return NULL;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_sign_sig pfn_eckey_sign_sig = NULL;
        EC_KEY_METHOD_get_sign(ossl_eckey_method, NULL, NULL, &pfn_eckey_sign_sig);
        if( !pfn_eckey_sign_sig )
        {
            return NULL;
        }
        return pfn_eckey_sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return NULL;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );
    symError = SymCryptEcDsaSign(
        keyCtx->key,
        dgst,
        dgst_len,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION,
        buf,
        cbSymCryptSig);
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEcDsaSign failed", symError);
        return NULL;
    }

    returnSignature = ECDSA_SIG_new();
    if( returnSignature == NULL )
    {
        SYMCRYPT_LOG_ERROR("ECDSA_SIG_new returned NULL.");
        return NULL;
    }

    if( ((r = BN_new()) == NULL) ||
        ((s = BN_new()) == NULL) )
    {
        if( r != NULL )
        {
            BN_free(r);
        }
        if( s != NULL )
        {
            BN_free(r);
        }
        SYMCRYPT_LOG_ERROR("BN_new returned NULL.");
        return NULL;
    }

    BN_bin2bn(buf, cbSymCryptSig/2, r);
    BN_bin2bn(buf + cbSymCryptSig/2, cbSymCryptSig/2, s);

    if( ECDSA_SIG_set0(returnSignature, r, s) == 0 )
    {
        if( returnSignature == NULL )
        {
            BN_free(r);
            BN_free(s);
        }
        else
        {
            ECDSA_SIG_free(returnSignature);
        }
        return NULL;
    }

    return returnSignature;
}


int symcrypt_eckey_verify(
    int type, const unsigned char* dgst, int dgstlen,
    const unsigned char* sig, int siglen, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    switch( symcrypt_get_context(eckey, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return 0;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_verify pfn_eckey_verify = NULL;
        EC_KEY_METHOD_get_verify(ossl_eckey_method, &pfn_eckey_verify, NULL);
        if (!pfn_eckey_verify)
        {
            return 0;
        }
        return pfn_eckey_verify(type, dgst, dgstlen, sig, siglen, eckey);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return 0;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );
    if( symcrypt_ecdsa_remove_der(sig, siglen, &buf[0], cbSymCryptSig) == 0 )
    {
        SYMCRYPT_LOG_ERROR("symcrypt_ecdsa_remove_der failed");
        return 0;
    }

    symError = SymCryptEcDsaVerify(
        keyCtx->key,
        dgst,
        dgstlen,
        buf,
        cbSymCryptSig,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION);
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEcDsaVerify failed", symError);
        return 0;
    }

    return 1;
}


int symcrypt_eckey_verify_sig(
    const unsigned char* dgst, int dgst_len, const ECDSA_SIG* sig, EC_KEY* eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SYMCRYPT_ECDSA_MAX_SYMCRYPT_SIGNATURE_LEN] = { 0 };
    SIZE_T cbSymCryptSig = 0;

    const BIGNUM* r = NULL;
    const BIGNUM* s = NULL;

    switch( symcrypt_get_context(eckey, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return 0;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_verify_sig pfn_eckey_verify_sig = NULL;
        EC_KEY_METHOD_get_verify(ossl_eckey_method, NULL, &pfn_eckey_verify_sig);
        if (!pfn_eckey_verify_sig)
        {
            return 0;
        }
        return pfn_eckey_verify_sig(dgst, dgst_len, sig, eckey);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return 0;
    }

    cbSymCryptSig = 2*SymCryptEcurveSizeofFieldElement( keyCtx->key->pCurve );

    ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, buf, cbSymCryptSig/2);
    BN_bn2binpad(s, buf + (cbSymCryptSig/2), cbSymCryptSig/2);

    symError = SymCryptEcDsaVerify(
        keyCtx->key,
        dgst,
        dgst_len,
        buf,
        cbSymCryptSig,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION);
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEcDsaVerify failed", symError);
        return 0;
    }

    return 1;
}

int symcrypt_eckey_keygen(EC_KEY *eckey)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;

    switch( symcrypt_get_context_ex(eckey, &keyCtx, TRUE) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context_ex failed.");
        return 0;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_keygen pfn_eckey_keygen = NULL;
        EC_KEY_METHOD_get_keygen(ossl_eckey_method, &pfn_eckey_keygen);
        if (!pfn_eckey_keygen)
        {
            return 0;
        }
        return pfn_eckey_keygen(eckey);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        SYMCRYPT_LOG_DEBUG("generated new key in symcrypt_get_context_ex");
        return 1;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return 0;
    }
}

int symcrypt_eckey_compute_key(unsigned char **psec,
                               size_t *pseclen,
                               const EC_POINT *pub_key,
                               const EC_KEY *ecdh)
{
    SYMCRYPT_LOG_DEBUG(NULL);
    const EC_KEY_METHOD* ossl_eckey_method = NULL;
    SYMCRYPT_ERROR symError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_ECC_KEY_CONTEXT *keyCtx = NULL;
    BYTE buf[SYMCRYPT_ECDH_MAX_PUBLIC_KEY_LEN] = { 0 };

    const EC_GROUP* ecgroup = NULL;
    BN_CTX* bn_ctx = NULL;
    BIGNUM* ec_pub_x = NULL;
    BIGNUM* ec_pub_y = NULL;
    UINT32 cbPublicKey = 0;
    PSYMCRYPT_ECKEY pkPublic = NULL;

    int res = -1; // fail

    switch( symcrypt_get_context(ecdh, &keyCtx) )
    {
    case SC_OSSL_ECC_GET_CONTEXT_ERROR:
        SYMCRYPT_LOG_ERROR("symcrypt_get_context failed.");
        return -1;
    case SC_OSSL_ECC_GET_CONTEXT_FALLBACK:
        ossl_eckey_method = EC_KEY_OpenSSL();
        PFN_eckey_compute_key pfn_eckey_compute_key = NULL;
        EC_KEY_METHOD_get_compute_key(ossl_eckey_method, &pfn_eckey_compute_key);
        if( !pfn_eckey_compute_key )
        {
            return -1;
        }
        return pfn_eckey_compute_key(psec, pseclen, pub_key, ecdh);
    case SC_OSSL_ECC_GET_CONTEXT_SUCCESS:
        break;
    default:
        SYMCRYPT_LOG_ERROR("Unexpected symcrypt_get_context value");
        return -1;
    }

    ecgroup = EC_KEY_get0_group(ecdh);
    if( ecgroup == NULL )
    {
        SYMCRYPT_LOG_ERROR("EC_KEY_get0_group returned NULL.");
        goto err;
    }

    cbPublicKey = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_XY);
    pkPublic = SymCryptEckeyAllocate(keyCtx->key->pCurve);
    if( pkPublic == NULL )
    {
        SYMCRYPT_LOG_ERROR("SymCryptEckeyAllocate returned NULL.");
        goto err;
    }

    SYMCRYPT_LOG_DEBUG("psec %lx, pseclen %lx, pub_key %lx, ecdh %lx", psec, pseclen, pub_key, ecdh);

    if( (bn_ctx = BN_CTX_new()) == NULL )
    {
        SYMCRYPT_LOG_ERROR("BN_CTX_new returned NULL.");
        goto err;
    }
    BN_CTX_start(bn_ctx);

    if( ((ec_pub_x = BN_new()) == NULL) ||
        ((ec_pub_y = BN_new()) == NULL) )
    {
        SYMCRYPT_LOG_ERROR("BN_new returned NULL.");
        goto err;
    }

    if( EC_POINT_get_affine_coordinates(ecgroup, pub_key, ec_pub_x, ec_pub_y, bn_ctx) == 0 )
    {
        SYMCRYPT_LOG_ERROR("EC_POINT_get_affine_coordinates failed.");
        goto err;
    }

    if( (2*BN_num_bytes(ec_pub_x) > cbPublicKey) || (2*BN_num_bytes(ec_pub_y) > cbPublicKey) )
    {
        SYMCRYPT_LOG_ERROR("EC_POINT coordinate too big: BN_num_bytes(ec_pub_x) %d, BN_num_bytes(ec_pub_y) %d, cbPublicKey %d.",
                        BN_num_bytes(ec_pub_x), BN_num_bytes(ec_pub_y), cbPublicKey);
        goto err;
    }

    BN_bn2binpad(ec_pub_x, buf, cbPublicKey/2);
    BN_bn2binpad(ec_pub_y, buf + (cbPublicKey/2), cbPublicKey/2);
    SYMCRYPT_LOG_BYTES_DEBUG("SymCrypt pbPublicKey", buf, cbPublicKey);

    SYMCRYPT_LOG_BIGNUM_DEBUG("x", ec_pub_x);
    SYMCRYPT_LOG_BIGNUM_DEBUG("y", ec_pub_y);

    symError = SymCryptEckeySetValue(
        NULL, 0,
        buf, cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_KEY_RANGE_AND_PUBLIC_KEY_ORDER_VALIDATION,
        pkPublic );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEckeySetValue failed", symError);
        goto err;
    }

    *pseclen = SymCryptEckeySizeofPublicKey(keyCtx->key, SYMCRYPT_ECPOINT_FORMAT_X);
    *psec = OPENSSL_zalloc(*pseclen);

    symError = SymCryptEcDhSecretAgreement(
        keyCtx->key,
        pkPublic,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        *psec,
        *pseclen );
    if( symError != SYMCRYPT_NO_ERROR )
    {
        SYMCRYPT_LOG_SYMERROR_ERROR("SymCryptEcDhSecretAgreement failed", symError);
        goto err;
    }

    res = *pseclen;

cleanup:
    // Always free the temporary BIGNUMs and BN_CTX
    if( ec_pub_x != NULL )
    {
        BN_free(ec_pub_x);
    }
    if( ec_pub_y != NULL )
    {
        BN_free(ec_pub_y);
    }
    BN_CTX_end(bn_ctx);
    if( bn_ctx != NULL )
    {
        BN_CTX_free(bn_ctx);
    }
    return res;

err:
    if( pkPublic )
    {
        SymCryptEckeyFree(pkPublic);
    }
    if( *psec )
    {
        OPENSSL_free(*psec);
        *psec = NULL;
    }
    *pseclen = 0;

    res = -1;

    goto cleanup;
}

void symcrypt_destroy_ecc_curves(void)
{
    SYMCRYPT_LOG_DEBUG(NULL);

    if( _hidden_curve_P192 )
    {
        SymCryptEcurveFree(_hidden_curve_P192);
        _hidden_curve_P192 = NULL;
    }
    if( _hidden_curve_P224 )
    {
        SymCryptEcurveFree(_hidden_curve_P224);
        _hidden_curve_P224 = NULL;
    }
    if( _hidden_curve_P256 )
    {
        SymCryptEcurveFree(_hidden_curve_P256);
        _hidden_curve_P256 = NULL;
    }
    if( _hidden_curve_P384 )
    {
        SymCryptEcurveFree(_hidden_curve_P384);
        _hidden_curve_P384 = NULL;
    }
    if( _hidden_curve_P521 )
    {
        SymCryptEcurveFree(_hidden_curve_P521);
        _hidden_curve_P521 = NULL;
    }
}

#ifdef __cplusplus
}
#endif
