// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/trace.h>

#include "bcrypt.h"
#include "key.h"
#include "magic.h"
#include "rsa.h"

#ifndef PKCS8_PRIVATEKEY_INFO
#define PKCS8_PRIVATEKEY_INFO ((LPCSTR)47)
#endif

typedef struct _der_cursor
{
    const uint8_t* ptr;
    size_t length;
} der_cursor_t;

static void _der_cursor_init(
    der_cursor_t* cursor,
    const uint8_t* data,
    size_t length)
{
    if (cursor)
    {
        cursor->ptr = data;
        cursor->length = length;
    }
}

static bool _der_cursor_more(const der_cursor_t* cursor)
{
    return cursor && cursor->length > 0;
}

static oe_result_t _der_read_tl(
    der_cursor_t* cursor,
    uint8_t* tag,
    const uint8_t** value,
    size_t* value_length)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* p = NULL;
    size_t remaining = 0;
    size_t len = 0;

    if (tag)
        *tag = 0;

    if (value)
        *value = NULL;

    if (value_length)
        *value_length = 0;

    if (!cursor || !cursor->ptr || cursor->length == 0 || !tag || !value ||
        !value_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (cursor->length < 2)
        OE_RAISE(OE_CRYPTO_ERROR);

    p = cursor->ptr;
    remaining = cursor->length;

    uint8_t t = *p++;
    remaining--;

    if (remaining == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    uint8_t len_byte = *p++;
    remaining--;

    if ((len_byte & 0x80) == 0)
    {
        len = len_byte;
    }
    else
    {
        size_t num_bytes = len_byte & 0x7f;

        if (num_bytes == 0 || num_bytes > sizeof(size_t) ||
            num_bytes > remaining)
            OE_RAISE(OE_CRYPTO_ERROR);

        len = 0;
        for (size_t i = 0; i < num_bytes; ++i)
        {
            len = (len << 8) | p[i];
        }

        p += num_bytes;
        remaining -= num_bytes;
    }

    if (len > remaining)
        OE_RAISE(OE_CRYPTO_ERROR);

    *tag = t;
    *value = p;
    *value_length = len;

    cursor->ptr = p + len;
    cursor->length = remaining - len;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _der_get_sequence(
    der_cursor_t* cursor,
    der_cursor_t* sequence)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_length = 0;

    if (sequence)
        memset(sequence, 0, sizeof(*sequence));

    if (!sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_der_read_tl(cursor, &tag, &value, &value_length));

    if (tag != 0x30)
        OE_RAISE(OE_CRYPTO_ERROR);

    _der_cursor_init(sequence, value, value_length);
    result = OE_OK;

done:
    return result;
}

static oe_result_t _der_get_small_integer(der_cursor_t* cursor, int* value)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag = 0;
    const uint8_t* data = NULL;
    size_t data_length = 0;
    int tmp = 0;

    if (value)
        *value = 0;

    if (!value)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_der_read_tl(cursor, &tag, &data, &data_length));

    if (tag != 0x02 || data_length == 0 || data_length > sizeof(int))
        OE_RAISE(OE_CRYPTO_ERROR);

    for (size_t i = 0; i < data_length; ++i)
        tmp = (tmp << 8) | data[i];

    *value = tmp;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _der_get_integer_bytes(
    der_cursor_t* cursor,
    const uint8_t** data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_length = 0;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    if (!data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_der_read_tl(cursor, &tag, &value, &value_length));

    if (tag != 0x02 || value_length == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (value[0] == 0 && value_length > 1)
    {
        value++;
        value_length--;
    }

    *data = value;
    *size = value_length;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _der_get_octet_string(
    der_cursor_t* cursor,
    const uint8_t** data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t tag = 0;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    if (!data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_der_read_tl(cursor, &tag, data, size));

    if (tag != 0x04)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _der_skip_null_if_present(der_cursor_t* cursor)
{
    oe_result_t result = OE_OK;

    if (!cursor || !_der_cursor_more(cursor))
        return OE_OK;

    der_cursor_t tmp = *cursor;
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_length = 0;

    result = _der_read_tl(&tmp, &tag, &value, &value_length);

    if (result == OE_OK)
    {
        if (tag == 0x05 && value_length == 0)
        {
            *cursor = tmp;
        }
        else
        {
            /* Restore original cursor if tag is not NULL */
            result = OE_OK;
        }
    }

    return result;
}

static oe_result_t _der_expect_oid_rsa(der_cursor_t* cursor)
{
    oe_result_t result = OE_UNEXPECTED;
    static const uint8_t oid_rsa[] = {0x2a, 0x86, 0x48, 0x86,
                                      0xf7, 0x0d, 0x01, 0x01, 0x01};
    uint8_t tag = 0;
    const uint8_t* value = NULL;
    size_t value_length = 0;

    OE_CHECK(_der_read_tl(cursor, &tag, &value, &value_length));

    if (tag != 0x06 || value_length != OE_COUNTOF(oid_rsa) ||
        memcmp(value, oid_rsa, value_length) != 0)
        OE_RAISE(OE_UNSUPPORTED);

    result = OE_OK;

done:
    return result;
}

/* BCRYPT RSA blobs expect big-endian multi-precision integers. */
static void _copy_big_endian_bytes(
    uint8_t* dest,
    size_t dest_size,
    const uint8_t* src,
    size_t src_size)
{
    if (!dest || !src)
        return;

    memset(dest, 0, dest_size);

    if (src_size > dest_size)
    {
        src += (src_size - dest_size);
        src_size = dest_size;
    }

    memcpy(dest, src, src_size);
}

static oe_result_t _decode_pkcs1_private_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BYTE** key_blob,
    DWORD* key_blob_size)
{
    oe_result_t result = OE_UNEXPECTED;
    der_cursor_t root = {0};
    der_cursor_t sequence = {0};
    int version = 0;
    const uint8_t *modulus = NULL, *public_exp = NULL, *private_exp = NULL;
    const uint8_t *prime1 = NULL, *prime2 = NULL;
    const uint8_t *exp1 = NULL, *exp2 = NULL, *coefficient = NULL;
    size_t modulus_size = 0;
    size_t public_exp_size = 0;
    size_t private_exp_size = 0;
    size_t prime1_size = 0;
    size_t prime2_size = 0;
    size_t exp1_size = 0;
    size_t exp2_size = 0;
    size_t coefficient_size = 0;
    uint64_t total_size_u64 = sizeof(BCRYPT_RSAKEY_BLOB);
    size_t total_size = 0;
    BYTE* blob = NULL;
    BCRYPT_RSAKEY_BLOB* header = NULL;
    uint8_t* cursor = NULL;

    if (key_blob)
        *key_blob = NULL;

    if (key_blob_size)
        *key_blob_size = 0;

    if (!der_data || der_data_size == 0 || !key_blob || !key_blob_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    _der_cursor_init(&root, der_data, der_data_size);
    OE_TRACE_VERBOSE(
        "PKCS1 fallback invoked: size=%lu first bytes=%02x %02x %02x %02x",
        (unsigned long)der_data_size,
        der_data_size > 0 ? der_data[0] : 0,
        der_data_size > 1 ? der_data[1] : 0,
        der_data_size > 2 ? der_data[2] : 0,
        der_data_size > 3 ? der_data[3] : 0);
    OE_CHECK(_der_get_sequence(&root, &sequence));
    OE_CHECK(_der_get_small_integer(&sequence, &version));

    if (version != 0)
        OE_RAISE(OE_UNSUPPORTED);

    OE_CHECK(_der_get_integer_bytes(&sequence, &modulus, &modulus_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &public_exp, &public_exp_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &private_exp, &private_exp_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &prime1, &prime1_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &prime2, &prime2_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &exp1, &exp1_size));
    OE_CHECK(_der_get_integer_bytes(&sequence, &exp2, &exp2_size));
    OE_CHECK(
        _der_get_integer_bytes(&sequence, &coefficient, &coefficient_size));

    OE_TRACE_VERBOSE(
        "PKCS1 sizes: modulus=%zu pubexp=%zu privexp=%zu prime1=%zu prime2=%zu exp1=%zu exp2=%zu coeff=%zu",
        modulus_size,
        public_exp_size,
        private_exp_size,
        prime1_size,
        prime2_size,
        exp1_size,
        exp2_size,
        coefficient_size);

    if (_der_cursor_more(&sequence))
        OE_RAISE(OE_UNSUPPORTED);

    if (prime1_size != exp1_size || prime2_size != exp2_size ||
        prime1_size != coefficient_size || modulus_size != private_exp_size)
        OE_RAISE(OE_CRYPTO_ERROR);

    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)public_exp_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)modulus_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)prime1_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)prime2_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)exp1_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)exp2_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)coefficient_size, &total_size_u64));
    OE_CHECK(oe_safe_add_u64(
        total_size_u64, (uint64_t)private_exp_size, &total_size_u64));

    if (total_size_u64 > MAXDWORD)
        OE_RAISE(OE_OUT_OF_MEMORY);

    total_size = (size_t)total_size_u64;
    OE_TRACE_VERBOSE("PKCS1 blob total_size=%zu", total_size);

    blob = (BYTE*)LocalAlloc(LMEM_FIXED, (SIZE_T)total_size);
    if (!blob)
        OE_RAISE(OE_OUT_OF_MEMORY);

    header = (BCRYPT_RSAKEY_BLOB*)blob;
    header->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    header->BitLength = (ULONG)(modulus_size * 8);
    header->cbPublicExp = (ULONG)public_exp_size;
    header->cbModulus = (ULONG)modulus_size;
    header->cbPrime1 = (ULONG)prime1_size;
    header->cbPrime2 = (ULONG)prime2_size;

    cursor = blob + sizeof(BCRYPT_RSAKEY_BLOB);

    _copy_big_endian_bytes(cursor, public_exp_size, public_exp, public_exp_size);
    cursor += public_exp_size;

    _copy_big_endian_bytes(cursor, modulus_size, modulus, modulus_size);
    cursor += modulus_size;

    _copy_big_endian_bytes(cursor, prime1_size, prime1, prime1_size);
    cursor += prime1_size;

    _copy_big_endian_bytes(cursor, prime2_size, prime2, prime2_size);
    cursor += prime2_size;

    _copy_big_endian_bytes(cursor, exp1_size, exp1, exp1_size);
    cursor += exp1_size;

    _copy_big_endian_bytes(cursor, exp2_size, exp2, exp2_size);
    cursor += exp2_size;

    _copy_big_endian_bytes(
        cursor, coefficient_size, coefficient, coefficient_size);
    cursor += coefficient_size;

    _copy_big_endian_bytes(cursor, private_exp_size, private_exp, private_exp_size);
    cursor += private_exp_size;

    if ((size_t)(cursor - blob) != total_size)
        OE_RAISE(OE_FAILURE);

    *key_blob = blob;
    *key_blob_size = (DWORD)total_size;
    blob = NULL;
    result = OE_OK;

done:
    if (blob)
    {
        SecureZeroMemory(blob, total_size);
        LocalFree(blob);
    }

    return result;
}

static oe_result_t _decode_pkcs8_private_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BYTE** key_blob,
    DWORD* key_blob_size)
{
    oe_result_t result = OE_UNEXPECTED;
    der_cursor_t root = {0};
    der_cursor_t sequence = {0};
    der_cursor_t algorithm = {0};
    const uint8_t* private_key = NULL;
    size_t private_key_size = 0;
    int version = 0;

    if (key_blob)
        *key_blob = NULL;

    if (key_blob_size)
        *key_blob_size = 0;

    if (!der_data || der_data_size == 0 || !key_blob || !key_blob_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    _der_cursor_init(&root, der_data, der_data_size);
    OE_TRACE_VERBOSE(
        "PKCS8 fallback invoked: size=%lu first bytes=%02x %02x %02x %02x",
        (unsigned long)der_data_size,
        der_data_size > 0 ? der_data[0] : 0,
        der_data_size > 1 ? der_data[1] : 0,
        der_data_size > 2 ? der_data[2] : 0,
        der_data_size > 3 ? der_data[3] : 0);
    OE_CHECK(_der_get_sequence(&root, &sequence));
    OE_CHECK(_der_get_small_integer(&sequence, &version));

    if (version != 0)
        OE_RAISE(OE_UNSUPPORTED);

    OE_CHECK(_der_get_sequence(&sequence, &algorithm));
    OE_CHECK(_der_expect_oid_rsa(&algorithm));
    OE_CHECK(_der_skip_null_if_present(&algorithm));

    OE_CHECK(_der_get_octet_string(&sequence, &private_key, &private_key_size));

    if (private_key_size == 0 || private_key_size > MAXDWORD)
        OE_RAISE(OE_CRYPTO_ERROR);

    OE_CHECK(_decode_pkcs1_private_key(
        private_key, (DWORD)private_key_size, key_blob, key_blob_size));

    result = OE_OK;

done:
    return result;
}

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

/* Caller is responsible for calling BCryptDestroyKey on key_handle */
static oe_result_t _bcrypt_decode_rsa_private_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* key_blob = NULL;
    DWORD key_blob_size = 0;
    DWORD err = 0;
    OE_TRACE_VERBOSE(
        "Decode RSA key invoked: size=%lu first bytes=%02x %02x %02x %02x",
        (unsigned long)der_data_size,
        der_data_size > 0 ? der_data[0] : 0,
        der_data_size > 1 ? der_data[1] : 0,
        der_data_size > 2 ? der_data[2] : 0,
        der_data_size > 3 ? der_data[3] : 0);
    BOOL success = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        CNG_RSA_PRIVATE_KEY_BLOB,
        der_data,
        der_data_size,
        CRYPT_DECODE_ALLOC_FLAG,
        NULL,
        &key_blob,
        &key_blob_size);

    if (!success)
    {
        err = GetLastError();
        if (err == CRYPT_E_ASN1_BADPDU || err == CRYPT_E_ASN1_EOD ||
            err == CRYPT_E_ASN1_CORRUPT || err == CRYPT_E_ASN1_ERROR ||
            err == CRYPT_E_ASN1_BADTAG || err == CRYPT_E_BAD_ENCODE ||
            err == NTE_BAD_DATA)
        {
            CRYPT_PRIVATE_KEY_INFO* pkcs8_info = NULL;
            DWORD pkcs8_info_size = 0;
            BOOL pkcs8_success = CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                PKCS8_PRIVATEKEY_INFO,
                der_data,
                der_data_size,
                CRYPT_DECODE_ALLOC_FLAG,
                NULL,
                &pkcs8_info,
                &pkcs8_info_size);

            if (pkcs8_success && pkcs8_info)
            {
                if (!pkcs8_info->Algorithm.pszObjId ||
                    strcmp(pkcs8_info->Algorithm.pszObjId, szOID_RSA_RSA) != 0)
                {
                    oe_secure_zero_fill(pkcs8_info, (size_t)pkcs8_info_size);
                    LocalFree(pkcs8_info);
                    OE_RAISE(OE_UNSUPPORTED);
                }

                void* pkcs1_from_pkcs8 = NULL;
                DWORD pkcs1_from_pkcs8_size = 0;
                BOOL pkcs1_from_pkcs8_success = CryptDecodeObjectEx(
                    X509_ASN_ENCODING,
                    PKCS_RSA_PRIVATE_KEY,
                    pkcs8_info->PrivateKey.pbData,
                    pkcs8_info->PrivateKey.cbData,
                    CRYPT_DECODE_ALLOC_FLAG,
                    NULL,
                    &pkcs1_from_pkcs8,
                    &pkcs1_from_pkcs8_size);

                if (pkcs1_from_pkcs8_success && pkcs1_from_pkcs8)
                {
                    success = CryptEncodeObjectEx(
                        X509_ASN_ENCODING,
                        CNG_RSA_PRIVATE_KEY_BLOB,
                        pkcs1_from_pkcs8,
                        CRYPT_ENCODE_ALLOC_FLAG,
                        NULL,
                        &key_blob,
                        &key_blob_size);

                    err = GetLastError();

                    oe_secure_zero_fill(
                        pkcs1_from_pkcs8, (size_t)pkcs1_from_pkcs8_size);
                    LocalFree(pkcs1_from_pkcs8);

                    if (!success)
                    {
                        oe_secure_zero_fill(
                            pkcs8_info, (size_t)pkcs8_info_size);
                        LocalFree(pkcs8_info);
                        OE_RAISE_MSG(
                            OE_CRYPTO_ERROR,
                            "CryptEncodeObjectEx (PKCS8->RSA) failed (err=%#x)\n",
                            err);
                    }
                }
                else
                {
                    DWORD inner_err = GetLastError();
                    success = CryptDecodeObjectEx(
                        X509_ASN_ENCODING,
                        CNG_RSA_PRIVATE_KEY_BLOB,
                        pkcs8_info->PrivateKey.pbData,
                        pkcs8_info->PrivateKey.cbData,
                        CRYPT_DECODE_ALLOC_FLAG,
                        NULL,
                        &key_blob,
                        &key_blob_size);

                    err = GetLastError();

                    if (!success)
                    {
                        oe_secure_zero_fill(
                            pkcs8_info, (size_t)pkcs8_info_size);
                        LocalFree(pkcs8_info);
                        OE_RAISE_MSG(
                            OE_CRYPTO_ERROR,
                            "CryptDecodeObjectEx(PKCS8 inner) failed (err=%#x)\n",
                            inner_err ? inner_err : err);
                    }
                }

                oe_secure_zero_fill(pkcs8_info, (size_t)pkcs8_info_size);
                LocalFree(pkcs8_info);
            }
            else
            {
                void* pkcs1_info = NULL;
                DWORD pkcs1_info_size = 0;
                DWORD pkcs8_err = GetLastError();
                oe_result_t pkcs8_fallback_result = OE_UNEXPECTED;

                if (pkcs8_info)
                {
                    oe_secure_zero_fill(pkcs8_info, (size_t)pkcs8_info_size);
                    LocalFree(pkcs8_info);
                    pkcs8_info = NULL;
                }

                pkcs8_fallback_result = _decode_pkcs8_private_key(
                    der_data, der_data_size, &key_blob, &key_blob_size);

                if (pkcs8_fallback_result == OE_OK)
                {
                    success = TRUE;
                }
                else
                {
                    success = CryptDecodeObjectEx(
                        X509_ASN_ENCODING,
                        PKCS_RSA_PRIVATE_KEY,
                        der_data,
                        der_data_size,
                        CRYPT_DECODE_ALLOC_FLAG,
                        NULL,
                        &pkcs1_info,
                        &pkcs1_info_size);

                    if (!success || !pkcs1_info)
                    {
                        DWORD pkcs1_err = GetLastError();
                        oe_result_t fallback_result = _decode_pkcs1_private_key(
                            der_data, der_data_size, &key_blob, &key_blob_size);

                        if (fallback_result != OE_OK)
                        {
                            OE_RAISE_MSG(
                                OE_CRYPTO_ERROR,
                                "CryptDecodeObjectEx(PKCS8/PKCS1) failed (pkcs8_err=%#x, pkcs1_err=%#x)\n",
                                pkcs8_err,
                                pkcs1_err);
                        }

                        if (pkcs1_info)
                        {
                            oe_secure_zero_fill(
                                pkcs1_info, (size_t)pkcs1_info_size);
                            LocalFree(pkcs1_info);
                            pkcs1_info = NULL;
                        }

                        success = TRUE;
                    }
                    else
                    {
                        success = CryptEncodeObjectEx(
                            X509_ASN_ENCODING,
                            CNG_RSA_PRIVATE_KEY_BLOB,
                            pkcs1_info,
                            CRYPT_ENCODE_ALLOC_FLAG,
                            NULL,
                            &key_blob,
                            &key_blob_size);

                        err = GetLastError();

                        oe_secure_zero_fill(
                            pkcs1_info, (size_t)pkcs1_info_size);
                        LocalFree(pkcs1_info);
                        pkcs1_info = NULL;

                        if (!success)
                            OE_RAISE_MSG(
                                OE_CRYPTO_ERROR,
                                "CryptEncodeObjectEx (PKCS1->RSA) failed (err=%#x)\n",
                                err);
                    }
                }
            }
        }
        else
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptDecodeObjectEx failed (err=%#x)\n",
                err);
        }
    }

    if (success && key_blob && key_blob_size > 0)
    {
        NTSTATUS status = BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            NULL,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            key_handle,
            key_blob,
            key_blob_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "BCryptImportKeyPair failed (err=%#x)\n",
                status);
    }
    else
    {
        OE_RAISE(OE_CRYPTO_ERROR);
    }

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        LocalFree(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_rsa_public_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    return oe_bcrypt_encode_x509_public_key(
        key_handle, szOID_RSA_RSA, der_data, der_data_size);
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_rsa_private_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* key_blob = NULL;
    DWORD key_blob_size = 0;

    OE_CHECK(oe_bcrypt_export_key(
        key_handle, BCRYPT_RSAFULLPRIVATE_BLOB, &key_blob, &key_blob_size));

    {
        /* Encode the key_info structure as a X509 public key */
        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            CNG_RSA_PRIVATE_KEY_BLOB,
            key_blob,
            CRYPT_ENCODE_ALLOC_FLAG,
            NULL,
            der_data,
            der_data_size);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptEncodeObjectEx failed (err=%#x)\n",
                GetLastError());
    }

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Caller is responsible for calling free on padding_info->config */
static oe_result_t _get_padding_info(
    oe_hash_type_t hash_type,
    size_t hash_size,
    oe_bcrypt_padding_info_t* padding_info)
{
    oe_result_t result = OE_UNEXPECTED;
    PCWSTR hash_algorithm = NULL;

    /* Check for support hash types and correct sizes. */
    switch (hash_type)
    {
        case OE_HASH_TYPE_SHA256:
            if (hash_size != 32)
                OE_RAISE(OE_INVALID_PARAMETER);
            hash_algorithm = BCRYPT_SHA256_ALGORITHM;
            break;
        case OE_HASH_TYPE_SHA512:
            if (hash_size != 64)
                OE_RAISE(OE_INVALID_PARAMETER);
            hash_algorithm = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    /*
     * Note that we use the less secure PKCS1 signature padding
     * because Intel requires it for SGX enclave signatures.
     */
    padding_info->type = BCRYPT_PAD_PKCS1;
    padding_info->config = malloc(sizeof(BCRYPT_PKCS1_PADDING_INFO));
    if (!padding_info->config)
        OE_RAISE(OE_OUT_OF_MEMORY);

    BCRYPT_PKCS1_PADDING_INFO* info =
        (BCRYPT_PKCS1_PADDING_INFO*)(padding_info->config);
    info->pszAlgId = hash_algorithm;

    result = OE_OK;

done:
    return result;
}

void oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_bcrypt_key_init(
        (oe_bcrypt_key_t*)public_key, key_handle, OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_from_engine(
    oe_rsa_private_key_t* private_key,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id)
{
    /*
     * bcrypt does not support engines, so nothing to do.
     */
    return OE_UNSUPPORTED;
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_RSA_PRIVATE_KEY_MAGIC,
        _bcrypt_decode_rsa_private_key,
        (oe_bcrypt_key_t*)private_key);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)private_key,
        OE_RSA_PRIVATE_KEY_MAGIC,
        _bcrypt_encode_rsa_private_key,
        pem_data,
        pem_data_size);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_RSA_PUBLIC_KEY_MAGIC,
        oe_bcrypt_decode_x509_public_key,
        (oe_bcrypt_key_t*)public_key);
}

/* Used by tests/crypto/rsa_tests
 * Also used by common/cert.c for tlsverifier.c now */
oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)public_key,
        OE_RSA_PUBLIC_KEY_MAGIC,
        _bcrypt_encode_rsa_public_key,
        pem_data,
        pem_data_size);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)private_key, OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)public_key, OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_bcrypt_padding_info_t padding_info = {0};
    OE_CHECK(_get_padding_info(hash_type, hash_size, &padding_info));
    OE_CHECK(oe_private_key_sign(
        (oe_private_key_t*)private_key,
        OE_RSA_PRIVATE_KEY_MAGIC,
        &padding_info,
        hash_data,
        hash_size,
        signature,
        signature_size));

    result = OE_OK;

done:
    if (padding_info.config)
        free(padding_info.config);

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_bcrypt_padding_info_t padding_info = {0};
    OE_CHECK(_get_padding_info(hash_type, hash_size, &padding_info));
    OE_CHECK(oe_public_key_verify(
        (oe_public_key_t*)public_key,
        OE_RSA_PUBLIC_KEY_MAGIC,
        &padding_info,
        hash_data,
        hash_size,
        signature,
        signature_size));

    result = OE_OK;

done:
    if (padding_info.config)
        free(padding_info.config);

    return result;
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* modulus,
    size_t* modulus_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PUBLIC_KEY_MAGIC) ||
        !modulus_size || *modulus_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If modulus is null, then modulus_size must be zero */
    if (!modulus && *modulus_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)key_blob;
    assert(keyblob->cbModulus != 0);
    if (keyblob->cbModulus > *modulus_size)
    {
        *modulus_size = keyblob->cbModulus;

        if (modulus)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        /* If modulus is null, this call is intented to get the correct
         * modulus_size so no need to trace OE_BUFFER_TOO_SMALL */
        else
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        modulus,
        *modulus_size,
        key_blob + sizeof(*keyblob) + keyblob->cbPublicExp,
        keyblob->cbModulus));

    *modulus_size = keyblob->cbModulus;
    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* exponent,
    size_t* exponent_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PUBLIC_KEY_MAGIC) ||
        !exponent_size || *exponent_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If exponent is null, then exponent_size must be zero */
    if (!exponent && *exponent_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)key_blob;
    assert(keyblob->cbPublicExp != 0);
    if (keyblob->cbPublicExp > *exponent_size)
    {
        *exponent_size = keyblob->cbPublicExp;

        if (exponent)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        /* If exponent is null, this call is intented to get the correct
         * exponent_size so no need to trace OE_BUFFER_TOO_SMALL */
        else
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        exponent,
        *exponent_size,
        key_blob + sizeof(*keyblob),
        keyblob->cbPublicExp));

    *exponent_size = keyblob->cbPublicExp;
    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    /* key1 and key2 are both BCRYPT_RSAKEY_BLOB structures
     * which should be comparable as raw byte buffers.
     */
    BYTE* key1 = NULL;
    BYTE* key2 = NULL;
    ULONG key1_size = 0;
    ULONG key2_size = 0;

    if (equal)
        *equal = false;
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key1,
        OE_RSA_PUBLIC_KEY_MAGIC,
        BCRYPT_RSAPUBLIC_BLOB,
        &key1,
        &key1_size));

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key2,
        OE_RSA_PUBLIC_KEY_MAGIC,
        BCRYPT_RSAPUBLIC_BLOB,
        &key2,
        &key2_size));

    if ((key1_size == key2_size) &&
        oe_constant_time_mem_equal(key1, key2, key1_size))
    {
        *equal = true;
    }

    result = OE_OK;

done:
    if (key1)
    {
        oe_secure_zero_fill(key1, key1_size);
        free(key1);
        key1_size = 0;
    }

    if (key2)
    {
        oe_secure_zero_fill(key2, key2_size);
        free(key2);
        key2_size = 0;
    }
    return result;
}

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)private_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;

    if (public_key)
        memset(public_key, 0, sizeof(oe_rsa_public_key_t));

    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PRIVATE_KEY_MAGIC) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));
    /*
     * Export the key blob to a public key. Note that the private key blob has
     * the modulus and the exponent already, so we can just use it to import
     * the public key.
     */
    {
        NTSTATUS status;
        BCRYPT_KEY_HANDLE public_key_handle;

        status = BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &public_key_handle,
            key_blob,
            key_blob_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        oe_rsa_public_key_init(public_key, public_key_handle);
    }

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_from_modulus(
    const uint8_t* modulus,
    size_t modulus_size,
    const uint8_t* exponent,
    size_t exponent_size,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    BCRYPT_KEY_HANDLE key_handle;
    uint8_t* key_data_bytes = NULL;
    size_t key_data_size = 0;

    if (!public_key || modulus_size > ULONG_MAX || exponent_size > ULONG_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    key_data_size = sizeof(BCRYPT_RSAKEY_BLOB) + exponent_size + modulus_size;
    key_data_bytes = malloc(key_data_size);
    if (!key_data_bytes)
        OE_RAISE(OE_OUT_OF_MEMORY);

    BCRYPT_RSAKEY_BLOB* blob = (BCRYPT_RSAKEY_BLOB*)key_data_bytes;

    blob->BitLength = (ULONG)modulus_size;
    blob->cbModulus = (ULONG)modulus_size;
    blob->cbPublicExp = (ULONG)exponent_size;
    blob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob->cbPrime1 = 0;
    blob->cbPrime2 = 0;

    OE_CHECK(oe_memcpy_s(
        key_data_bytes + sizeof(BCRYPT_RSAKEY_BLOB),
        (ULONG)exponent_size,
        exponent,
        (ULONG)exponent_size));
    OE_CHECK(oe_memcpy_s(
        key_data_bytes + sizeof(BCRYPT_RSAKEY_BLOB) + exponent_size,
        (ULONG)modulus_size,
        modulus,
        (ULONG)modulus_size));

    status = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &key_handle,
        (PUCHAR)key_data_bytes,
        (ULONG)key_data_size,
        BCRYPT_NO_KEY_VALIDATION);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptImportKeyPair failed with %#x", status);

    oe_rsa_public_key_init(public_key, key_handle);

    result = OE_OK;

done:
    free(key_data_bytes);

    return result;
}
