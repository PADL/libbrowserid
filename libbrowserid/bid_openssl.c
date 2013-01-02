/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <ctype.h>

#ifdef GSSBID_DEBUG
#define BID_CRYPTO_PRINT_ERRORS() do { ERR_print_errors_fp(stderr); } while (0)
#else
#define BID_CRYPTO_PRINT_ERRORS()
#endif

static BIDError
_BIDGetJsonBNValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    uint32_t encoding,
    BIGNUM **bn)
{
    BIDError err;
    json_t *value;
    const char *szValue;

    *bn = NULL;

    if (key != NULL)
        value = json_object_get(jwk, key);
    else
        value = jwk;
    if (value == NULL)
        return BID_S_NO_KEY;

    szValue = json_string_value(value);
    if (szValue == NULL)
        return BID_S_INVALID_KEY;

    err = BID_S_INVALID_KEY;

    if ((encoding == BID_JSON_ENCODING_BASE64) ||
        !_BIDIsLegacyJWK(context, jwk)) {
        unsigned char buf[512];
        unsigned char *pBuf = buf;
        size_t len = sizeof(buf);
        BIDError err2;

        err2 = _BIDBase64UrlDecode(szValue, &pBuf, &len);
        if (err2 == BID_S_OK) {
            *bn = BN_bin2bn(buf, len, NULL);
            if (*bn != NULL)
                err = BID_S_OK;
            memset(buf, 0, sizeof(buf));
        }
    } else {
        size_t len = strlen(szValue), i;
        size_t cchDecimal = 0;

        /* XXX this is bogus, a hex string could also be a valid decimal string. */
        for (i = 0; i < len; i++) {
            if (isdigit(szValue[i]))
                cchDecimal++;
        }

        if (cchDecimal == len ? BN_dec2bn(bn, szValue) : BN_hex2bn(bn, szValue))
            err = BID_S_OK;
    }

    return err;
}

#ifdef GSSBID_DEBUG
static void
_BIDDebugJsonBNValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    uint32_t encoding)
{
    BIGNUM *bn;

    if (_BIDGetJsonBNValue(context, jwk, key, encoding, &bn) == BID_S_OK) {
        fprintf(stderr, "_BIDDebugJsonBNValue %s: ", key);
        BN_print_fp(stderr, bn);
        printf("\n");
        BN_free(bn);
    }
}
#endif

static BIDError
_BIDSetJsonBNValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    BIGNUM *bn)
{
    BIDError err;
    unsigned char buf[1024];
    unsigned char *pbData;
    size_t cbData;
    int bFreeData = 0;
    json_t *j = NULL;

    cbData = BN_num_bytes(bn);
    if (cbData > sizeof(buf)) {
        pbData = BIDMalloc(cbData);
        if (pbData == NULL)
            return BID_S_NO_MEMORY;
        bFreeData = 1;
    } else
        pbData = buf;

    cbData = BN_bn2bin(bn, pbData);

    err = _BIDJsonBinaryValue(context, pbData, cbData, &j);
    if (err == BID_S_OK) {
        if (json_object_set(jwk, key, j) < 0)
            err = BID_S_NO_MEMORY;
    }

    if (bFreeData)
        BIDFree(pbData);
    json_decref(j);

    return err;
}

static BIDError
_BIDEvpForAlgorithm(
    struct BIDJWTAlgorithmDesc *algorithm,
    const EVP_MD **pMd)
{
    const EVP_MD *md;

    *pMd = NULL;

    if (strlen(algorithm->szAlgID) != 5)
        return BID_S_CRYPTO_ERROR;

    if (strcmp(algorithm->szAlgID, "DS128") == 0) {
        md = EVP_sha1();
    } else if (strcmp(&algorithm->szAlgID[1], "S512") == 0) {
        md = EVP_sha512();
    } else if (strcmp(&algorithm->szAlgID[1], "S384") == 0) {
        md = EVP_sha384();
    } else if (strcmp(&algorithm->szAlgID[1], "S256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(&algorithm->szAlgID[1], "S224") == 0) {
        md = EVP_sha224();
    } else {
        return BID_S_CRYPTO_ERROR;
    }

    *pMd = md;
    return BID_S_OK;
}

static BIDError
_BIDMakeShaDigest(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    unsigned char *digest,
    size_t *digestLength)
{
    BIDError err;
    const EVP_MD *md;
    EVP_MD_CTX mdCtx;
    unsigned char shaMd[EVP_MAX_MD_SIZE] = { 0 };
    unsigned int mdLength = sizeof(md);

    err = _BIDEvpForAlgorithm(algorithm, &md);
    if (err != BID_S_OK)
        return err;

    if (*digestLength < EVP_MD_size(md))
        return BID_S_BUFFER_TOO_SMALL;

    EVP_DigestInit(&mdCtx, md);
    EVP_DigestUpdate(&mdCtx, jwt->EncData, jwt->EncDataLength);
    EVP_DigestFinal(&mdCtx, shaMd, &mdLength);

    if (*digestLength > mdLength)
        *digestLength = mdLength;

    memcpy(digest, shaMd, *digestLength);

    return BID_S_OK;
}

static BIDError
_BIDMakeRsaKey(
    BIDContext context,
    BIDJWK jwk,
    int public,
    RSA **pRsa)
{
    BIDError err;
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (rsa == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    err = _BIDGetJsonBNValue(context, jwk, "n", BID_JSON_ENCODING_UNKNOWN, &rsa->n);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "e", BID_JSON_ENCODING_UNKNOWN, &rsa->e);
    BID_BAIL_ON_ERROR(err);

    if (!public) {
        err = _BIDGetJsonBNValue(context, jwk, "d", BID_JSON_ENCODING_UNKNOWN, &rsa->d);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    *pRsa = rsa;

cleanup:
    if (err != BID_S_OK)
        RSA_free(rsa);

    return err;
}

static BIDError
_RSAKeySize(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWK jwk,
    size_t *pcbKey)
{
    BIDError err;
    RSA *rsa = NULL;

    err = _BIDMakeRsaKey(context, jwk, 0, &rsa);
    if (err != BID_S_OK)
        return err;

    *pcbKey = RSA_size(rsa);
    RSA_free(rsa);

    return BID_S_OK;
}

static BIDError
_RSAMakeSignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk)
{
    BIDError err;
    RSA *rsa = NULL;
    unsigned char digest[19 + EVP_MAX_MD_SIZE];
    size_t digestLength = EVP_MAX_MD_SIZE;
    ssize_t signatureLength;

    err = _BIDMakeRsaKey(context, jwk, 0, &rsa);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);
    BID_ASSERT(algorithm->cbOid == sizeof(digest) - EVP_MAX_MD_SIZE);

    memcpy(digest, algorithm->pbOid, algorithm->cbOid);

    err = _BIDMakeShaDigest(algorithm, context, jwt, &digest[algorithm->cbOid], &digestLength);
    BID_BAIL_ON_ERROR(err);

    digestLength += algorithm->cbOid;

    jwt->Signature = BIDMalloc(RSA_size(rsa));
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    signatureLength = RSA_private_encrypt(digestLength,
                                          digest,
                                          jwt->Signature,
                                          rsa,
                                          RSA_PKCS1_PADDING);

    if (signatureLength < 0) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    jwt->SignatureLength = signatureLength;
    err = BID_S_OK;

cleanup:
    RSA_free(rsa);

    return err;
}

static BIDError
_RSAVerifySignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk,
    int *valid)
{
    BIDError err;
    RSA *rsa = NULL;
    unsigned char digest[19 + EVP_MAX_MD_SIZE];
    size_t digestLength = EVP_MAX_MD_SIZE;
    unsigned char *signature = NULL;
    ssize_t signatureLength;

    *valid = 0;

    err = _BIDMakeRsaKey(context, jwk, 1, &rsa);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);
    BID_ASSERT(algorithm->cbOid == sizeof(digest) - EVP_MAX_MD_SIZE);

    memcpy(digest, algorithm->pbOid, algorithm->cbOid);

    err = _BIDMakeShaDigest(algorithm, context, jwt, &digest[algorithm->cbOid], &digestLength);
    BID_BAIL_ON_ERROR(err);

    digestLength += algorithm->cbOid;

    signature = BIDMalloc(RSA_size(rsa));
    if (signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    signatureLength = RSA_public_decrypt(jwt->SignatureLength,
                                         jwt->Signature,
                                         signature,
                                         rsa,
                                         RSA_PKCS1_PADDING);
    if (signatureLength < 0) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    *valid = (signatureLength == digestLength &&
              memcmp(signature, digest, signatureLength) == 0);

cleanup:
    RSA_free(rsa);
    BIDFree(signature);

    return err;
}

static BIDError
_BIDMakeDsaKey(BIDContext context, BIDJWK jwk, int public, DSA **pDsa)
{
    BIDError err;
    DSA *dsa = NULL;

    dsa = DSA_new();
    if (dsa == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    err = _BIDGetJsonBNValue(context, jwk, "p", BID_JSON_ENCODING_UNKNOWN, &dsa->p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "q", BID_JSON_ENCODING_UNKNOWN, &dsa->q);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "g", BID_JSON_ENCODING_UNKNOWN, &dsa->g);
    BID_BAIL_ON_ERROR(err);

    if (public)
        err = _BIDGetJsonBNValue(context, jwk, "y", BID_JSON_ENCODING_UNKNOWN, &dsa->pub_key);
    else
        err = _BIDGetJsonBNValue(context, jwk, "x", BID_JSON_ENCODING_UNKNOWN, &dsa->priv_key);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pDsa = dsa;

cleanup:
    if (err != BID_S_OK)
        DSA_free(dsa);

    return err;
}

static BIDError
_DSAKeySize(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWK jwk,
    size_t *pcbKey)
{
    BIDError err;
    BIGNUM *p;
    size_t cbKey;

    err = _BIDGetJsonBNValue(context, jwk, "p", BID_JSON_ENCODING_UNKNOWN, &p);
    if (err != BID_S_OK)
        return err;

    /*
     * FIPS 186-3[3] specifies L and N length pairs of
     * (1024,160), (2048,224), (2048,256), and (3072,256).
     */
    cbKey = BN_num_bytes(p);
    if (cbKey < 160)
        cbKey = 160;
    else if (cbKey < 224)
        cbKey = 224;
    else if (cbKey < 256)
        cbKey = 256;

    BN_free(p);

    *pcbKey = cbKey;
    return BID_S_OK;
}

static BIDError
_DSAMakeSignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk)
{
    BIDError err;
    DSA *dsa = NULL;
    DSA_SIG *dsaSig = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digestLength = sizeof(digest);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMakeShaDigest(algorithm, context, jwt, digest, &digestLength);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeDsaKey(context, jwk, 0, &dsa);
    BID_BAIL_ON_ERROR(err);

    dsaSig = DSA_do_sign(digest, digestLength, dsa);
    if (dsaSig == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    if (BN_num_bytes(dsaSig->r) > digestLength ||
        BN_num_bytes(dsaSig->s) > digestLength) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    jwt->Signature = BIDMalloc(2 * digestLength);
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    BN_bn2bin(dsaSig->r, &jwt->Signature[0]);
    BN_bn2bin(dsaSig->s, &jwt->Signature[digestLength]);

    jwt->SignatureLength = 2 * digestLength;

    err = BID_S_OK;

cleanup:
    DSA_free(dsa);
    DSA_SIG_free(dsaSig);

    return err;
}

static BIDError
_DSAVerifySignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk,
    int *valid)
{
    BIDError err;
    DSA *dsa = NULL;
    DSA_SIG *dsaSig = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digestLength = sizeof(digest);

    *valid = 0;

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMakeDsaKey(context, jwk, 1, &dsa);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeShaDigest(algorithm, context, jwt, digest, &digestLength);
    BID_BAIL_ON_ERROR(err);

    if (jwt->SignatureLength != 2 * digestLength) {
        err = BID_S_INVALID_SIGNATURE;
        goto cleanup;
    }

    dsaSig = DSA_SIG_new();
    if (dsaSig == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    dsaSig->r = BN_bin2bn(&jwt->Signature[0],            digestLength, NULL);
    dsaSig->s = BN_bin2bn(&jwt->Signature[digestLength], digestLength, NULL);

    *valid = DSA_do_verify(digest, digestLength, dsaSig, dsa);
    if (*valid < 0) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    DSA_free(dsa);
    DSA_SIG_free(dsaSig);

    return err;
}

static BIDError
_BIDHMACSHA(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk,
    unsigned char *hmac,
    size_t *hmacLength)
{
    BIDError err;
    HMAC_CTX h;
    const EVP_MD *md;
    unsigned char *pbKey = NULL;
    size_t cbKey = 0;
    unsigned int mdLen = *hmacLength;

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDEvpForAlgorithm(algorithm, &md);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBinaryValue(context, jwk, "secret-key", &pbKey, &cbKey);
    BID_BAIL_ON_ERROR(err);

    HMAC_Init(&h, pbKey, cbKey, md);
    HMAC_Update(&h, (const unsigned char *)jwt->EncData, jwt->EncDataLength);
    HMAC_Final(&h, hmac, &mdLen);

    *hmacLength = mdLen;

cleanup:
    if (pbKey != NULL) {
        memset(pbKey, 0, cbKey);
        BIDFree(pbKey);
    }

    return err;
}

static BIDError
_HMACSHAMakeSignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk)
{
    BIDError err;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digestLength = sizeof(digest);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDHMACSHA(algorithm, context, jwt, jwk, digest, &digestLength);
    BID_BAIL_ON_ERROR(err);

    jwt->Signature = BIDMalloc(digestLength);
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    memcpy(jwt->Signature, digest, digestLength);
    jwt->SignatureLength = digestLength;

cleanup:
    memset(digest, 0, sizeof(digest));

    return err;
}

static BIDError
_HMACSHAVerifySignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk,
    int *valid)
{
    BIDError err;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digestLength = sizeof(digest);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDHMACSHA(algorithm, context, jwt, jwk, digest, &digestLength);
    if (err != BID_S_OK)
        return err;

    *valid = (jwt->SignatureLength == digestLength) &&
             (memcmp(jwt->Signature, digest, digestLength) == 0);

    return BID_S_OK;
}

BIDError
_BIDDigestAssertion(
    BIDContext context,
    const char *szAssertion,
    unsigned char *digest,
    size_t *digestLength)
{
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX mdCtx;
    unsigned int mdLength = *digestLength;

    if (*digestLength < EVP_MD_size(md))
        return BID_S_BUFFER_TOO_SMALL;

    EVP_DigestInit(&mdCtx, md);
    EVP_DigestUpdate(&mdCtx, szAssertion, strlen(szAssertion));
    EVP_DigestFinal(&mdCtx, digest, &mdLength);

    *digestLength = mdLength;

    return BID_S_OK;
}

struct BIDJWTAlgorithmDesc
_BIDJWTAlgorithms[] = {
#if 0
    {
        "RS512",
        "RSA",
        0,
        (const unsigned char *)"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x40",
        19,
        _RSAMakeSignature,
        _RSAVerifySignature,
        _RSAKeySize,
    },
    {
        "RS384",
        "RSA",
        0,
        (const unsigned char *)"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x30",
        19,
        _RSAMakeSignature,
        _RSAVerifySignature,
        _RSAKeySize,
    },
#endif
    {
        "RS256",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _RSAMakeSignature,
        _RSAVerifySignature,
        _RSAKeySize,
    },
    {
        "RS128",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _RSAMakeSignature,
        _RSAVerifySignature,
        _RSAKeySize,
    },
    {
        "RS64",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _RSAMakeSignature,
        _RSAVerifySignature,
        _RSAKeySize,
    },
    {
        "DS256",
        "DSA",
        256,
        NULL,
        0,
        _DSAMakeSignature,
        _DSAVerifySignature,
        _DSAKeySize,
    },
    {
        "DS128",
        "DSA",
        160,
        NULL,
        0,
        _DSAMakeSignature,
        _DSAVerifySignature,
        _DSAKeySize,
    },
    {
        "HS256",
        "HS",
        0,
        NULL,
        0,
        _HMACSHAMakeSignature,
        _HMACSHAVerifySignature,
        NULL,
    },
    {
        NULL
    },
};

BIDError
_BIDMakeDHKey(
    BIDContext context,
    json_t *dhParams,
    json_t *dhSecret,
    DH **pDh)
{
    BIDError err;
    DH *dh = NULL;

    *pDh = NULL;

    if (dhParams == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    dh = DH_new();
    if (dh == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDGetJsonBNValue(context, dhParams, "p", BID_JSON_ENCODING_BASE64, &dh->p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, dhParams, "g", BID_JSON_ENCODING_BASE64, &dh->g);
    BID_BAIL_ON_ERROR(err);

    if (dhSecret != NULL) {
        err = _BIDGetJsonBNValue(context, dhSecret, "y", BID_JSON_ENCODING_BASE64, &dh->pub_key);
        BID_BAIL_ON_ERROR(err);

        err = _BIDGetJsonBNValue(context, dhSecret, "x", BID_JSON_ENCODING_BASE64, &dh->priv_key);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    *pDh = dh;

cleanup:
    if (err != BID_S_OK)
        DH_free(dh);

    return err;
}

BIDError
_BIDGenerateDHParams(
    BIDContext context,
    json_t **pDhParams)
{
    BIDError err;
    json_t *dhParams = NULL;
    DH *dh = NULL;
    int codes = 0;

    *pDhParams = NULL;

    dh = DH_new();
    if (dh == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    BID_ASSERT(context->DhKeySize != 0);

    if (!DH_generate_parameters_ex(dh, context->DhKeySize, DH_GENERATOR_2, NULL)) {
        err = BID_S_DH_PARAM_GENERATION_FAILURE;
        goto cleanup;
    }

    if (!DH_check(dh, &codes)) {
        err = BID_S_DH_PARAM_GENERATION_FAILURE;
        goto cleanup;
    }

    if (codes & DH_CHECK_P_NOT_PRIME)
        err = BID_S_DH_CHECK_P_NOT_PRIME;
    else if (codes & DH_CHECK_P_NOT_SAFE_PRIME)
        err = BID_S_DH_CHECK_P_NOT_SAFE_PRIME;
    else if (codes & DH_UNABLE_TO_CHECK_GENERATOR)
        err = BID_S_DH_UNABLE_TO_CHECK_GENERATOR;
    else if (codes & DH_NOT_SUITABLE_GENERATOR)
        err = BID_S_DH_NOT_SUITABLE_GENERATOR;
    else
        err = BID_S_OK;
    BID_BAIL_ON_ERROR(err);

    dhParams = json_object();
    if (dhParams == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDSetJsonBNValue(context, dhParams, "p", dh->p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonBNValue(context, dhParams, "g", dh->g);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pDhParams = dhParams;

cleanup:
    if (err != BID_S_OK) {
        json_decref(dhParams);
    }
    DH_free(dh);

    return err;
}

BIDError
_BIDGenerateDHKey(
    BIDContext context,
    json_t *dhParams,
    BIDJWK *pDhKey)
{
    BIDError err;
    DH *dh = NULL;
    json_t *dhKey = NULL;

    err = _BIDMakeDHKey(context, dhParams, NULL, &dh);
    BID_BAIL_ON_ERROR(err);

    dhKey = json_object();
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (!DH_generate_key(dh)) {
        err = BID_S_DH_KEY_GENERATION_FAILURE;
        goto cleanup;
    }

    dhKey = json_object();
    if (dhKey == NULL ||
        json_object_set(dhKey, "params", dhParams) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDSetJsonBNValue(context, dhKey, "x", dh->priv_key);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonBNValue(context, dhKey, "y", dh->pub_key);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pDhKey = dhKey;

cleanup:
    if (err != BID_S_OK) {
        json_decref(dhKey);
    }
    DH_free(dh);

    return err;
}

BIDError
_BIDComputeDHKey(
    BIDContext context,
    BIDJWK dhKey,
    json_t *pubValue,
    unsigned char **ppbKey,
    size_t *pcbKey)
{
    BIDError err;
    json_t *dhParams;
    unsigned char *pbKey = NULL;
    ssize_t cbKey = 0;
    BIGNUM *pub = NULL;
    DH *dh = NULL;

    *ppbKey = NULL;
    *pcbKey = 0;

    if (dhKey == NULL || pubValue == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    dhParams = json_object_get(dhKey, "params");
    if (dhParams == NULL) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    err = _BIDGetJsonBNValue(context, pubValue, "y", BID_JSON_ENCODING_BASE64, &pub);
    BID_BAIL_ON_ERROR(err);

    dh = DH_new();

    err = _BIDMakeDHKey(context, dhParams, dhKey, &dh);
    BID_BAIL_ON_ERROR(err);

    cbKey = DH_size(dh);
    if (cbKey < 0) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    pbKey = BIDMalloc(cbKey);
    if (pbKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    cbKey = DH_compute_key(pbKey, pub, dh);
    if (cbKey < 0) {
        err = BID_S_DH_KEY_GENERATION_FAILURE;
        goto cleanup;
    }

    err = BID_S_OK;
    *ppbKey = pbKey;
    *pcbKey = cbKey;

cleanup:
    if (err != BID_S_OK)
        BIDFree(pbKey);
    BN_free(pub);
    DH_free(dh);

    return err;
}

BIDError
_BIDGenerateNonce(
    BIDContext context,
    json_t **pNonce)
{
    unsigned char nonce[8];

    *pNonce = NULL;

    if (!RAND_bytes(nonce, sizeof(nonce)))
        return BID_S_CRYPTO_ERROR;

    return _BIDJsonBinaryValue(context, nonce, sizeof(nonce), pNonce);
}

static const unsigned char _BIDARKSalt[] = "browserid-reauth";

BIDError
_BIDDeriveAuthenticatorRootKey(
    BIDContext context,
    BIDIdentity identity,
    BIDJWK *pArk)
{
    HMAC_CTX h;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int mdLength = sizeof(digest);
    BIDError err;
    BIDJWK ark = NULL;
    json_t *sk = NULL;
    unsigned char T0 = 0x00;

    *pArk = NULL;

    err = BIDGetIdentitySessionKey(context, identity, NULL, NULL);
    BID_BAIL_ON_ERROR(err);

    HMAC_Init(&h, identity->SessionKey, identity->SessionKeyLength, EVP_sha256());
    HMAC_Update(&h, _BIDARKSalt, sizeof(_BIDARKSalt) - 1);
    HMAC_Update(&h, &T0, 1);
    HMAC_Final(&h, digest, &mdLength);

    ark = json_object();
    if (ark == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonBinaryValue(context, digest, mdLength, &sk);
    BID_BAIL_ON_ERROR(err);

    if (json_object_set(ark, "secret-key", sk) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    *pArk = ark;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK)
        json_decref(ark);
    json_decref(sk);
    memset(digest, 0, sizeof(digest));

    return err;
}

BIDError
_BIDDeriveAuthenticatorSessionKey(
    BIDContext context,
    BIDJWK ark,
    BIDJWT ap,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey)
{
    BIDError err;
    HMAC_CTX h;
    unsigned char *pbArk = NULL, *pbNonce = NULL;
    size_t cbArk, cbNonce;
    unsigned int mdLength;
    unsigned char T1 = 0x01;
    uint64_t ts;
    unsigned char pbTimestamp[8];

    *ppbSessionKey = NULL;
    *pcbSessionKey = 0;

    err = _BIDGetJsonBinaryValue(context, ark, "secret-key", &pbArk, &cbArk);
    BID_BAIL_ON_ERROR(err);

    ts = json_integer_value(json_object_get(ap->Payload, "ts"));

    pbTimestamp[0] = (unsigned char)((ts >> 56) & 0xff);
    pbTimestamp[1] = (unsigned char)((ts >> 48) & 0xff);
    pbTimestamp[2] = (unsigned char)((ts >> 40) & 0xff);
    pbTimestamp[3] = (unsigned char)((ts >> 32) & 0xff);
    pbTimestamp[4] = (unsigned char)((ts >> 24) & 0xff);
    pbTimestamp[5] = (unsigned char)((ts >> 16) & 0xff);
    pbTimestamp[6] = (unsigned char)((ts >>  8) & 0xff);
    pbTimestamp[7] = (unsigned char)((ts      ) & 0xff);

    err = _BIDGetJsonBinaryValue(context, ap->Payload, "n", &pbNonce, &cbNonce);
    BID_BAIL_ON_ERROR(err);

    HMAC_Init(&h, pbArk, cbArk, EVP_sha256());
    HMAC_Update(&h, _BIDARKSalt, sizeof(_BIDARKSalt) - 1);
    HMAC_Update(&h, pbTimestamp, sizeof(pbTimestamp));
    HMAC_Update(&h, pbNonce, cbNonce);
    HMAC_Update(&h, &T1, 1);

    *ppbSessionKey = BIDMalloc(SHA256_DIGEST_LENGTH);
    if (*ppbSessionKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    mdLength = SHA256_DIGEST_LENGTH;
    HMAC_Final(&h, *ppbSessionKey, &mdLength);
    *pcbSessionKey = mdLength;

    err = BID_S_OK;

cleanup:
    if (pbArk != NULL) {
        memset(pbArk, 0, cbArk);
        BIDFree(pbArk);
    }
    BIDFree(pbNonce);

    return err;
}
