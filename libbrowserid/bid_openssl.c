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
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <ctype.h>

#ifdef GSSBID_DEBUG
#define BID_CRYPTO_PRINT_ERRORS() do { ERR_print_errors_fp(stderr); } while (0)
#else
#define BID_CRYPTO_PRINT_ERRORS()
#endif

#define BID_JSON_ENCODING_UNKNOWN   0
#define BID_JSON_ENCODING_BASE64    1

static void
_BIDOpenSSLInit(void) __attribute__((__constructor__));

static void
_BIDOpenSSLInit(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

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

#if 0
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
    if (err == BID_S_OK)
        err = _BIDJsonObjectSet(context, jwk, key, j, 0);

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
    BIDContext context BID_UNUSED,
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
_BIDCertDataToX509(
    BIDContext context BID_UNUSED,
    json_t *x5c,
    int index,
    X509 **pX509)
{
    BIDError err;
    const char *szCert;
    unsigned char *pbData = NULL;
    const unsigned char *p;
    size_t cbData = 0;

    if (x5c == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    szCert = json_string_value(json_array_get(x5c, index));
    if (szCert == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    err = _BIDBase64UrlDecode(szCert, &pbData, &cbData);
    BID_BAIL_ON_ERROR(err);

    p = pbData;

    *pX509 = d2i_X509(NULL, &p, cbData);
    if (*pX509 == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

cleanup:
    BIDFree(pbData);

    return err;
}

static BIDError
_BIDCertDataToX509RsaKey(
    BIDContext context,
    json_t *x5c,
    RSA **pRsa)
{
    BIDError err;
    X509 *x509;
    EVP_PKEY *pkey;

    err = _BIDCertDataToX509(context, x5c, 0, &x509);
    if (err != BID_S_OK)
        return err;

    pkey = X509_get_pubkey(x509);
    if (pkey == NULL || EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
        X509_free(x509);
        return BID_S_NO_KEY;
    }

    RSA_up_ref(pkey->pkey.rsa);
    *pRsa = pkey->pkey.rsa;

    X509_free(x509);

    return BID_S_OK;
}

static BIDError
_BIDMakeJwtRsaKey(
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
_BIDMakeRsaKey(
    BIDContext context,
    BIDJWK jwk,
    int public,
    RSA **pRsa)
{
    BIDError err;
    json_t *x5c;

    *pRsa = NULL;

    x5c = json_object_get(jwk, "x5c");
    if (public && x5c != NULL)
        err = _BIDCertDataToX509RsaKey(context, x5c, pRsa);
    else
        err = _BIDMakeJwtRsaKey(context, jwk, public, pRsa);

    return err;
}

static BIDError
_RSAKeySize(
    struct BIDJWTAlgorithmDesc *algorithm BID_UNUSED,
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
_BIDCertDataToX509DsaKey(
    BIDContext context,
    json_t *x5c,
    DSA **pDsa)
{
    BIDError err;
    X509 *x509;
    EVP_PKEY *pkey;

    err = _BIDCertDataToX509(context, x5c, 0, &x509);
    if (err != BID_S_OK)
        return err;

    pkey = X509_get_pubkey(x509);
    if (pkey == NULL || EVP_PKEY_type(pkey->type) != EVP_PKEY_RSA) {
        X509_free(x509);
        return BID_S_NO_KEY;
    }

    DSA_up_ref(pkey->pkey.dsa);
    *pDsa = pkey->pkey.dsa;

    X509_free(x509);

    return BID_S_OK;
}

static BIDError
_BIDMakeJwtDsaKey(BIDContext context, BIDJWK jwk, int public, DSA **pDsa)
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
_BIDMakeDsaKey(
    BIDContext context,
    BIDJWK jwk,
    int public,
    DSA **pDsa)
{
    BIDError err;
    json_t *x5c;

    *pDsa = NULL;

    x5c = json_object_get(jwk, "x5c");
    if (public && x5c != NULL)
        err = _BIDCertDataToX509DsaKey(context, x5c, pDsa);
    else
        err = _BIDMakeJwtDsaKey(context, jwk, public, pDsa);

    return err;
}

static BIDError
_DSAKeySize(
    struct BIDJWTAlgorithmDesc *algorithm BID_UNUSED,
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
    BIDContext context BID_UNUSED,
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
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, dhKey, "params", dhParams, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

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

static const unsigned char _BIDSalt[9] = "BrowserID";

BIDError
_BIDDeriveKey(
    BIDContext context BID_UNUSED,
    const unsigned char *pbBaseKey,
    size_t cbBaseKey,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey)
{
    HMAC_CTX h;
    unsigned char T1 = 0x01;
    unsigned int mdLength = SHA256_DIGEST_LENGTH;

    *ppbDerivedKey = NULL;
    *pcbDerivedKey = 0;

    *ppbDerivedKey = BIDMalloc(mdLength);
    if (*ppbDerivedKey == NULL)
        return BID_S_NO_MEMORY;

    HMAC_Init(&h, pbBaseKey, cbBaseKey, EVP_sha256());
    HMAC_Update(&h, _BIDSalt, sizeof(_BIDSalt));
    if (pbSalt != NULL)
        HMAC_Update(&h, pbSalt, cbSalt);
    HMAC_Update(&h, &T1, 1);

    HMAC_Final(&h, *ppbDerivedKey, &mdLength);
    *pcbDerivedKey = mdLength;

    return BID_S_OK;
}

BIDError
_BIDLoadX509PrivateKey(
    BIDContext context BID_UNUSED,
    const char *path,
    BIDJWK *pPrivateKey)
{
    BIDError err;
    BIDJWK privateKey = NULL;
    FILE *fp = NULL;
    EVP_PKEY *pemKey = NULL;

    *pPrivateKey = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        err = BID_S_KEY_FILE_UNREADABLE;
        goto cleanup;
    }

    pemKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pemKey == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_KEY_FILE_UNREADABLE;
        goto cleanup;
    }

    privateKey = json_object();
    if (privateKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, privateKey, "version", json_string("2012.08.15"), BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (pemKey->pkey.ptr == NULL) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    switch (pemKey->type) {
    case EVP_PKEY_RSA:
        err = _BIDJsonObjectSet(context, privateKey, "algorithm", json_string("RS"), BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "n", pemKey->pkey.rsa->n);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "e", pemKey->pkey.rsa->e);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "d", pemKey->pkey.rsa->d);
        BID_BAIL_ON_ERROR(err);

        break;
    case EVP_PKEY_DSA:
        err = _BIDJsonObjectSet(context, privateKey, "algorithm", json_string("DS"), BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "p", pemKey->pkey.dsa->p);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "q", pemKey->pkey.dsa->q);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "g", pemKey->pkey.dsa->g);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonBNValue(context, privateKey, "x", pemKey->pkey.dsa->priv_key);
        BID_BAIL_ON_ERROR(err);

        break;
    default:
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    *pPrivateKey = privateKey;

cleanup:
    if (fp != NULL)
        fclose(fp);
    if (pemKey != NULL)
        EVP_PKEY_free(pemKey);
    if (err != BID_S_OK)
        json_decref(privateKey);

    return err;
}

BIDError
_BIDLoadX509Certificate(
    BIDContext context BID_UNUSED,
    const char *path,
    json_t **pCert)
{
    BIDError err;
    json_t *cert = NULL;
    FILE *fp = NULL;
    X509 *pemCert = NULL;
    unsigned char *pbData = NULL, *p;
    size_t cbData = 0;

    *pCert = NULL;

    fp = fopen(path, "r");
    if (fp == NULL) {
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    pemCert = PEM_ASN1_read((void *(*) ()) d2i_X509, PEM_STRING_X509, fp, NULL, NULL, NULL);
    if (pemCert == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    cbData = i2d_X509(pemCert, NULL);

    p = pbData = BIDMalloc(cbData);
    if (pbData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (i2d_X509(pemCert, &p) < 0) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    /* XXX should be base64 (not URL) encoded */
    err = _BIDJsonBinaryValue(context, pbData, cbData, &cert);
    BID_BAIL_ON_ERROR(err);

    *pCert = cert;

cleanup:
    if (fp != NULL)
        fclose(fp);
    if (pemCert != NULL)
        X509_free(pemCert);
    if (err != BID_S_OK)
        json_decref(cert);
    BIDFree(pbData);

    return err;
}

static BIDError
_BIDSetJsonX509Name(
    BIDContext context,
    json_t *j,
    const char *key,
    X509_NAME *name,
    int cnOnly)
{
    char *szValue = NULL;
    BIDError err;

    if (cnOnly) {
        int i;
        X509_NAME_ENTRY *cn;
        ASN1_STRING *cnValue;

        i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (i < 0)
            return BID_S_MISSING_PRINCIPAL;

        cn = X509_NAME_get_entry(name, i);
        if (cn == NULL)
            return BID_S_MISSING_PRINCIPAL;

        cnValue = X509_NAME_ENTRY_get_data(cn);
        ASN1_STRING_to_UTF8((unsigned char **)&szValue, cnValue);
    } else {
        /* XXX this is a deprecated API */
        szValue = X509_NAME_oneline(name, NULL, -1);
        if (szValue == NULL)
            return BID_S_NO_MEMORY;
    }

    err = _BIDJsonObjectSet(context, j, key, json_string(szValue),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);

    OPENSSL_free(szValue);

    return err;
}

BIDError
_BIDPopulateX509Identity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity identity,
    uint32_t ulReqFlags)
{
    BIDError err;
    json_t *certChain = json_object_get(backedAssertion->Assertion->Header, "x5c");
    json_t *principal = json_object();
    X509 *x509 = NULL;
    STACK_OF(GENERAL_NAME) *gens;
    int i;

    err = _BIDCertDataToX509(context, certChain, 0, &x509);
    BID_BAIL_ON_ERROR(err);

    gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (gens != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
            GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
            const char *key = NULL;

            switch (gen->type) {
            case GEN_EMAIL:
                key = "email";
                break;
            case GEN_DNS:
                key = "hostname";
                break;
            case GEN_URI:
                key = "uri";
                break;
            default:
                break;
            }

            if (key != NULL) {
                err = _BIDJsonObjectSet(context, principal, key,
                                        json_string((char *)gen->d.ia5->data),
                                        BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
                BID_BAIL_ON_ERROR(err);
            }
        }
    }

    err = _BIDJsonObjectSet(context, identity->Attributes, "principal", principal, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonX509Name(context, identity->Attributes, "sub", X509_get_subject_name(x509),
                              !!(ulReqFlags & BID_VERIFY_FLAG_RP));
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonX509Name(context, identity->Attributes, "iss", X509_get_issuer_name(x509), 0);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(principal);

    return err;
}

BIDError
_BIDValidateX509CertChain(
    BIDContext context,
    const char *caCertificateFile,
    const char *caCertificateDir,
    json_t *certChain)
{
    BIDError err;
    X509_STORE *store = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    X509 *leafCert = NULL;
    STACK_OF(X509) *chain = NULL;
    size_t i;

    if (json_array_size(certChain) == 0) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    err = _BIDCertDataToX509(context, certChain, 0, &leafCert);
    BID_BAIL_ON_ERROR(err);

    chain = sk_X509_new_null();
    if (chain == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 1; i < json_array_size(certChain); i++) {
        X509 *cert;

        err = _BIDCertDataToX509(context, certChain, i, &cert);
        BID_BAIL_ON_ERROR(err);

        sk_X509_push(chain, cert);
    }

    store = X509_STORE_new();
    storeCtx = X509_STORE_CTX_new();
    if (store == NULL || storeCtx == NULL) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    if (X509_STORE_load_locations(store, caCertificateFile, caCertificateDir) != 1 ||
        X509_STORE_set_default_paths(store) != 1 ||
        X509_STORE_CTX_init(storeCtx, store, leafCert, chain) != 1) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

#if 0
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif

    if (!X509_verify_cert(storeCtx)) {
        BID_CRYPTO_PRINT_ERRORS();
        err = BID_S_UNTRUSTED_X509_CERT;
        goto cleanup;
    }

cleanup:
    if (chain != NULL)
        sk_X509_free(chain);
    if (storeCtx != NULL)
        X509_STORE_CTX_free(storeCtx);
    if (store != NULL)
        X509_STORE_free(store);

    return err;
}

