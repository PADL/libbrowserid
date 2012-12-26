/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BID_CRYPTO_DEBUG    1

#if BID_CRYPTO_DEBUG
#define BID_CRYPTO_PRINT_ERRORS() do { ERR_print_errors_fp(stderr); } while (0)
#else
#define BID_CRYPTO_PRINT_ERRORS()
#endif

static BIDError
_BIDGetJsonBNValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    BIGNUM **bn)
{
    BIDError err;
    const char *value;

    *bn = NULL;

    value = json_string_value(json_object_get(jwk, key));
    if (value == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    err = BID_S_INVALID_KEY;

    if (!_BIDIsLegacyJWK(context, jwk)) {
        unsigned char buf[512];
        unsigned char *pBuf = buf;
        size_t len = sizeof(buf);
        BIDError err2;

        err2 = _BIDBase64UrlDecode(value, &pBuf, &len);
        if (err2 == BID_S_OK) {
            *bn = BN_bin2bn(buf, len, NULL);
            if (*bn != NULL)
                err = BID_S_OK;
            memset(buf, 0, sizeof(buf));
        }
    } else if (err != BID_S_OK && BN_dec2bn(bn, value)) {
        err = BID_S_OK;
    } else if (err != BID_S_OK && BN_hex2bn(bn, value)) {
        err = BID_S_OK;
    }

    return err;
}

static BIDError
_BIDMakeShaDigest(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    unsigned char *digest,
    size_t *digestLength)
{
    const EVP_MD *md;
    EVP_MD_CTX mdCtx;
    unsigned char shaMd[EVP_MAX_MD_SIZE] = { 0 };
    unsigned int mdLength = sizeof(md);

    /* Not particularly crypto-agile, but it is a start. */
    if (strcmp(algorithm->szAlgID, "RS512") == 0) {
        md = EVP_sha512();
    } else if (strcmp(algorithm->szAlgID, "RS384") == 0) {
        md = EVP_sha384();
    } else if (strcmp(algorithm->szAlgID, "RS224") == 0) {
        md = EVP_sha224();
    } else if (strcmp(algorithm->szAlgID, "DS128") == 0) {
        md = EVP_sha1();
    } else {
        md = EVP_sha256();
    }

    if (md == NULL)
        return BID_S_CRYPTO_ERROR;

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

    err = _BIDGetJsonBNValue(context, jwk, "n", &rsa->n);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "e", &rsa->e);
    BID_BAIL_ON_ERROR(err);

    if (!public) {
        err = _BIDGetJsonBNValue(context, jwk, "d", &rsa->d);
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

    err = _BIDGetJsonBNValue(context, jwk, "p", &dsa->p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "q", &dsa->q);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBNValue(context, jwk, "g", &dsa->g);
    BID_BAIL_ON_ERROR(err);

    if (public)
        err = _BIDGetJsonBNValue(context, jwk, "y", &dsa->pub_key);
    else
        err = _BIDGetJsonBNValue(context, jwk, "x", &dsa->priv_key);
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

    err = _BIDGetJsonBNValue(context, jwk, "p", &p);
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
