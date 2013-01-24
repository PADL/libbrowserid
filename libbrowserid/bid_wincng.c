/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#include <bcrypt.h>
#include <ncrypt.h>

/*
 * Windows Cryptography Next Generation (CNG) provider for BrowserID.
 */

/*
 * TODO bignums
 * TODO export key without derivation
 * TODO X.509 support
 */

static BIDError
_BIDNtStatusToBIDError(NTSTATUS nts)
{
    if (NT_SUCCESS(nts))
        return BID_S_OK;
    else if (nts == STATUS_NO_MEMORY)
        return BID_S_NO_MEMORY;
    else
        return BID_S_CRYPTO_ERROR;
}

static void
_BIDFreeBuffer(BCryptBuffer *blob)
{
    if (blob->pvBuffer != NULL) {
        SecureZeroMemory(blob->pvBuffer, blob->cbBuffer);
        BIDFree(blob->pvBuffer);
        blob->pvBuffer = NULL;
    }

    blob->cbBuffer = 0;
}

static BIDError
_BIDParseHexNumber(
    BIDContext context,
    const char *szValue,
    size_t cchValue,
    BCryptBuffer *blob)
{
    size_t i;

    if (cchValue % 2)
        return BID_S_INVALID_JSON;

    blob->pvBuffer = BIDMalloc(cchValue / 2);
    if (blob->pvBuffer == NULL)
        return BID_S_NO_MEMORY;

    for (i = 0; i < cchValue / 2; i++) {
        int b;

        if (sscanf(&szValue[i * 2], "%02x", &b) != 1) {
            BIDFree(blob->pvBuffer);
            blob->pvBuffer = NULL;
            return BID_S_INVALID_JSON;
        }
        ((PUCHAR)blob->pvBuffer)[i] = b & 0xff;
    }
    blob->cbBuffer = cchValue / 2;
    return BID_S_OK;
}


static BIDError
_BIDParseBigNumber(
    BIDContext context,
    const char *szValue,
    size_t cchValue,
    BCryptBuffer *blob)
{
    return BID_S_NOT_IMPLEMENTED;
}

static BIDError
_BIDGetJsonBufferValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    uint32_t encoding,
    BCryptBuffer *blob)
{
    BIDError err;
    json_t *value;
    const char *szValue;

    blob->cbBuffer = 0;
    blob->pvBuffer = NULL;

    if (key != NULL)
        value = json_object_get(jwk, key);
    else
        value = jwk;
    if (value == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    szValue = json_string_value(value);
    if (szValue == NULL)
        return BID_S_INVALID_KEY;

    err = BID_S_INVALID_KEY;

    if ((encoding == BID_ENCODING_BASE64_URL) ||
        !_BIDIsLegacyJWK(context, jwk)) {
        size_t len = 0;

        err = _BIDBase64UrlDecode(szValue, (PUCHAR *)&blob->pvBuffer, &len);
        blob->cbBuffer = len;
    } else {
        size_t len = strlen(szValue), i;
        size_t cchDecimal = 0;

        /* XXX this is bogus, a hex string could also be a valid decimal string. */
        for (i = 0; i < len; i++) {
            if (isdigit(szValue[i]))
                cchDecimal++;
        }

        if (cchDecimal == len || (len % 2))
            err = _BIDParseBigNumber(context, szValue, len, blob);
        else
            err = _BIDParseHexNumber(context, szValue, len, blob);
    }

    return err;
}

static BIDError
_BIDMapHashAlgorithmID(
    struct BIDJWTAlgorithmDesc *algorithm,
    LPCWSTR *pAlgID)
{
    LPCWSTR algID = NULL;

    *pAlgID = NULL;

    if (strlen(algorithm->szAlgID) != 5)
        return BID_S_CRYPTO_ERROR;

    if (strcmp(algorithm->szAlgID, "DS128") == 0) {
        algID = BCRYPT_SHA1_ALGORITHM;
    } else if (strcmp(&algorithm->szAlgID[1], "S512") == 0) {
        algID = BCRYPT_SHA512_ALGORITHM;
    } else if (strcmp(&algorithm->szAlgID[1], "S384") == 0) {
        algID = BCRYPT_SHA384_ALGORITHM;
    } else if (strcmp(&algorithm->szAlgID[1], "S256") == 0) {
        algID = BCRYPT_SHA256_ALGORITHM;
    } else {
        return BID_S_UNKNOWN_ALGORITHM;
    }

    *pAlgID = algID;
    return BID_S_OK;
}

static BIDError
_BIDMapCryptAlgorithmID(
    struct BIDJWTAlgorithmDesc *algorithm,
    LPCWSTR *pAlgID)
{
    LPCWSTR algID = NULL;

    *pAlgID = NULL;

    if (strncmp(algorithm->szAlgID, "DS", 2) == 0)
        algID = BCRYPT_DSA_ALGORITHM;
    else if (strncmp(algorithm->szAlgID, "RS", 2) == 0)
        algID = BCRYPT_RSA_ALGORITHM;
    else
        return BID_S_UNKNOWN_ALGORITHM;

    *pAlgID = algID;
    return BID_S_OK;
}

static BIDError
_BIDMakeShaDigest(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context BID_UNUSED,
    BIDJWT jwt,
    BIDJWK jwk,
    unsigned char *digest,
    size_t *digestLength)
{
    BIDError err;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS nts;
    LPCWSTR wszAlgID;
    PUCHAR pbHashObject = NULL;
    DWORD cbHashObject, cbHash, cbData;
    PBYTE pbKey = NULL;
    size_t cbKey = 0;

    if (jwk != NULL) {
        err = _BIDGetJsonBinaryValue(context, jwk, "secret-key",
                                     &pbKey, &cbKey);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDMapHashAlgorithmID(algorithm, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlg,
                                      wszAlgID,
                                      NULL,
                                      jwk ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptGetProperty(hAlg,
                            BCRYPT_OBJECT_LENGTH,
                            (PUCHAR)&cbHashObject,
                            sizeof(DWORD),
                            &cbData,
                            0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    pbHashObject = BIDMalloc(cbHashObject);
    if (pbHashObject == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptGetProperty(hAlg,
                            BCRYPT_HASH_LENGTH,
                            (PUCHAR)&cbHash,
                            sizeof(DWORD),
                            &cbData,
                            0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    if (*digestLength < cbHash) {
        err = BID_S_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    nts = BCryptCreateHash(hAlg,
                           &hHash,
                           pbHashObject,
                           cbHashObject,
                           pbKey,
                           cbKey,
                           0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptHashData(hHash,
                         (PUCHAR)jwt->EncData,
                         jwt->EncDataLength,
                         0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptFinishHash(hHash,
                           digest,
                           *digestLength,
                           0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = BID_S_OK;

cleanup:
    if (hAlg != NULL)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash != NULL)
        BCryptDestroyHash(hHash);
    if (pbKey != NULL) {
        SecureZeroMemory(pbKey, cbKey);
        BIDFree(pbKey);
    }
    BIDFree(pbHashObject);

    return err;
}

static BIDError
_BIDCertDataToKey(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context BID_UNUSED,
    BCRYPT_ALG_HANDLE hAlgorithm,
    json_t *x5c,
    int index,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    NTSTATUS nts;
    const char *szCert;
    unsigned char *pbData = NULL;
    size_t cbData = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    CERT_PUBLIC_KEY_INFO *pcpki;
    LPCSTR szCertID;
    LPCWSTR wszBlobID;

    *phKey = NULL;

    if (x5c == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    if (strncmp(algorithm->szAlgID, "RS", 2) == 0) {
        wszBlobID = LEGACY_RSAPUBLIC_BLOB;
        szCertID = szOID_RSA;
    } else if (strcmp(algorithm->szAlgID, "DS128") == 0) {
        wszBlobID = LEGACY_DSA_PUBLIC_BLOB;
        szCertID = szOID_X957_SHA1DSA;
    } else if (strncmp(algorithm->szAlgID, "DS", 2) == 0) {
        wszBlobID = LEGACY_DSA_PUBLIC_BLOB;
        szCertID = szOID_X957_DSA;
    } else {
        err = BID_S_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    szCert = json_string_value(json_array_get(x5c, index));
    if (szCert == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    err = _BIDBase64UrlDecode(szCert, &pbData, &cbData);
    BID_BAIL_ON_ERROR(err);

    pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING |
                                                 PKCS_7_ASN_ENCODING,
                                                pbData,
                                                cbData);
    if (pCertContext == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    pcpki = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

    if (pcpki->Algorithm.pszObjId == NULL) {
        err = BID_S_MISSING_ALGORITHM;
        goto cleanup;
    }

    if (strcmp(pcpki->Algorithm.pszObjId, szCertID) == 0) {
        err = BID_S_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              wszBlobID,
                              phKey,
                              pcpki->PublicKey.pbData,
                              pcpki->PublicKey.cbData,
                              0);   /* dwFlags */
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (pCertContext != NULL)
        CertFreeCertificateContext(pCertContext);

    BIDFree(pbData);

    return err;
}

static BIDError
_BIDMakeJwtRsaKey(
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    BIDJWK jwk,
    int public,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    NTSTATUS nts;
    BCryptBuffer n = { 0 };
    BCryptBuffer e = { 0 };
    BCryptBuffer d = { 0 };
    BCRYPT_RSAKEY_BLOB *rsaKey = NULL;
    DWORD cbRsaKey = 0;
    PUCHAR p;

    *phKey = NULL;

    if (public) {
        err = _BIDGetJsonBufferValue(context, jwk, "e", BID_ENCODING_UNKNOWN, &e);
        BID_BAIL_ON_ERROR(err);
    } else {
        err = _BIDGetJsonBufferValue(context, jwk, "d", BID_ENCODING_UNKNOWN, &d);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDGetJsonBufferValue(context, jwk, "n", BID_ENCODING_UNKNOWN, &n);
    BID_BAIL_ON_ERROR(err);

    cbRsaKey = sizeof(*rsaKey);
    cbRsaKey += public ? e.cbBuffer : d.cbBuffer;
    cbRsaKey += n.cbBuffer;

    rsaKey = BIDMalloc(cbRsaKey);
    if (rsaKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(rsaKey, cbRsaKey);

    rsaKey->Magic       = public
                        ? BCRYPT_RSAPUBLIC_MAGIC : BCRYPT_RSAPRIVATE_MAGIC;
    rsaKey->BitLength   = n.cbBuffer * 8;
    rsaKey->cbPublicExp = public ? e.cbBuffer : d.cbBuffer;
    rsaKey->cbModulus   = n.cbBuffer;
    rsaKey->cbPrime1    = 0;
    rsaKey->cbPrime2    = 0;

    p = (PUCHAR)(rsaKey + 1);

    if (public) {
        CopyMemory(p, e.pvBuffer, e.cbBuffer);
        p += e.cbBuffer;
    } else {
        CopyMemory(p, d.pvBuffer, d.cbBuffer);
        p += d.cbBuffer;
    }
    CopyMemory(p, n.pvBuffer, n.cbBuffer);
    p += n.cbBuffer;

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              public ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAPRIVATE_BLOB,
                              phKey,
                              (PUCHAR)rsaKey,
                              cbRsaKey,
                              0);   /* dwFlags */
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (rsaKey != NULL) {
        SecureZeroMemory(rsaKey, cbRsaKey);
        BIDFree(rsaKey);
    }
    _BIDFreeBuffer(&n);
    _BIDFreeBuffer(&e);
    _BIDFreeBuffer(&d);

    return err;
}

static BIDError
_BIDMakeJwtDsaKey(
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    BIDJWK jwk,
    int public,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    NTSTATUS nts;
    BCryptBuffer p = { 0 };
    BCryptBuffer q = { 0 };
    BCryptBuffer g = { 0 };
    BCryptBuffer x = { 0 };
    BCryptBuffer y = { 0 };
    BCRYPT_DSA_KEY_BLOB *dsaKey = NULL;
    DWORD cbDsaKey = 0;
    PUCHAR pbDsaKeyData;

    *phKey = NULL;

    /* modulus */
    err = _BIDGetJsonBufferValue(context, jwk, "p", BID_ENCODING_UNKNOWN, &p);
    BID_BAIL_ON_ERROR(err);

    /* inline */
    err = _BIDGetJsonBufferValue(context, jwk, "q", BID_ENCODING_UNKNOWN, &q);
    BID_BAIL_ON_ERROR(err);

    /* generator */
    err = _BIDGetJsonBufferValue(context, jwk, "g", BID_ENCODING_UNKNOWN, &g);
    BID_BAIL_ON_ERROR(err);

    /* public key */
    err = _BIDGetJsonBufferValue(context, jwk, "y", BID_ENCODING_UNKNOWN, &y);
    BID_BAIL_ON_ERROR(err);

    if (!public) {
        /* private exponent */
        err = _BIDGetJsonBufferValue(context, jwk, "x", BID_ENCODING_UNKNOWN, &x);
        BID_BAIL_ON_ERROR(err);
    }

    if (q.cbBuffer > 20) {
        err = BID_S_BUFFER_TOO_LONG;
        goto cleanup;
    }

    /* XXX we may need to zero pad these */
    if (p.cbBuffer != g.cbBuffer || p.cbBuffer != y.cbBuffer ||
        (!public && x.cbBuffer != 20)) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    cbDsaKey = sizeof(*dsaKey);
    cbDsaKey += q.cbBuffer + p.cbBuffer + g.cbBuffer + y.cbBuffer;
    if (!public)
        cbDsaKey += x.cbBuffer;

    dsaKey = BIDMalloc(cbDsaKey);
    if (dsaKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(dsaKey, cbDsaKey);

    dsaKey->dwMagic     = public
                        ? BCRYPT_DSA_PUBLIC_MAGIC : BCRYPT_DSA_PRIVATE_MAGIC;
    dsaKey->cbKey       = y.cbBuffer;

    CopyMemory(dsaKey->q, q.pvBuffer, q.cbBuffer);
    pbDsaKeyData = (PUCHAR)(dsaKey + 1);

    CopyMemory(pbDsaKeyData, p.pvBuffer, p.cbBuffer);
    pbDsaKeyData += p.cbBuffer;

    CopyMemory(pbDsaKeyData, g.pvBuffer, g.cbBuffer);
    pbDsaKeyData += g.cbBuffer;

    CopyMemory(pbDsaKeyData, y.pvBuffer, y.cbBuffer);
    pbDsaKeyData += y.cbBuffer;
   
    if (!public) {
        CopyMemory(pbDsaKeyData, x.pvBuffer, x.cbBuffer);
        pbDsaKeyData += x.cbBuffer;
    } 

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              public ? BCRYPT_DSA_PUBLIC_BLOB : BCRYPT_DSA_PRIVATE_BLOB,
                              phKey,
                              (PUCHAR)dsaKey,
                              cbDsaKey,
                              0);   /* dwFlags */
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (dsaKey != NULL) {
        SecureZeroMemory(dsaKey, cbDsaKey);
        BIDFree(dsaKey);
    }
    _BIDFreeBuffer(&p);
    _BIDFreeBuffer(&q);
    _BIDFreeBuffer(&g);
    _BIDFreeBuffer(&x);
    _BIDFreeBuffer(&y);

    return err;
}

static BIDError
_CNGMakeKey(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    BIDJWK jwk,
    int public,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    json_t *x5c;

    *phKey = NULL;

    x5c = json_object_get(jwk, "x5c");
    if (public && x5c != NULL)
        err = _BIDCertDataToKey(algorithm, context, hAlgorithm, x5c, 0, phKey);
    else if (strncmp(algorithm->szAlgID, "RS", 2) == 0)
        err = _BIDMakeJwtRsaKey(context, hAlgorithm, jwk, public, phKey);
    else if (strncmp(algorithm->szAlgID, "DS", 2) == 0)
        err = _BIDMakeJwtDsaKey(context, hAlgorithm, jwk, public, phKey);
    else
        err = BID_S_UNKNOWN_ALGORITHM;

    return err;
}

static BIDError
_CNGKeySize(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWK jwk,
    size_t *pcbKey)
{
    BIDError err;
    NTSTATUS nts;
    LPCWSTR wszAlgID;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    DWORD cbKey = 0, cbResult;

    *pcbKey = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, 0, &hRsaKey);
    BID_BAIL_ON_ERROR(err);

    err = BCryptGetProperty(hRsaKey, BCRYPT_KEY_STRENGTH, (PUCHAR)&cbKey,
                            sizeof(cbKey), &cbResult, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    cbKey /= 8; /* bytes */

    /*
     * FIPS 186-3[3] specifies L and N length pairs of
     * (1024,160), (2048,224), (2048,256), and (3072,256).
     */
    if (strncmp(algorithm->szAlgID, "DS", 2) == 0) {
        if (cbKey < 160)
            cbKey = 160;
        else if (cbKey < 224)
            cbKey = 224;
        else if (cbKey < 256)
            cbKey = 256;
    }

    *pcbKey = cbKey;

cleanup:
    if (hRsaKey != NULL)
        BCryptDestroyKey(hRsaKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

     return err;
}

static BIDError
_CNGMakeSignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk)
{
    BIDError err;
    NTSTATUS nts;
    LPCWSTR wszAlgID;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    DWORD cbOutput = 0;
    UCHAR pbDigest[64]; /* longest known hash is SHA-512 */
    size_t cbDigest = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, 0, &hRsaKey);
    BID_BAIL_ON_ERROR(err);

    cbDigest = sizeof(pbDigest);

    err = _BIDMakeShaDigest(algorithm, context, jwt, NULL, pbDigest, &cbDigest);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMapHashAlgorithmID(algorithm, &paddingInfo.pszAlgId);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptSignHash(hRsaKey,
                         &paddingInfo,
                         pbDigest,
                         cbDigest,
                         NULL,
                         0,
                         &cbOutput,
                         BCRYPT_PAD_PKCS1);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    jwt->Signature = BIDMalloc(cbOutput);
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    jwt->SignatureLength = cbOutput;

    nts = BCryptSignHash(hRsaKey,
                        &paddingInfo,
                        pbDigest,
                        cbDigest,
                        jwt->Signature,
                        jwt->SignatureLength,
                        &cbOutput,
                        BCRYPT_PAD_PKCS1);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    jwt->SignatureLength = cbOutput;

    err = BID_S_OK;

cleanup:
    if (hRsaKey != NULL)
        BCryptDestroyKey(hRsaKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    BIDFree(pbDigest);
 
    return err;
}

static BIDError
_CNGVerifySignature(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BIDJWT jwt,
    BIDJWK jwk,
    int *valid)
{
    BIDError err;
    NTSTATUS nts;
    LPCWSTR wszAlgID;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hRsaKey = NULL;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    UCHAR pbDigest[64]; /* longest known hash is SHA-512 */
    size_t cbDigest = 0;

    *valid = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, 0, &hRsaKey);
    BID_BAIL_ON_ERROR(err);

    cbDigest = sizeof(pbDigest);

    err = _BIDMakeShaDigest(algorithm, context, jwt, NULL, pbDigest, &cbDigest);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMapHashAlgorithmID(algorithm, &paddingInfo.pszAlgId);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptVerifySignature(hRsaKey,
                                &paddingInfo,
                                pbDigest,
                                cbDigest,
                                jwt->Signature,
                                jwt->SignatureLength,
                                BCRYPT_PAD_PKCS1);
    if (nts == STATUS_SUCCESS)
        *valid = 1;
    else if (nts == STATUS_INVALID_SIGNATURE)
        nts = STATUS_SUCCESS;
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (hRsaKey != NULL)
        BCryptDestroyKey(hRsaKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    BIDFree(pbDigest);
 
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
    UCHAR pbDigest[64];
    size_t cbDigest = sizeof(pbDigest);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMakeShaDigest(algorithm, context, jwt, jwk, pbDigest, &cbDigest);
    BID_BAIL_ON_ERROR(err);

    jwt->Signature = BIDMalloc(cbDigest);
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    CopyMemory(jwt->Signature, pbDigest, cbDigest);
    jwt->SignatureLength = cbDigest;

cleanup:
    SecureZeroMemory(pbDigest, sizeof(pbDigest));

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
    UCHAR pbDigest[64];
    size_t cbDigest = sizeof(pbDigest);

    BID_ASSERT(jwt->EncData != NULL);

    err = _BIDMakeShaDigest(algorithm, context, jwt, jwk, pbDigest, &cbDigest);
    if (err != BID_S_OK)
        return err;

    *valid = (jwt->SignatureLength == cbDigest) &&
             (memcmp(jwt->Signature, pbDigest, cbDigest) == 0);

    return BID_S_OK;
}

struct BIDJWTAlgorithmDesc
_BIDJWTAlgorithms[] = {
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
#if 0
    {
        "RS512",
        "RSA",
        0,
        (const unsigned char *)"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x40",
        19,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        "RS384",
        "RSA",
        0,
        (const unsigned char *)"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x30",
        19,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
#endif
    {
        "RS256",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        "RS128",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        "RS64",
        "RSA",
        0,
        (const unsigned char *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        19,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        "DS256",
        "DSA",
        256,
        NULL,
        0,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        "DS128",
        "DSA",
        160,
        NULL,
        0,
        _CNGMakeSignature,
        _CNGVerifySignature,
        _CNGKeySize,
    },
    {
        NULL
    },
};

BIDError
_BIDDigestAssertion(
    BIDContext context,
    const char *szAssertion,
    unsigned char *digest,
    size_t *digestLength)
{
    BIDError err;
    struct BIDJWTDesc jwt = { 0 };

    jwt.EncData = (PCHAR)szAssertion;
    jwt.EncDataLength = strlen(szAssertion);

    err = _BIDMakeShaDigest(&_BIDJWTAlgorithms[0], context, &jwt, NULL,
                            digest, digestLength);

    return err;
}

static BIDError
_BIDMakeDHKey(
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    json_t *dhParams,
    json_t *dhKey,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    NTSTATUS nts;
    BCryptBuffer p = { 0 };
    BCryptBuffer g = { 0 };
    BCryptBuffer x = { 0 };
    BCryptBuffer y = { 0 };
    BCRYPT_DH_KEY_BLOB *dhKeyBlob = NULL;
    DWORD cbDhKeyBlob = 0;
    PUCHAR pbDhKeyBlob;
    BOOLEAN bIsPrivateKey = FALSE;

    *phKey = NULL;

    if (dhParams == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDGetJsonBufferValue(context, dhParams, "p", BID_ENCODING_UNKNOWN, &p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhParams, "g", BID_ENCODING_UNKNOWN, &g);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhKey, "y", BID_ENCODING_UNKNOWN, &y);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhKey, "x", BID_ENCODING_UNKNOWN, &x);
    if (err == BID_S_OK)
        bIsPrivateKey = TRUE;
    else if (err == BID_S_UNKNOWN_JSON_KEY || err == BID_S_INVALID_KEY)
        bIsPrivateKey = FALSE;
    else
        goto cleanup;

    if (p.cbBuffer != g.cbBuffer) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    if ((x.cbBuffer && x.cbBuffer != p.cbBuffer) ||
        (y.cbBuffer && y.cbBuffer != p.cbBuffer)) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    cbDhKeyBlob = sizeof(*dhKey);
    cbDhKeyBlob += p.cbBuffer + g.cbBuffer + y.cbBuffer + x.cbBuffer;

    dhKeyBlob = BIDMalloc(cbDhKeyBlob);
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(dhKeyBlob, cbDhKeyBlob);

    dhKeyBlob->dwMagic = bIsPrivateKey
                       ? BCRYPT_DH_PRIVATE_MAGIC : BCRYPT_DH_PUBLIC_MAGIC;
    dhKeyBlob->cbKey   = p.cbBuffer;

    pbDhKeyBlob = (PUCHAR)(dhKeyBlob + 1);

    CopyMemory(pbDhKeyBlob, p.pvBuffer, p.cbBuffer);
    pbDhKeyBlob += p.cbBuffer;

    CopyMemory(pbDhKeyBlob, g.pvBuffer, g.cbBuffer);
    pbDhKeyBlob += g.cbBuffer;

    CopyMemory(pbDhKeyBlob, y.pvBuffer, y.cbBuffer);
    pbDhKeyBlob += y.cbBuffer;
   
    if (bIsPrivateKey) {
        CopyMemory(pbDhKeyBlob, x.pvBuffer, x.cbBuffer);
        pbDhKeyBlob += x.cbBuffer;
    } 

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              bIsPrivateKey ? BCRYPT_DH_PRIVATE_BLOB : BCRYPT_DH_PUBLIC_BLOB,
                              phKey,
                              (PUCHAR)dhKeyBlob,
                              cbDhKeyBlob,
                              0);   /* dwFlags */
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (dhKey != NULL) {
        SecureZeroMemory(dhKeyBlob, cbDhKeyBlob);
        BIDFree(dhKeyBlob);
    }
    _BIDFreeBuffer(&p);
    _BIDFreeBuffer(&g);
    _BIDFreeBuffer(&x);
    _BIDFreeBuffer(&y);

    return err;
}

BIDError
_BIDGenerateDHParams(
    BIDContext context,
    json_t **pDhParams)
{
    BIDError err;
    NTSTATUS nts;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hTmpKey = NULL;
    BCRYPT_DH_PARAMETER_HEADER *dhParamsHeader = NULL;
    DWORD cbDhParamsHeader = 0;
    json_t *dhParams = NULL;
    json_t *p = NULL;
    json_t *g = NULL;

    *pDhParams = NULL;

    dhParams = json_object();
    if (dhParams == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    BID_ASSERT(context->DhKeySize != 0);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm,
                                      BCRYPT_DH_ALGORITHM,
                                      NULL,
                                      0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    /* XXX is there a way to generate the parameters without a keypair? */
    nts = BCryptGenerateKeyPair(hAlgorithm, &hTmpKey, context->DhKeySize, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptFinalizeKeyPair(hTmpKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptGetProperty(hTmpKey, BCRYPT_DH_PARAMETERS,
                            NULL, 0, &cbDhParamsHeader, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    dhParamsHeader = BIDMalloc(cbDhParamsHeader);
    if (dhParamsHeader == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptGetProperty(hTmpKey, BCRYPT_DH_PARAMETERS,
                            (PUCHAR)dhParamsHeader, cbDhParamsHeader,
                            &cbDhParamsHeader, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _BIDJsonObjectSetBinaryValue(context,
                                       dhParams,
                                       "p",
                                       (PUCHAR)(dhParamsHeader + 1),
                                       dhParamsHeader->cbKeyLength);
    BID_BAIL_ON_ERROR(err);
                     
    err = _BIDJsonObjectSetBinaryValue(context,
                                       dhParams,
                                       "g",
                                       (PUCHAR)(dhParamsHeader + 1) + dhParamsHeader->cbKeyLength,
                                       dhParamsHeader->cbKeyLength);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pDhParams = dhParams;

cleanup:
    if (err != BID_S_OK)
        json_decref(dhParams);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hTmpKey != NULL)
        BCryptDestroyKey(hTmpKey);
    BIDFree(dhParamsHeader);
    json_decref(p);
    json_decref(g);

    return err;
}

static BIDError
_BIDMakeDHParams(
    BIDContext context,
    json_t *dhParams,
    BCRYPT_DH_PARAMETER_HEADER **ppDhParamsHeader)
{
    BIDError err;
    BCRYPT_DH_PARAMETER_HEADER *pDhParamsHeader = NULL;
    DWORD cbDhParamsHeader = 0;
    PUCHAR pbDhParamsHeader;
    BCryptBuffer p = { 0 };
    BCryptBuffer g = { 0 };

    *ppDhParamsHeader = NULL;

    err = _BIDGetJsonBufferValue(context, dhParams, "p", BID_ENCODING_UNKNOWN, &p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhParams, "g", BID_ENCODING_UNKNOWN, &g);
    BID_BAIL_ON_ERROR(err);

    if (p.cbBuffer != g.cbBuffer) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    cbDhParamsHeader = sizeof(*pDhParamsHeader) + p.cbBuffer + g.cbBuffer;
    pDhParamsHeader = BIDMalloc(cbDhParamsHeader);
    if (pDhParamsHeader == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(pDhParamsHeader, cbDhParamsHeader);

    pDhParamsHeader->cbLength    = cbDhParamsHeader;
    pDhParamsHeader->dwMagic     = BCRYPT_DH_PARAMETERS_MAGIC;
    pDhParamsHeader->cbKeyLength = p.cbBuffer;

    pbDhParamsHeader = (PUCHAR)(pDhParamsHeader + 1);
    
    CopyMemory(pbDhParamsHeader, p.pvBuffer, p.cbBuffer);
    pbDhParamsHeader += p.cbBuffer;

    CopyMemory(pbDhParamsHeader, g.pvBuffer, g.cbBuffer);
    pbDhParamsHeader += g.cbBuffer;

    BID_ASSERT(pbDhParamsHeader == (PUCHAR)pDhParamsHeader + cbDhParamsHeader);

    err = BID_S_OK;

    *ppDhParamsHeader  = pDhParamsHeader;

cleanup:
    if (err != BID_S_OK)
        BIDFree(pDhParamsHeader);
    _BIDFreeBuffer(&p);
    _BIDFreeBuffer(&g);

    return err;
}

BIDError
_BIDGenerateDHKey(
    BIDContext context,
    json_t *dhParams,
    BIDJWK *pDhKey)
{
    BIDError err;
    NTSTATUS nts;
    json_t *dhKey = NULL;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_DH_PARAMETER_HEADER *dhParamsHeader = NULL;
    BCRYPT_DH_KEY_BLOB *dhKeyBlob = NULL;
    DWORD cbDhKeyBlob = 0;
    PUCHAR pbDhKeyBlob;

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm,
                                      BCRYPT_DH_ALGORITHM,
                                      NULL,
                                      0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptGenerateKeyPair(hAlgorithm, &hKey, context->DhKeySize, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _BIDMakeDHParams(context, dhParams, &dhParamsHeader);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptSetProperty(hKey, BCRYPT_DH_PARAMETERS,
                            (PUCHAR)dhParamsHeader, dhParamsHeader->cbLength, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptFinalizeKeyPair(hKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptExportKey(hKey, NULL, BCRYPT_DH_PRIVATE_BLOB,
                          NULL, 0, &cbDhKeyBlob, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    dhKeyBlob = BIDMalloc(cbDhKeyBlob);
    if (dhKeyBlob == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptExportKey(hKey, NULL, BCRYPT_DH_PRIVATE_BLOB,
                          (PUCHAR)dhKeyBlob, cbDhKeyBlob, &cbDhKeyBlob, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    if (cbDhKeyBlob < sizeof(*dhKeyBlob) + 4 * dhKeyBlob->cbKey) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    dhKey = json_object();
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, dhKey, "params", dhParams,
                            BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    pbDhKeyBlob = (PUCHAR)(dhKeyBlob + 1);

    /* Layout is DH_KEY_BLOB || p || g || y || x */
    /*                          0    1    2    3 */
    err = _BIDJsonObjectSetBinaryValue(context,
                                       dhParams,
                                       "y",
                                       &pbDhKeyBlob[2 * dhKeyBlob->cbKey],
                                       dhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context,
                                       dhParams,
                                       "x",
                                       &pbDhKeyBlob[3 * dhKeyBlob->cbKey],
                                       dhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pDhKey = dhKey;

cleanup:
    if (err != BID_S_OK)
        json_decref(dhKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey != NULL)
        BCryptDestroyKey(hKey);
    if (dhKeyBlob != NULL) {
        SecureZeroMemory(dhKeyBlob, cbDhKeyBlob);
        BIDFree(dhKeyBlob);
    }
    BIDFree(dhParamsHeader);

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
    NTSTATUS nts;
    json_t *dhParams;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    PUCHAR pbKey = NULL;
    DWORD cbKey = 0;
    BCryptBuffer pub = { 0 };
    BCryptBuffer paramBuffers[1];
    BCryptBufferDesc params;

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

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm,
                                      BCRYPT_DH_ALGORITHM,
                                      NULL,
                                      0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _BIDMakeDHKey(context, hAlgorithm, dhParams, dhKey, &hPrivateKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeDHKey(context, hAlgorithm, dhParams, pubValue, &hPublicKey);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    /*
     * XXX there's no defined interface to get the DH secret directly.
     * for now, we will just SHA256 it but this will not be interoperable
     * with the OpenSSL implementation and/or the spec.
     */
    paramBuffers[0].cbBuffer   = wcslen(BCRYPT_SHA256_ALGORITHM) * sizeof(WCHAR);
    paramBuffers[0].BufferType = KDF_HASH_ALGORITHM;
    paramBuffers[0].pvBuffer   = BCRYPT_SHA256_ALGORITHM;

    params.ulVersion = BCRYPTBUFFER_VERSION;
    params.cBuffers  = ARRAYSIZE(paramBuffers);
    params.pBuffers  = paramBuffers;

    nts = BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &params,
                          NULL, 0, &cbKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    pbKey = BIDMalloc(cbKey);
    if (pbKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &params,
                          pbKey, cbKey, &cbKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = BID_S_OK;
    *ppbKey = pbKey;
    *pcbKey = cbKey;

cleanup:
    if (err != BID_S_OK) {
        SecureZeroMemory(pbKey, cbKey);
        BIDFree(pbKey);
    }
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hPrivateKey != NULL)
        BCryptDestroyKey(hPrivateKey);
    if (hPublicKey != NULL)
        BCryptDestroyKey(hPublicKey);
    if (hSecret != NULL)
        BCryptDestroySecret(hSecret);
    _BIDFreeBuffer(&pub);

    return err;
}

BIDError
_BIDGenerateNonce(
    BIDContext context,
    json_t **pNonce)
{
    BIDError err;
    NTSTATUS nts;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    unsigned char nonce[8];

    *pNonce = NULL;

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptGenRandom(hAlgorithm, nonce, sizeof(nonce), 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _BIDJsonBinaryValue(context, nonce, sizeof(nonce), pNonce);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return err;
}

static const UCHAR _BIDSalt[9] = "BrowserID";

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
    BIDError err;
    BIDJWK jwk = NULL;
    struct BIDJWTDesc jwt = { 0 };
    PUCHAR pbDerivedKey = NULL;
    size_t cbDerivedKey = 0;

    *ppbDerivedKey = NULL;
    *pcbDerivedKey = 0;

    jwk = json_object();
    if (jwk == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSetBinaryValue(context,
                                       jwk,
                                       "secret-key",
                                       pbBaseKey,
                                       cbBaseKey);
    BID_BAIL_ON_ERROR(err);

    jwt.EncData = BIDMalloc(sizeof(_BIDSalt) + cbSalt + 1);
    if (jwt.EncData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    } 

    CopyMemory(jwt.EncData, _BIDSalt, sizeof(_BIDSalt));
    if (pbSalt != NULL)
        CopyMemory(&jwt.EncData[sizeof(_BIDSalt)], pbSalt, cbSalt);
    jwt.EncData[sizeof(_BIDSalt) + cbSalt] = 1; /* T1 */

    cbDerivedKey = 32; /* XXX */
    pbDerivedKey = BIDMalloc(cbDerivedKey);

    err = _BIDMakeShaDigest(&_BIDJWTAlgorithms[0], context, &jwt, jwk,
                            pbDerivedKey, &cbDerivedKey);
    BID_BAIL_ON_ERROR(err);

    *ppbDerivedKey = pbDerivedKey;
    *pcbDerivedKey = cbDerivedKey;

cleanup:
    if (err != BID_S_OK) {
        SecureZeroMemory(pbDerivedKey, cbDerivedKey);
        BIDFree(pbDerivedKey);
    }

    BIDFree(jwt.EncData);
    json_decref(jwk);

    return err;
}

/*
 * X.509/mutual authentication SPIs below, not yet implemented
 */
BIDError
_BIDLoadX509PrivateKey(
    BIDContext context BID_UNUSED,
    const char *path,
    BIDJWK *pPrivateKey)
{
    return BID_S_NOT_IMPLEMENTED;
}

BIDError
_BIDLoadX509Certificate(
    BIDContext context BID_UNUSED,
    const char *path,
    json_t **pCert)
{
    return BID_S_NOT_IMPLEMENTED;
}

BIDError
_BIDPopulateX509Identity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity identity,
    uint32_t ulReqFlags)
{
    return BID_S_NOT_IMPLEMENTED;
}

BIDError
_BIDValidateX509CertChain(
    BIDContext context,
    const char *caCertificateFile,
    const char *caCertificateDir,
    json_t *certChain)
{
    return BID_S_NOT_IMPLEMENTED;
}

