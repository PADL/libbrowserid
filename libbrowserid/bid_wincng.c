/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#include <bcrypt.h>
#include <ncrypt.h>

#ifdef BID_DECIMAL_BIGNUM
#include <bn/cryptlib.h>
#endif

/*
 * Windows Cryptography Next Generation (CNG) provider for BrowserID.
 */

/*
 * TODO X.509 support
 */

/*
 * Secret key agreement handle.
 */
struct BIDSecretHandleDesc {
    enum {
        SECRET_TYPE_KEY_AGREEMENT,
        SECRET_TYPE_IMPORTED
    } SecretType;
    union {
        BCRYPT_SECRET_HANDLE KeyAgreement;
        struct {
            unsigned char *pbSecret;
            size_t cbSecret;
        } Imported;
    } SecretData;
};

static BIDError
_BIDAllocSecret(
    BIDContext context BID_UNUSED,
    BIDSecretHandle keyInput,
    BIDSecretHandle *pSecretHandle);

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

/*
 * XXX once everything is base64-encoded we can get rid of this
 * bignum library entirely
 */
static BIDError
_BIDParseDecimalNumber(
    BIDContext context,
    const char *szValue,
    size_t cchValue,
    BCryptBuffer *blob)
{
#ifdef BID_DECIMAL_BIGNUM
    BIGNUM *bn;

    if (!BN_dec2bn(&bn, szValue))
        return BID_S_INVALID_KEY;

    blob->pvBuffer = BIDMalloc(BN_num_bytes(bn));
    if (blob->pvBuffer == NULL) {
        BN_free(bn);
        return BID_S_NO_MEMORY;
    }

    blob->cbBuffer = BN_bn2bin(bn, blob->pvBuffer);

    BN_free(bn);

    return BID_S_OK;
#else
    return BID_S_NOT_IMPLEMENTED;
#endif
}

static BIDError
_BIDGetJsonBufferValue(
    BIDContext context,
    BIDJWK jwk,
    const char *key,
    ULONG encoding,
    ULONG cbPadding,
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
            err = _BIDParseDecimalNumber(context, szValue, len, blob);
        else
            err = BID_S_INVALID_JSON;

        if (err != BID_S_OK)
            err = _BIDParseHexNumber(context, szValue, len, blob);
    }

    if (cbPadding) {
        if (blob->cbBuffer > cbPadding)
            err = BID_S_BUFFER_TOO_LONG;
        else {
            DWORD cbOffset = cbPadding - blob->cbBuffer;

            /* Add leading zeros to pad to block size */
            MoveMemory((PUCHAR)blob->pvBuffer + cbOffset,
                       blob->pvBuffer, blob->cbBuffer);
            ZeroMemory(blob->pvBuffer, cbOffset);
        }
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
    LPCWSTR *pAlgID,
    DWORD *pdwSignFlags)
{
    LPCWSTR algID = NULL;

    *pAlgID = NULL;
    *pdwSignFlags = 0;

    if (strncmp(algorithm->szAlgID, "DS", 2) == 0) {
        algID = BCRYPT_DSA_ALGORITHM;
    } else if (strncmp(algorithm->szAlgID, "RS", 2) == 0) {
        algID = BCRYPT_RSA_ALGORITHM;
        *pdwSignFlags = BCRYPT_PAD_PKCS1;
    } else {
        return BID_S_UNKNOWN_ALGORITHM;
    }

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
                           cbHash,
                           0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = BID_S_OK;
    *digestLength = cbHash;

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
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    BIDJWK jwk,
    BOOLEAN bPublic,
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
    DWORD cbPadding = 0;

    *phKey = NULL;

    if (bPublic) {
        err = _BIDGetJsonBufferValue(context, jwk, "e", BID_ENCODING_UNKNOWN,
                                     cbPadding, &e);
        BID_BAIL_ON_ERROR(err);
    } else {
        err = _BIDGetJsonBufferValue(context, jwk, "d", BID_ENCODING_UNKNOWN,
                                     cbPadding, &d);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDGetJsonBufferValue(context, jwk, "n", BID_ENCODING_UNKNOWN,
                                 cbPadding, &n);
    BID_BAIL_ON_ERROR(err);

    cbRsaKey = sizeof(*rsaKey);
    cbRsaKey += bPublic ? e.cbBuffer : d.cbBuffer;
    cbRsaKey += n.cbBuffer;

    rsaKey = BIDMalloc(cbRsaKey);
    if (rsaKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(rsaKey, cbRsaKey);

    rsaKey->Magic       = bPublic
                        ? BCRYPT_RSAPUBLIC_MAGIC : BCRYPT_RSAPRIVATE_MAGIC;
    rsaKey->BitLength   = n.cbBuffer * 8;
    rsaKey->cbPublicExp = bPublic ? e.cbBuffer : d.cbBuffer;
    rsaKey->cbModulus   = n.cbBuffer;
    rsaKey->cbPrime1    = 0;
    rsaKey->cbPrime2    = 0;

    p = (PUCHAR)(rsaKey + 1);

    if (bPublic) {
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
                              bPublic ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAPRIVATE_BLOB,
                              phKey,
                              (PUCHAR)rsaKey,
                              p - (PUCHAR)rsaKey,
                              BCRYPT_NO_KEY_VALIDATION);
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

static void
_BIDOutputDebugJson(json_t *j)
{
    char *szJson = json_dumps(j, JSON_INDENT(8));

    OutputDebugString(szJson);
    OutputDebugString("\r\n");

    BIDFree(szJson);
}

static BIDError
_BIDMakeJwtDsaKey(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    BIDJWK jwk,
    BOOLEAN bPublic,
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
    DWORD cbPadding = algorithm->cbKey / 8;
    DWORD cbKey = strtoul(&algorithm->szAlgID[2], NULL, 10);

    *phKey = NULL;

    if (cbPadding != 20) {
        err = BID_S_BUFFER_TOO_LONG; /* limitations in API */
        goto cleanup;
    }

    /* prime factor */
    err = _BIDGetJsonBufferValue(context, jwk, "q", BID_ENCODING_UNKNOWN,
                                 cbPadding, &q);
    BID_BAIL_ON_ERROR(err);

    /* modulus */
    err = _BIDGetJsonBufferValue(context, jwk, "p", BID_ENCODING_UNKNOWN,
                                 cbKey, &p);
    BID_BAIL_ON_ERROR(err);

    /* generator */
    err = _BIDGetJsonBufferValue(context, jwk, "g", BID_ENCODING_UNKNOWN,
                                 cbKey, &g);
    BID_BAIL_ON_ERROR(err);

    if (bPublic) {
        /* public key */
        err = _BIDGetJsonBufferValue(context, jwk, "y", BID_ENCODING_UNKNOWN,
                                     cbKey, &y);
        BID_BAIL_ON_ERROR(err);
    } else {
        /* private exponent */
        err = _BIDGetJsonBufferValue(context, jwk, "x", BID_ENCODING_UNKNOWN,
                                     cbPadding, &x);
        BID_BAIL_ON_ERROR(err);
    }

    if (p.cbBuffer != g.cbBuffer) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    if ((bPublic ? y.cbBuffer : x.cbBuffer) != (bPublic ? p.cbBuffer : cbPadding)) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    cbDsaKey = sizeof(*dsaKey);
    cbDsaKey += p.cbBuffer + g.cbBuffer;
    if (bPublic)
        cbDsaKey += y.cbBuffer;
    else
        cbDsaKey += p.cbBuffer + x.cbBuffer;

    dsaKey = BIDCalloc(1, cbDsaKey);
    if (dsaKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    dsaKey->dwMagic     = bPublic
                        ? BCRYPT_DSA_PUBLIC_MAGIC : BCRYPT_DSA_PRIVATE_MAGIC;
    dsaKey->cbKey       = cbKey;
    dsaKey->Count[2]    = 0x10; /* 4096 BE */

    CopyMemory(dsaKey->q, q.pvBuffer, q.cbBuffer);
    pbDsaKeyData = (PUCHAR)(dsaKey + 1);

    CopyMemory(pbDsaKeyData, p.pvBuffer, p.cbBuffer);
    pbDsaKeyData += p.cbBuffer;

    CopyMemory(pbDsaKeyData, g.pvBuffer, g.cbBuffer);
    pbDsaKeyData += g.cbBuffer;

    if (bPublic) {
        CopyMemory(pbDsaKeyData, y.pvBuffer, y.cbBuffer);
        pbDsaKeyData += y.cbBuffer;
    } else {
        pbDsaKeyData += dsaKey->cbKey; /* skip over public key */

        CopyMemory(pbDsaKeyData, x.pvBuffer, x.cbBuffer);
        pbDsaKeyData += x.cbBuffer;
    }

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              bPublic ? BCRYPT_DSA_PUBLIC_BLOB : BCRYPT_DSA_PRIVATE_BLOB,
                              phKey,
                              (PUCHAR)dsaKey,
                              pbDsaKeyData - (PUCHAR)dsaKey,
                              BCRYPT_NO_KEY_VALIDATION);
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
    BOOLEAN bPublic,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    json_t *x5c;

    *phKey = NULL;

    x5c = json_object_get(jwk, "x5c");
    if (bPublic && x5c != NULL)
        err = _BIDCertDataToKey(algorithm, context, hAlgorithm, x5c, 0, phKey);
    else if (strncmp(algorithm->szAlgID, "RS", 2) == 0)
        err = _BIDMakeJwtRsaKey(algorithm, context, hAlgorithm, jwk, bPublic, phKey);
    else if (strncmp(algorithm->szAlgID, "DS", 2) == 0)
        err = _BIDMakeJwtDsaKey(algorithm, context, hAlgorithm, jwk, bPublic, phKey);
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
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKey = 0, cbResult;
    DWORD dwFlags = 0;
    BOOLEAN bPublic;
    BOOLEAN bDsaKey = (strncmp(algorithm->szAlgID, "DS", 2) == 0);

    *pcbKey = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID, &dwFlags);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    /* XXX this is all a bit ugly, is there a better way? */
    bPublic = (json_object_get(jwk, bDsaKey ? "y" : "e") != NULL);

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, bPublic, &hKey);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptGetProperty(hKey, BCRYPT_KEY_STRENGTH, (PUCHAR)&cbKey,
                            sizeof(cbKey), &cbResult, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    cbKey /= 8; /* bytes */

    /*
     * FIPS 186-3[3] specifies L and N length pairs of
     * (1024,160), (2048,224), (2048,256), and (3072,256).
     */
    if (bDsaKey) {
        if (cbKey < 160)
            cbKey = 160;
        else if (cbKey < 224)
            cbKey = 224;
        else if (cbKey < 256)
            cbKey = 256;
    }

    *pcbKey = cbKey;

cleanup:
    if (hKey != NULL)
        BCryptDestroyKey(hKey);
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
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwFlags = 0;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    DWORD cbOutput = 0;
    UCHAR pbDigest[64]; /* longest known hash is SHA-512 */
    size_t cbDigest = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID, &dwFlags);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, FALSE, &hKey);
    BID_BAIL_ON_ERROR(err);

    cbDigest = sizeof(pbDigest);

    err = _BIDMakeShaDigest(algorithm, context, jwt, NULL, pbDigest, &cbDigest);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);

    if (dwFlags & BCRYPT_PAD_PKCS1) {
        err = _BIDMapHashAlgorithmID(algorithm, &paddingInfo.pszAlgId);
        BID_BAIL_ON_ERROR(err);
    }

    nts = BCryptSignHash(hKey,
                         (dwFlags & BCRYPT_PAD_PKCS1) ? &paddingInfo : NULL,
                         pbDigest,
                         cbDigest,
                         NULL,
                         0,
                         &cbOutput,
                         dwFlags);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    jwt->Signature = BIDMalloc(cbOutput);
    if (jwt->Signature == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    jwt->SignatureLength = cbOutput;

    nts = BCryptSignHash(hKey,
                         (dwFlags & BCRYPT_PAD_PKCS1) ? &paddingInfo : NULL,
                         pbDigest,
                         cbDigest,
                         jwt->Signature,
                         jwt->SignatureLength,
                         &cbOutput,
                         dwFlags);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    jwt->SignatureLength = cbOutput;

    err = BID_S_OK;

cleanup:
    if (hKey != NULL)
        BCryptDestroyKey(hKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

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
    DWORD dwFlags = 0;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { 0 };
    UCHAR pbDigest[64]; /* longest known hash is SHA-512 */
    size_t cbDigest = 0;

    *valid = 0;

    err = _BIDMapCryptAlgorithmID(algorithm, &wszAlgID, &dwFlags);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID,
                                      NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _CNGMakeKey(algorithm, context, hAlgorithm, jwk, TRUE, &hKey);
    BID_BAIL_ON_ERROR(err);

    cbDigest = sizeof(pbDigest);

    err = _BIDMakeShaDigest(algorithm, context, jwt, NULL, pbDigest, &cbDigest);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->EncData != NULL);

    if (dwFlags & BCRYPT_PAD_PKCS1) {
        err = _BIDMapHashAlgorithmID(algorithm, &paddingInfo.pszAlgId);
        BID_BAIL_ON_ERROR(err);
    }

    nts = BCryptVerifySignature(hKey,
                                (dwFlags & BCRYPT_PAD_PKCS1) ? &paddingInfo : NULL,
                                pbDigest,
                                cbDigest,
                                jwt->Signature,
                                jwt->SignatureLength,
                                dwFlags);
    if (nts == STATUS_SUCCESS)
        *valid = 1;
    else if (nts == STATUS_INVALID_SIGNATURE)
        nts = STATUS_SUCCESS;
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (hKey != NULL)
        BCryptDestroyKey(hKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);

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
    BOOLEAN bPublic,
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
    DWORD cbPad = context->DhKeySize / 8;

    *phKey = NULL;

    if (dhParams == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDGetJsonBufferValue(context, dhParams, "p",
                                 BID_ENCODING_BASE64_URL, cbPad, &p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhParams, "g",
                                 BID_ENCODING_BASE64_URL, cbPad, &g);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhKey, "y",
                                 BID_ENCODING_BASE64_URL, cbPad, &y);
    BID_BAIL_ON_ERROR(err);

    if (!bPublic) {
        err = _BIDGetJsonBufferValue(context, dhKey, "x",
                                     BID_ENCODING_BASE64_URL, cbPad, &x);
        BID_BAIL_ON_ERROR(err);
    }

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

    dhKeyBlob = BIDCalloc(1, cbDhKeyBlob);
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    dhKeyBlob->dwMagic = bPublic ? BCRYPT_DH_PUBLIC_MAGIC : BCRYPT_DH_PRIVATE_MAGIC;
    dhKeyBlob->cbKey   = cbPad;

    pbDhKeyBlob = (PUCHAR)(dhKeyBlob + 1);

    CopyMemory(pbDhKeyBlob, p.pvBuffer, p.cbBuffer);
    pbDhKeyBlob += p.cbBuffer;

    CopyMemory(pbDhKeyBlob, g.pvBuffer, g.cbBuffer);
    pbDhKeyBlob += g.cbBuffer;

    CopyMemory(pbDhKeyBlob, y.pvBuffer, y.cbBuffer);
    pbDhKeyBlob += y.cbBuffer;

    if (!bPublic) {
        CopyMemory(pbDhKeyBlob, x.pvBuffer, x.cbBuffer);
        pbDhKeyBlob += x.cbBuffer;
    }

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              bPublic ? BCRYPT_DH_PUBLIC_BLOB : BCRYPT_DH_PRIVATE_BLOB,
                              phKey,
                              (PUCHAR)dhKeyBlob,
                              pbDhKeyBlob - (PUCHAR)dhKeyBlob,
                              BCRYPT_NO_KEY_VALIDATION);
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

static BIDError
_BIDCryptGetKeyParam(
    BIDContext context,
    HCRYPTKEY hKey,
    DWORD dwParam,
    json_t *json,
    const char *szJsonKey)
{
    BIDError err;
    PUCHAR pbData = NULL;
    DWORD cbData = 0, i;

    if (!CryptGetKeyParam(hKey, dwParam, NULL, &cbData, 0))
        return BID_S_CRYPTO_ERROR;

    pbData = BIDMalloc(cbData);
    if (pbData == NULL)
        return BID_S_NO_MEMORY;

    if (!CryptGetKeyParam(hKey, dwParam, pbData, &cbData, 0)) {
        BIDFree(pbData);
        return BID_S_CRYPTO_ERROR;
    }

    /*
     * Pretty sure we need to swap the endianness here, as OpenSSL and
     * CNG are big-endian, whereas CryptoAPI is little-endian.
     */
    for (i = 0; i < cbData / 2; i++) {
        UCHAR tmp = pbData[i];
        pbData[i] = pbData[cbData - 1 - i];
        pbData[cbData - 1 - i] = tmp;
    }

    err = _BIDJsonObjectSetBinaryValue(context, json, szJsonKey,
                                       pbData, cbData);

    BIDFree(pbData);

    return err;
}

BIDError
_BIDGenerateDHParams(
    BIDContext context,
    json_t **pDhParams)
{
    BIDError err;
    json_t *dhParams = NULL;
    HCRYPTPROV hProv = (HCRYPTPROV)0;
    HCRYPTKEY hKey = (HCRYPTKEY)0;
    DWORD dwFlags;

    *pDhParams = NULL;

    BID_ASSERT(context->DhKeySize != 0);

    dhParams = json_object();
    if (dhParams == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    /*
     * Can't find a way to generate ephereral DH parameters using
     * BCrypt (parameters must be set before a key can be generated),
     * so fall back to the old WinCrypt. XXX
     */

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_DSS_DH_PROV, PROV_DSS_DH,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    /*
     * We're just going to generate a key, throw away the private part
     * and keep the parameters. According to the documentation, the key
     * size in bits, is set in the upper 16 bits of the parameter.
     */
    dwFlags = CRYPT_EXPORTABLE;
    dwFlags |= context->DhKeySize << 16;

    if (!CryptGenKey(hProv, CALG_DH_EPHEM, dwFlags, &hKey)) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    err = _BIDCryptGetKeyParam(context, hKey, KP_P, dhParams, "p");
    BID_BAIL_ON_ERROR(err);

    err = _BIDCryptGetKeyParam(context, hKey, KP_G, dhParams, "g");
    BID_BAIL_ON_ERROR(err);

    _BIDOutputDebugJson(dhParams);

    err = BID_S_OK;
    *pDhParams = dhParams;

cleanup:
    if (err != BID_S_OK)
        json_decref(dhParams);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hProv)
        CryptReleaseContext(hProv, 0);

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
    DWORD cbPad = context->DhKeySize / 8;

    *ppDhParamsHeader = NULL;

    err = _BIDGetJsonBufferValue(context, dhParams, "p", BID_ENCODING_BASE64_URL, cbPad, &p);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhParams, "g", BID_ENCODING_BASE64_URL, cbPad, &g);
    BID_BAIL_ON_ERROR(err);

    if (p.cbBuffer != g.cbBuffer) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    cbDhParamsHeader = sizeof(*pDhParamsHeader) + p.cbBuffer + g.cbBuffer;
    pDhParamsHeader = BIDCalloc(1, cbDhParamsHeader);
    if (pDhParamsHeader == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

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
                                       dhKey,
                                       "y",
                                       &pbDhKeyBlob[2 * dhKeyBlob->cbKey],
                                       dhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context,
                                       dhKey,
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
    BIDSecretHandle *pSecretHandle)
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
    struct BIDSecretHandleDesc keyInput = { 0 };

    *pSecretHandle = NULL;

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

    err = _BIDMakeDHKey(context, hAlgorithm, dhParams, dhKey,
                        FALSE /* bPublic */, &hPrivateKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeDHKey(context, hAlgorithm, dhParams, pubValue,
                        TRUE /* bPublic */, &hPublicKey);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    keyInput.SecretType = SECRET_TYPE_KEY_AGREEMENT;
    keyInput.SecretData.KeyAgreement = hSecret;

    err = _BIDAllocSecret(context, &keyInput, pSecretHandle);
    BID_BAIL_ON_ERROR(err);

    hSecret = NULL;

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

static UCHAR _BIDSalt[9] = "BrowserID";

static BIDError
_BIDDeriveKeyKeyAgreement(
    BIDContext context BID_UNUSED,
    BIDSecretHandle secretHandle,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey)
{
    BIDError err;
    NTSTATUS nts;
    BCryptBufferDesc params;
    BCryptBuffer paramBuffers[4];
    UCHAR szEmptySalt[1] = { 0 };
    ULONG cbDerivedKey = 0;
    PUCHAR pbDerivedKey = NULL;
    UCHAR T1 = 0x01;

    *ppbDerivedKey = NULL;
    *pcbDerivedKey = 0;

    if (secretHandle->SecretData.KeyAgreement == NULL) {
        err = BID_S_INVALID_SECRET;
        goto cleanup;
    }

    paramBuffers[0].cbBuffer   = wcslen(BCRYPT_SHA256_ALGORITHM) * sizeof(WCHAR);
    paramBuffers[0].BufferType = KDF_HASH_ALGORITHM;
    paramBuffers[0].pvBuffer   = BCRYPT_SHA256_ALGORITHM;

    paramBuffers[1].cbBuffer   = sizeof(_BIDSalt);
    paramBuffers[1].BufferType = KDF_SECRET_PREPEND;
    paramBuffers[1].pvBuffer   = _BIDSalt;

    paramBuffers[2].cbBuffer   = cbSalt;
    paramBuffers[2].BufferType = KDF_SECRET_APPEND;
    paramBuffers[2].pvBuffer   = pbSalt ? (PUCHAR)pbSalt : szEmptySalt;

    paramBuffers[3].cbBuffer   = 1;
    paramBuffers[3].BufferType = KDF_SECRET_APPEND;
    paramBuffers[3].pvBuffer   = &T1;

    params.ulVersion = BCRYPTBUFFER_VERSION;
    params.cBuffers  = ARRAYSIZE(paramBuffers);
    params.pBuffers  = paramBuffers;

    nts = BCryptDeriveKey(secretHandle->SecretData.KeyAgreement,
                          BCRYPT_KDF_HMAC,
                          &params,
                          NULL,
                          0,
                          &cbDerivedKey,
                          KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    pbDerivedKey = BIDMalloc(cbDerivedKey);
    if (pbDerivedKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptDeriveKey(secretHandle->SecretData.KeyAgreement,
                          BCRYPT_KDF_HMAC,
                          &params,
                          pbDerivedKey,
                          cbDerivedKey,
                          &cbDerivedKey,
                          KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    *ppbDerivedKey = pbDerivedKey;
    *pcbDerivedKey = cbDerivedKey;

cleanup:
    if (err != BID_S_OK && pbDerivedKey != NULL) {
        SecureZeroMemory(pbDerivedKey, cbDerivedKey);
        BIDFree(pbDerivedKey);
    }

    return err;
}

static BIDError
_BIDDeriveKeyImported(
    BIDContext context BID_UNUSED,
    BIDSecretHandle secretHandle,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey)
{
    BIDError err;
    NTSTATUS nts;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR pbHashObject = NULL;
    DWORD cbHashObject;
    PUCHAR pbDerivedKey = NULL;
    ULONG cbDerivedKey = 0;
    DWORD cbData;
    UCHAR T1 = 0x01;

    *ppbDerivedKey = NULL;
    *pcbDerivedKey = 0;

    if (secretHandle->SecretData.Imported.pbSecret == NULL) {
        err = BID_S_INVALID_SECRET;
        goto cleanup;
    }

    nts = BCryptOpenAlgorithmProvider(&hAlg,
                                      BCRYPT_SHA256_ALGORITHM,
                                      NULL,
                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
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
                            (PUCHAR)&cbDerivedKey,
                            sizeof(DWORD),
                            &cbData,
                            0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    pbDerivedKey = BIDMalloc(cbDerivedKey);
    if (pbDerivedKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject,
                           secretHandle->SecretData.Imported.pbSecret,
                           secretHandle->SecretData.Imported.cbSecret,
                           0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptHashData(hHash,
                         _BIDSalt,
                         sizeof(_BIDSalt),
                         0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptHashData(hHash,
                         secretHandle->SecretData.Imported.pbSecret,
                         secretHandle->SecretData.Imported.cbSecret,
                         0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    if (pbSalt != NULL) {
        nts = BCryptHashData(hHash, (PUCHAR)pbSalt, cbSalt, 0);
        BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));
    }

    nts = BCryptHashData(hHash, &T1, 1, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptFinishHash(hHash, pbDerivedKey, cbDerivedKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = BID_S_OK;

    *ppbDerivedKey = pbDerivedKey;
    *pcbDerivedKey = cbDerivedKey;

cleanup:
    if (err != BID_S_OK && pbDerivedKey != NULL) {
        SecureZeroMemory(pbDerivedKey, cbDerivedKey);
        BIDFree(pbDerivedKey);
    }
    if (hHash != NULL)
        BCryptDestroyHash(hHash);
    BIDFree(pbHashObject);

    return err;
}

BIDError
_BIDDeriveKey(
    BIDContext context,
    BIDSecretHandle secretHandle,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey)
{
    BIDError err;

    *ppbDerivedKey = NULL;
    *pcbDerivedKey = 0;

    if (secretHandle == NULL)
        return BID_S_INVALID_PARAMETER;

    switch (secretHandle->SecretType) {
    case SECRET_TYPE_KEY_AGREEMENT:
        err = _BIDDeriveKeyKeyAgreement(context, secretHandle,
                                        pbSalt, cbSalt,
                                        ppbDerivedKey, pcbDerivedKey);
        break;
    case SECRET_TYPE_IMPORTED:
        err = _BIDDeriveKeyImported(context, secretHandle,
                                    pbSalt, cbSalt,
                                    ppbDerivedKey, pcbDerivedKey);
        break;
    default:
        err = BID_S_INVALID_SECRET;
        break;
    }

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

static BIDError
_BIDAllocSecret(
    BIDContext context BID_UNUSED,
    BIDSecretHandle keyInput,
    BIDSecretHandle *pSecretHandle)
{
    BIDSecretHandle secretHandle;

    *pSecretHandle = NULL;

    secretHandle = BIDCalloc(1, sizeof(*secretHandle));
    if (secretHandle == NULL)
        return BID_S_NO_MEMORY;

    secretHandle->SecretType = keyInput->SecretType;

    switch (keyInput->SecretType) {
    case SECRET_TYPE_KEY_AGREEMENT:
        secretHandle->SecretData.KeyAgreement =
            keyInput->SecretData.KeyAgreement;
        keyInput->SecretData.KeyAgreement = NULL;
        /* no way to duplicate this */
        break;
    case SECRET_TYPE_IMPORTED:
        secretHandle->SecretData.Imported.pbSecret =
            BIDMalloc(keyInput->SecretData.Imported.cbSecret);
        if (secretHandle->SecretData.Imported.pbSecret == NULL) {
            BIDFree(secretHandle);
            return BID_S_NO_MEMORY;
        }

        CopyMemory(secretHandle->SecretData.Imported.pbSecret,
                   keyInput->SecretData.Imported.pbSecret,
                   keyInput->SecretData.Imported.cbSecret);
        secretHandle->SecretData.Imported.cbSecret =
            keyInput->SecretData.Imported.cbSecret;
    }

    *pSecretHandle = secretHandle;

    return BID_S_OK;
}

BIDError
_BIDDestroySecret(
    BIDContext context BID_UNUSED,
    BIDSecretHandle secretHandle)
{
    BIDError err;
    NTSTATUS nts;

    if (secretHandle == NULL)
        return BID_S_INVALID_PARAMETER;

    switch (secretHandle->SecretType) {
    case SECRET_TYPE_KEY_AGREEMENT:
        nts = BCryptDestroySecret(secretHandle->SecretData.KeyAgreement);
        err = _BIDNtStatusToBIDError(nts);
        break;
    case SECRET_TYPE_IMPORTED:
        if (secretHandle->SecretData.Imported.pbSecret != NULL) {
            SecureZeroMemory(secretHandle->SecretData.Imported.pbSecret,
                             secretHandle->SecretData.Imported.cbSecret);
            BIDFree(secretHandle->SecretData.Imported.pbSecret);
        }
        break;
    }

    SecureZeroMemory(secretHandle, sizeof(*secretHandle));
    BIDFree(secretHandle);

    return BID_S_OK;
}

BIDError
_BIDImportSecretKeyData(
    BIDContext context,
    unsigned char *pbSecret,
    size_t cbSecret,
    BIDSecretHandle *pSecretHandle)
{
    struct BIDSecretHandleDesc keyInput;

    keyInput.SecretType = SECRET_TYPE_IMPORTED;
    keyInput.SecretData.Imported.pbSecret = pbSecret;
    keyInput.SecretData.Imported.cbSecret = cbSecret;

    return _BIDAllocSecret(context, &keyInput, pSecretHandle);
}
