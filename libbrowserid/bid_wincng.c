/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the libbrowserid software
 *    and any accompanying software that uses the libbrowserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
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
        BCRYPT_SECRET_HANDLE SecretAgreement;
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
_BIDCertStringToName(
    BIDContext context,
    const char *szName,
    PCERT_NAME_BLOB pCertNameBlob);

static BIDError
_BIDNtStatusToBIDError(NTSTATUS nts)
{
    BIDError err;

    if (NT_SUCCESS(nts))
        err = BID_S_OK;
    else if (nts == STATUS_NO_MEMORY)
        err = BID_S_NO_MEMORY;
    else if (nts == STATUS_INVALID_PARAMETER)
        err = BID_S_INVALID_PARAMETER;
    else
        err = BID_S_CRYPTO_ERROR;

    return err;
}

static BIDError
_BIDSecStatusToBIDError(SECURITY_STATUS ss)
{
    BIDError err;

    switch (ss) {
    case SEC_E_OK:
        err = BID_S_OK;
        break;
    case NTE_NO_MEMORY:
        err = BID_S_NO_MEMORY;
        break;
    case NTE_INVALID_PARAMETER:
        err = BID_S_INVALID_PARAMETER;
        break;
    case NTE_BAD_KEYSET:
        err = BID_S_KEY_FILE_UNREADABLE;
        break;
    default:
        err = BID_S_CRYPTO_ERROR;
        break;
    }

    return err;
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
    size_t i, cbBuffer = cchValue / 2;
    int pad = !!(cchValue % 2);

    cbBuffer += pad;

    blob->pvBuffer = BIDMalloc(cbBuffer);
    if (blob->pvBuffer == NULL)
        return BID_S_NO_MEMORY;

    for (i = 0; i < cbBuffer; i++) {
        int b, n;

        if (pad && i == 0)
            n = sscanf(&szValue[0], "%01x", &b);
        else
            n = sscanf(&szValue[i * 2 - pad], "%02x", &b);
        if (n != 1) {
            BIDFree(blob->pvBuffer);
            blob->pvBuffer = NULL;
            return BID_S_INVALID_JSON;
        }
        ((PUCHAR)blob->pvBuffer)[i] = b & 0xff;
    }
    blob->cbBuffer = cbBuffer;
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

        if (cchDecimal == len)
            err = _BIDParseDecimalNumber(context, szValue, len, blob);
        else
            err = BID_S_INVALID_JSON;

        if (err != BID_S_OK)
            err = _BIDParseHexNumber(context, szValue, len, blob);
    }

    if (err == BID_S_OK && cbPadding != 0) {
        if (blob->cbBuffer > cbPadding) {
            err = BID_S_BUFFER_TOO_LONG;
        } else if (blob->cbBuffer != cbPadding) {
            PBYTE pbPadded;
            DWORD cbOffset = cbPadding - blob->cbBuffer;

            pbPadded = BIDMalloc(cbPadding);
            if (pbPadded == NULL)
                return BID_S_NO_MEMORY;

            /* Add leading zeros to pad to block size */
            ZeroMemory(pbPadded, cbOffset);
            CopyMemory(pbPadded + cbOffset, blob->pvBuffer, blob->cbBuffer);

            BIDFree(blob->pvBuffer);
            blob->pvBuffer = pbPadded;
            blob->cbBuffer = cbPadding;
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
_BIDMapECDHAlgorithmID(
    BIDContext context,
    json_t *ecDhParams,
    LPCWSTR *pAlgID)
{
    BIDError err;
    LPCWSTR algID = NULL;
    ssize_t curve;

    *pAlgID = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_ECDH_KEYEX);

    err = _BIDGetECDHCurve(context, ecDhParams, &curve);
    if (err != BID_S_OK)
        return err;

    switch (curve) {
    case BID_CONTEXT_ECDH_CURVE_P256:
        algID = BCRYPT_ECDH_P256_ALGORITHM;
        break;
    case BID_CONTEXT_ECDH_CURVE_P384:
        algID = BCRYPT_ECDH_P384_ALGORITHM;
        break;
    case BID_CONTEXT_ECDH_CURVE_P521:
        algID = BCRYPT_ECDH_P521_ALGORITHM;
        break;
    default:
        return BID_S_UNKNOWN_EC_CURVE;
        break;
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
_BIDCertDataToContext(
    BIDContext context,
    json_t *x5c,
    PCCERT_CONTEXT *ppCertContext)
{
    BIDError err;
    const char *szCert;
    unsigned char *pbData = NULL;
    size_t cbData = 0;
    PCCERT_CONTEXT pCertContext = NULL;

    szCert = json_string_value(json_array_get(x5c, 0));
    if (szCert == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    err = _BIDBase64UrlDecode(szCert, &pbData, &cbData);
    BID_BAIL_ON_ERROR(err);

    pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,
                                                pbData,
                                                cbData);
    if (pCertContext == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    *ppCertContext = pCertContext;

cleanup:
    if (err != BID_S_OK && pCertContext != NULL)
        CertFreeCertificateContext(pCertContext);
    BIDFree(pbData);

    return err;
}

static BIDError
_BIDLoadCertificateFromStore(
    BIDContext context,
    const char *path,
    HCERTSTORE *phCertStore,
    PCCERT_CONTEXT *ppCertContext)
{
    BIDError err;
    CERT_NAME_BLOB cnbSubject = { 0 };
    PWSTR wszSubject = NULL;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwFlags;

    *ppCertContext = NULL;

    dwFlags = CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG;
    if (context->ContextOptions & BID_CONTEXT_RP)
        dwFlags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    else
        dwFlags |= CERT_SYSTEM_STORE_CURRENT_USER;

    hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                               0,
                               (HCRYPTPROV_LEGACY)0,
                               dwFlags,
                               L"MY");
    if (hCertStore == NULL) {
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    if (_BIDCertStringToName(context, path, &cnbSubject) == BID_S_OK) {
        pCertContext = CertFindCertificateInStore(hCertStore,
                                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_NAME,
                                                  &cnbSubject,
                                                  NULL);
    } else {
        err = _BIDUtf8ToUcs2(context, path, &wszSubject);
        BID_BAIL_ON_ERROR(err);

        pCertContext = CertFindCertificateInStore(hCertStore,
                                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_STR,
                                                  wszSubject,
                                                  NULL);
    }

    if (pCertContext == NULL) {
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    err = BID_S_OK;

    *phCertStore = hCertStore;
    *ppCertContext = pCertContext;

cleanup:
    if (err != BID_S_OK && hCertStore != NULL)
        CertCloseStore(hCertStore, 0);
    BIDFree(cnbSubject.pbData);
    BIDFree(wszSubject);

    return err;
}

static BIDError
_BIDCertDataToKey(
    struct BIDJWTAlgorithmDesc *algorithm,
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    json_t *x5c,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    PCCERT_CONTEXT pCertContext = NULL;
    CERT_PUBLIC_KEY_INFO *pcpki = NULL;
    LPCSTR szCertID;
    DWORD dwProv, dwFlags;

    *phKey = NULL;

    if (x5c == NULL) {
        err = BID_S_MISSING_CERT;
        goto cleanup;
    }

    if (strncmp(algorithm->szAlgID, "RS", 2) == 0) {
        dwProv = PROV_RSA_SIG;
        szCertID = szOID_RSA;
    } else if (strncmp(algorithm->szAlgID, "DS", 2) == 0) {
        dwProv = PROV_DSS;
        if (strcmp(algorithm->szAlgID, "DS128") == 0)
            szCertID = szOID_X957_SHA1DSA;
        else
            szCertID = szOID_X957_DSA;
    } else {
        err = BID_S_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    err = _BIDCertDataToContext(context, x5c, &pCertContext);
    BID_BAIL_ON_ERROR(err);

    pcpki = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

    if (pcpki->Algorithm.pszObjId == NULL) {
        err = BID_S_MISSING_ALGORITHM;
        goto cleanup;
    }

    if (strcmp(pcpki->Algorithm.pszObjId, szCertID) == 0) {
        err = BID_S_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    dwFlags = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;

    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
                                     pcpki,
                                     CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG,
                                     NULL,
                                     phKey)) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    if (pCertContext != NULL)
        CertFreeCertificateContext(pCertContext);

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
    BCryptBuffer p = { 0 };
    BCryptBuffer q = { 0 };
    BCRYPT_RSAKEY_BLOB *rsaKey = NULL;
    DWORD cbRsaKey = 0;
    PUCHAR pbRsaKey;
    DWORD cbPadding = 0;

    *phKey = NULL;

    /*
     * The layout of a BCRYPT_RSAKEY_BLOB is as follows:
     *
     *      BCRYPT_RSAKEY_BLOB
     *      e[cbPublicExp]
     *      n[cbModulus]
     *      p[cbPrime1]                 RSAPRIVATE_BLOB only
     *      q[cbPrime2]                 RSAPRIVATE_BLOB only
     *      dp[cbPrime1]                RSAFULLPRIVATE_BLOB only
     *      dq[cbPrime2]                RSAFULLPRIVATE_BLOB only
     *      coefficient[cbPrime2]       RSAFULLPRIVATE_BLOB only
     *      d[cbModulus]                RSAFULLPRIVATE_BLOB only
     *
     */
    err = _BIDGetJsonBufferValue(context, jwk, "e", BID_ENCODING_UNKNOWN,
                                 cbPadding, &e);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, jwk, "n", BID_ENCODING_UNKNOWN,
                                 cbPadding, &n);
    BID_BAIL_ON_ERROR(err);

    if (!bPublic) {
        err = _BIDGetJsonBufferValue(context, jwk, "p", BID_ENCODING_UNKNOWN,
                                     cbPadding, &p);
        BID_BAIL_ON_ERROR(err);

        err = _BIDGetJsonBufferValue(context, jwk, "q", BID_ENCODING_UNKNOWN,
                                     cbPadding, &q);
        BID_BAIL_ON_ERROR(err);
    }

    cbRsaKey = sizeof(*rsaKey) + e.cbBuffer + n.cbBuffer;
    if (!bPublic)
        cbRsaKey += p.cbBuffer + q.cbBuffer;

    rsaKey = BIDMalloc(cbRsaKey);
    if (rsaKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory(rsaKey, cbRsaKey);

    rsaKey->Magic       = bPublic
                        ? BCRYPT_RSAPUBLIC_MAGIC : BCRYPT_RSAPRIVATE_MAGIC;
    rsaKey->BitLength   = n.cbBuffer * 8;
    rsaKey->cbPublicExp = e.cbBuffer;
    rsaKey->cbModulus   = n.cbBuffer;
    rsaKey->cbPrime1    = p.cbBuffer;
    rsaKey->cbPrime2    = q.cbBuffer;

    pbRsaKey = (PUCHAR)(rsaKey + 1);

    CopyMemory(pbRsaKey, e.pvBuffer, e.cbBuffer);
    pbRsaKey += e.cbBuffer;

    CopyMemory(pbRsaKey, n.pvBuffer, n.cbBuffer);
    pbRsaKey += n.cbBuffer;

    if (!bPublic) {
        CopyMemory(pbRsaKey, p.pvBuffer, p.cbBuffer);
        pbRsaKey += p.cbBuffer;

        CopyMemory(pbRsaKey, q.pvBuffer, q.cbBuffer);
        pbRsaKey += q.cbBuffer;
    }

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              bPublic ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAPRIVATE_BLOB,
                              phKey,
                              (PUCHAR)rsaKey,
                              pbRsaKey - (PUCHAR)rsaKey,
                              BCRYPT_NO_KEY_VALIDATION);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (rsaKey != NULL) {
        SecureZeroMemory(rsaKey, cbRsaKey);
        BIDFree(rsaKey);
    }
    _BIDFreeBuffer(&e);
    _BIDFreeBuffer(&n);
    _BIDFreeBuffer(&p);
    _BIDFreeBuffer(&q);

    return err;
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
        err = _BIDCertDataToKey(algorithm, context, hAlgorithm, x5c, phKey);
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
    bPublic = (json_object_get(jwk, bDsaKey ? "x" : "p") == NULL);

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
_BIDMakeECDHKey(
    BIDContext context,
    BCRYPT_ALG_HANDLE hAlgorithm,
    json_t *ecDhParams,
    json_t *dhKey,
    BOOLEAN bPublic,
    BCRYPT_KEY_HANDLE *phKey)
{
    BIDError err;
    NTSTATUS nts;
    BCryptBuffer x = { 0 };
    BCryptBuffer y = { 0 };
    BCryptBuffer d = { 0 };
    BCRYPT_ECCKEY_BLOB *ecDhKeyBlob = NULL;
    DWORD cbEcDhKeyBlob = 0;
    PUCHAR pbEcDhKeyBlob;
    DWORD cbPad = 0, dwMagic = 0;
    ssize_t curve;

    *phKey = NULL;

    if (ecDhParams == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDGetECDHCurve(context, ecDhParams, &curve);
    BID_BAIL_ON_ERROR(err);

    switch (curve) {
    case BID_CONTEXT_ECDH_CURVE_P256:
        dwMagic = bPublic ? BCRYPT_ECDH_PUBLIC_P256_MAGIC : BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        cbPad = 32;
        break;
    case BID_CONTEXT_ECDH_CURVE_P384:
        dwMagic = bPublic ? BCRYPT_ECDH_PUBLIC_P384_MAGIC : BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        cbPad = 48;
        break;
    case BID_CONTEXT_ECDH_CURVE_P521:
        dwMagic = bPublic ? BCRYPT_ECDH_PUBLIC_P521_MAGIC : BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        cbPad = 66;
        break;
    default:
        err = BID_S_UNKNOWN_EC_CURVE;
        goto cleanup;
        break;
    }

    err = _BIDGetJsonBufferValue(context, dhKey, "x",
                                 BID_ENCODING_BASE64_URL, cbPad, &x);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBufferValue(context, dhKey, "y",
                                 BID_ENCODING_BASE64_URL, cbPad, &y);
    BID_BAIL_ON_ERROR(err);

    if (!bPublic) {
        err = _BIDGetJsonBufferValue(context, dhKey, "d",
                                     BID_ENCODING_BASE64_URL, cbPad, &d);
        BID_BAIL_ON_ERROR(err);
    }

    cbEcDhKeyBlob = sizeof(*dhKey);
    cbEcDhKeyBlob += x.cbBuffer + y.cbBuffer + d.cbBuffer;

    ecDhKeyBlob = BIDCalloc(1, cbEcDhKeyBlob);
    if (dhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    ecDhKeyBlob->dwMagic = dwMagic;
    ecDhKeyBlob->cbKey   = cbPad;

    pbEcDhKeyBlob = (PUCHAR)(ecDhKeyBlob + 1);

    CopyMemory(pbEcDhKeyBlob, x.pvBuffer, x.cbBuffer);
    pbEcDhKeyBlob += x.cbBuffer;

    CopyMemory(pbEcDhKeyBlob, y.pvBuffer, y.cbBuffer);
    pbEcDhKeyBlob += y.cbBuffer;

    if (!bPublic) {
        CopyMemory(pbEcDhKeyBlob, d.pvBuffer, d.cbBuffer);
        pbEcDhKeyBlob += d.cbBuffer;
    }

    nts = BCryptImportKeyPair(hAlgorithm,
                              NULL, /* hImportKey */
                              bPublic ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_ECCPRIVATE_BLOB,
                              phKey,
                              (PUCHAR)ecDhKeyBlob,
                              pbEcDhKeyBlob - (PUCHAR)ecDhKeyBlob,
                              BCRYPT_NO_KEY_VALIDATION);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

cleanup:
    if (dhKey != NULL) {
        SecureZeroMemory(ecDhKeyBlob, cbEcDhKeyBlob);
        BIDFree(ecDhKeyBlob);
    }
    _BIDFreeBuffer(&x);
    _BIDFreeBuffer(&y);
    _BIDFreeBuffer(&d);

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
_BIDECDHSecretAgreement(
    BIDContext context,
    BIDJWK dhKey,
    json_t *pubValue,
    BIDSecretHandle *pSecretHandle)
{
    BIDError err;
    NTSTATUS nts;
    json_t *dhParams;
    LPCWSTR wszAlgID = NULL;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    DWORD cbKey = 0, cbResult;
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

    err = _BIDMapECDHAlgorithmID(context, dhParams, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID, NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    err = _BIDMakeECDHKey(context, hAlgorithm, dhParams, dhKey,
                          FALSE /* bPublic */, &hPrivateKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeECDHKey(context, hAlgorithm, dhParams, pubValue,
                          TRUE /* bPublic */, &hPublicKey);
    BID_BAIL_ON_ERROR(err);

    /*
     * Check the strength of the public key to prevent a downgrade
     * attack. Note that cbKey is in bits and can be directly compared
     * to context->ECDHCurve.
     */
    nts = BCryptGetProperty(hPublicKey, BCRYPT_KEY_STRENGTH, (PUCHAR)&cbKey,
                            sizeof(cbKey), &cbResult, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    if (cbKey < context->ECDHCurve) {
        err = BID_S_KEY_TOO_SHORT;
        goto cleanup;
    }

    nts = BCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    keyInput.SecretType = SECRET_TYPE_KEY_AGREEMENT;
    keyInput.SecretData.SecretAgreement = hSecret;

    err = _BIDAllocSecret(context, &keyInput, pSecretHandle);
    BID_BAIL_ON_ERROR(err);

    hSecret = NULL;

cleanup:
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
    unsigned char nonce[16];

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
_BIDDeriveKeySecretAgreement(
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

    if (secretHandle->SecretData.SecretAgreement == NULL) {
        err = BID_S_INVALID_SECRET;
        goto cleanup;
    }

    paramBuffers[0].cbBuffer   = sizeof(BCRYPT_SHA256_ALGORITHM);
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

    nts = BCryptDeriveKey(secretHandle->SecretData.SecretAgreement,
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

    nts = BCryptDeriveKey(secretHandle->SecretData.SecretAgreement,
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
        err = _BIDDeriveKeySecretAgreement(context, secretHandle,
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
 * X.509/mutual authentication SPIs
 */
BIDError
_BIDLoadX509RsaPrivateKey(
    BIDContext context,
    PUCHAR pbbcKeyBlob,
    DWORD cbbcKeyBlob,
    BIDJWK privateKey)
{
    BIDError err;
    BCRYPT_RSAKEY_BLOB *pbcRsaKeyBlob = (BCRYPT_RSAKEY_BLOB *)pbbcKeyBlob;
    PUCHAR pbbcRsaKeyBlob = (PUCHAR)(pbcRsaKeyBlob + 1);

    BID_ASSERT(pbcRsaKeyBlob->Magic == BCRYPT_RSAPRIVATE_MAGIC);

    if (cbbcKeyBlob < (pbbcRsaKeyBlob - pbbcKeyBlob) +
                      pbcRsaKeyBlob->cbPublicExp +
                      pbcRsaKeyBlob->cbModulus +
                      pbcRsaKeyBlob->cbPrime1) {
        err = BID_S_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, privateKey, "algorithm",
                            json_string("RS"), BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "e",
                                       pbbcRsaKeyBlob,
                                       pbcRsaKeyBlob->cbPublicExp);
    BID_BAIL_ON_ERROR(err);

    pbbcRsaKeyBlob += pbcRsaKeyBlob->cbPublicExp;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "n",
                                       pbbcRsaKeyBlob,
                                       pbcRsaKeyBlob->cbModulus);
    BID_BAIL_ON_ERROR(err);

    pbbcRsaKeyBlob += pbcRsaKeyBlob->cbModulus;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "p",
                                       pbbcRsaKeyBlob,
                                       pbcRsaKeyBlob->cbPrime1);
    BID_BAIL_ON_ERROR(err);

    pbbcRsaKeyBlob += pbcRsaKeyBlob->cbPrime1;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "q",
                                       pbbcRsaKeyBlob,
                                       pbcRsaKeyBlob->cbPrime2);
    BID_BAIL_ON_ERROR(err);

    pbbcRsaKeyBlob += pbcRsaKeyBlob->cbPrime2;

cleanup:
    return err;
}

BIDError
_BIDLoadX509DsaPrivateKey(
    BIDContext context,
    PUCHAR pbbcKeyBlob,
    DWORD cbbcKeyBlob,
    BIDJWK privateKey)
{
    BIDError err;
    PBCRYPT_DSA_KEY_BLOB pbcDsaKeyBlob = (PBCRYPT_DSA_KEY_BLOB)pbbcKeyBlob;
    PUCHAR pbbcDsaKeyBlob = (PUCHAR)(pbcDsaKeyBlob + 1);

    BID_ASSERT(pbcDsaKeyBlob->dwMagic == BCRYPT_DSA_PRIVATE_MAGIC);

    if (cbbcKeyBlob < (pbbcDsaKeyBlob - pbbcKeyBlob) +
                      (3 * pbcDsaKeyBlob->cbKey) + 20) {
        err = BID_S_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, privateKey, "algorithm",
                            json_string("DS"), BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "q",
                                       pbcDsaKeyBlob->q, 20);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "p",
                                       pbbcDsaKeyBlob, pbcDsaKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    pbbcDsaKeyBlob += pbcDsaKeyBlob->cbKey;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "g",
                                       pbbcDsaKeyBlob, pbcDsaKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    pbbcDsaKeyBlob += pbcDsaKeyBlob->cbKey;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "y",
                                       pbbcDsaKeyBlob, pbcDsaKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    pbbcDsaKeyBlob += pbcDsaKeyBlob->cbKey;

    err = _BIDJsonObjectSetBinaryValue(context, privateKey, "x",
                                       pbbcDsaKeyBlob, 20);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDLoadX509PrivateKey(
    BIDContext context,
    const char *szPrivateKey,
    const char *szCertificate,
    BIDJWK *pPrivateKey)
{
    BIDError err;
    SECURITY_STATUS ss;
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    PWSTR wszKeyName = NULL;
    BCRYPT_KEY_BLOB *pbcKeyBlob = NULL;
    DWORD cbbcKeyBlob = 0;
    BIDJWK privateKey = NULL;
    DWORD dwFlags = 0, dwKeySpec;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fCallerFreeKey = FALSE;

    *pPrivateKey = NULL;

    /*
     * Because private keys are referenced by an opaque key ID, consumers
     * of this library may prefer to provide the certificate name instead
     * and have us dereference the private key using the CACPK API below.
     */
    if (szPrivateKey != NULL) {
        if (context->ContextOptions & BID_CONTEXT_RP)
            dwFlags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;

        ss = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);
        BID_BAIL_ON_ERROR((err = _BIDSecStatusToBIDError(ss)));

        err = _BIDUtf8ToUcs2(context, szPrivateKey, &wszKeyName);
        BID_BAIL_ON_ERROR(err);

        ss = NCryptOpenKey(hProvider, &hKey, wszKeyName,
                           AT_KEYEXCHANGE, dwFlags);
        if (ss == NTE_NO_KEY) {
            ss = NCryptOpenKey(hProvider, &hKey, wszKeyName,
                               AT_SIGNATURE, dwFlags);
        }
        BID_BAIL_ON_ERROR((err = _BIDSecStatusToBIDError(ss)));

        fCallerFreeKey = TRUE;
    } else {
        dwFlags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
        if (context->ContextOptions & BID_CONTEXT_RP)
            dwFlags |= CRYPT_ACQUIRE_SILENT_FLAG;

        err = _BIDLoadCertificateFromStore(context, szCertificate,
                                           &hCertStore, &pCertContext);
        BID_BAIL_ON_ERROR(err);

        if (!CryptAcquireCertificatePrivateKey(pCertContext, dwFlags,
                                               NULL, &hKey, &dwKeySpec,
                                               &fCallerFreeKey)) {
            err = BID_S_CRYPTO_ERROR;
            goto cleanup;
        }
    }

    dwFlags = 0;
    if (context->ContextOptions & BID_CONTEXT_RP)
        dwFlags |= NCRYPT_SILENT_FLAG;

    ss = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, NULL,
                         NULL, 0, &cbbcKeyBlob, dwFlags);
    BID_BAIL_ON_ERROR((err = _BIDSecStatusToBIDError(ss)));

    pbcKeyBlob = BIDMalloc(cbbcKeyBlob);
    if (pbcKeyBlob == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    ss = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, NULL,
                         (PBYTE)pbcKeyBlob, cbbcKeyBlob, &cbbcKeyBlob,
                         dwFlags);
    BID_BAIL_ON_ERROR((err = _BIDSecStatusToBIDError(ss)));

    privateKey = json_object();
    if (privateKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, privateKey, "version",
                            json_string("2012.08.15"),
                            BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    switch (pbcKeyBlob->Magic) {
    case BCRYPT_RSAPRIVATE_MAGIC:
        err = _BIDLoadX509RsaPrivateKey(context, (PUCHAR)pbcKeyBlob,
                                        cbbcKeyBlob, privateKey);
        break;
    case BCRYPT_DSA_PRIVATE_MAGIC:
        err = _BIDLoadX509DsaPrivateKey(context, (PUCHAR)pbcKeyBlob,
                                        cbbcKeyBlob, privateKey);
        break;
    default:
        err = BID_S_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    *pPrivateKey = privateKey;

cleanup:
    if (pbcKeyBlob != NULL) {
        SecureZeroMemory(pbcKeyBlob, cbbcKeyBlob);
        BIDFree(pbcKeyBlob);
    }
    if (hProvider)
        NCryptFreeObject(hProvider);
    if (fCallerFreeKey)
        NCryptFreeObject(hKey);
    if (err != BID_S_OK)
        CertCloseStore(hCertStore, 0);
    if (err != BID_S_OK)
        json_decref(privateKey);
    BIDFree(wszKeyName);

    return err;
}

BIDError
_BIDLoadX509Certificate(
    BIDContext context,
    const char *path,
    json_t **pCert)
{
    BIDError err;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    LPSTR szCertificate = NULL;
    SIZE_T cchCertificate = 0;
    json_t *cert = NULL;

    *pCert = NULL;

    err = _BIDLoadCertificateFromStore(context, path,
                                       &hCertStore, &pCertContext);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64Encode(pCertContext->pbCertEncoded,
                           pCertContext->cbCertEncoded,
                           BID_ENCODING_BASE64,
                           &szCertificate, &cchCertificate);
    BID_BAIL_ON_ERROR(err);

    cert = json_string(szCertificate);
    if (cert == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    *pCert = cert;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK)
        json_decref(cert);
    BIDFree(szCertificate);

    return err;
}

static BIDError
_BIDGetCertNameString(
    BIDContext context,
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    DWORD dwFlags,
    json_t **pValue)
{
    BIDError err;
    PWSTR wszNameString = NULL;
    char *szNameString = NULL;
    DWORD cchNameString = 0;
    DWORD dwNameToStrFlags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    void *pvTypePara = NULL;

    *pValue = NULL;

    if (dwType == CERT_NAME_RDN_TYPE)
        pvTypePara = &dwNameToStrFlags;

    cchNameString = CertGetNameStringW(pCertContext, dwType, dwFlags,
                                       pvTypePara, NULL, 0);
    if (cchNameString <= 1) {
        err = (dwFlags & CERT_NAME_ISSUER_FLAG)
            ? BID_S_MISSING_ISSUER : BID_S_BAD_SUBJECT;
        goto cleanup;
    }

    wszNameString = BIDMalloc(cchNameString * sizeof(WCHAR));
    if (wszNameString == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    CertGetNameStringW(pCertContext, dwType, dwFlags,
                       pvTypePara, wszNameString, cchNameString);

    err = _BIDUcs2ToUtf8(context, wszNameString, &szNameString);
    BID_BAIL_ON_ERROR(err);

    *pValue = json_string(szNameString);

    if (*pValue == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    BIDFree(wszNameString);
    BIDFree(szNameString);

    return err;
}

static BIDError
_BIDSetJsonCertNameString(
    BIDContext context,
    json_t *dict,
    const char *key,
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    DWORD dwFlags)
{
    BIDError err;
    json_t *name;

    err = _BIDGetCertNameString(context, pCertContext, dwType, dwFlags, &name);
    if (err != BID_S_OK)
        return err;

    err = _BIDJsonObjectSet(context, dict, key, name,
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    if (err != BID_S_OK)
        return err;

    return BID_S_OK;
}

static BIDError
_BIDGetCertOtherName(
    BIDContext context,
    PCERT_OTHER_NAME pOtherName,
    json_t **pJsonOtherName)
{
    BIDError err;
    PCERT_NAME_VALUE pNameValue = NULL;
    DWORD cbStructInfo;
    json_t *jsonOtherName = NULL;

    *pJsonOtherName = NULL;

    jsonOtherName = json_object();
    if (jsonOtherName == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, jsonOtherName, "oid",
                            json_string(pOtherName->pszObjId),
                            BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             X509_UNICODE_NAME_VALUE,
                             pOtherName->Value.pbData,
                             pOtherName->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
                             NULL,
                             (PVOID)&pNameValue,
                             &cbStructInfo)) {
        err = BID_S_BAD_SUBJECT;
        goto cleanup;
    }

    if (pNameValue->Value.pbData == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    switch (pNameValue->dwValueType) {
    case CERT_RDN_IA5_STRING:
    case CERT_RDN_UTF8_STRING:
    case CERT_RDN_NUMERIC_STRING:
    case CERT_RDN_PRINTABLE_STRING:
    case CERT_RDN_T61_STRING:
    case CERT_RDN_VISIBLE_STRING:
        err = _BIDJsonObjectSet(context, jsonOtherName, "value",
                                json_string((LPSTR)pNameValue->Value.pbData),
                                BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
        break;
    default:
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
        break;
    }

    *pJsonOtherName = jsonOtherName;

    err = BID_S_OK;

cleanup:
    LocalFree(pNameValue);
    if (err != BID_S_OK)
        json_decref(jsonOtherName);

    return err;
}

static BIDError
_BIDGetCertAltNames(
    BIDContext context,
    PCCERT_CONTEXT pCertContext,
    json_t **pPrincipal)
{
    BIDError err;
    PCERT_EXTENSION pCertExtension = NULL;
    PCERT_ALT_NAME_INFO pCertAltNameInfo = NULL;
    DWORD i, cbStructInfo;
    json_t *principal = NULL;

    *pPrincipal = NULL;

    principal = json_object();
    if (principal == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    pCertExtension = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                                       pCertContext->pCertInfo->cExtension,
                                       pCertContext->pCertInfo->rgExtension);
    if (pCertExtension == NULL) {
        err = BID_S_MISSING_PRINCIPAL;
        goto cleanup;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             szOID_SUBJECT_ALT_NAME2,
                             pCertExtension->Value.pbData,
                             pCertExtension->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
                             NULL,
                             (PVOID)&pCertAltNameInfo,
                             &cbStructInfo)) {
        err = BID_S_BAD_SUBJECT;
        goto cleanup;
    }

    for (i = 0; i < pCertAltNameInfo->cAltEntry; i++) {
        PCERT_ALT_NAME_ENTRY pCertAltNameEntry = &pCertAltNameInfo->rgAltEntry[i];
        const char *szKey = NULL;
        json_t *values = NULL;
        json_t *value = NULL;

        switch (pCertAltNameEntry->dwAltNameChoice) {
        case CERT_ALT_NAME_OTHER_NAME:
            szKey = "othername";
            break;
        case CERT_ALT_NAME_RFC822_NAME:
            szKey = "email";
            break;
        case CERT_ALT_NAME_DNS_NAME:
            szKey = "hostname";
            break;
        case CERT_ALT_NAME_URL:
            szKey = "uri";
            break;
        default:
            continue;
        }

        values = json_object_get(principal, szKey);
        if (values == NULL) {
            values = json_array();

            err = _BIDJsonObjectSet(context, principal, szKey, values,
                                    BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
            BID_BAIL_ON_ERROR(err);
        }

        if (strcmp(szKey, "othername") == 0) {
            err = _BIDGetCertOtherName(context, pCertAltNameEntry->pOtherName, &value);
            BID_BAIL_ON_ERROR(err);
        } else {
            char *szName = NULL;

            err = _BIDUcs2ToUtf8(context, pCertAltNameEntry->pwszRfc822Name, &szName);
            BID_BAIL_ON_ERROR(err);

            value = json_string(szName);

            BIDFree(szName);
        }

        json_array_append_new(values, value);
    }

    *pPrincipal = principal;
    err = BID_S_OK;

cleanup:
    LocalFree(pCertAltNameInfo);
    if (err != BID_S_OK)
        json_decref(principal);

    return err;
}

static BIDError
_BIDGetCertEKUs(
    BIDContext context BID_UNUSED,
    PCCERT_CONTEXT pCertContext,
    json_t **pEku)
{
    BIDError err;
    PCERT_ENHKEY_USAGE pCertEnhkeyUsage = NULL;
    DWORD i, cbCertEnhkeyUsage;
    json_t *eku = NULL;

    *pEku = NULL;

    if (!CertGetEnhancedKeyUsage(pCertContext, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                 NULL, &cbCertEnhkeyUsage)) {
        err = BID_S_OK; /* no EKU */
        goto cleanup;
    }

    eku = BIDMalloc(cbCertEnhkeyUsage);
    if (eku == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (!CertGetEnhancedKeyUsage(pCertContext, CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                 pCertEnhkeyUsage, &cbCertEnhkeyUsage)) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    eku = json_array();
    if (eku == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 0; i < pCertEnhkeyUsage->cUsageIdentifier; i++)
        json_array_append_new(eku, json_string(pCertEnhkeyUsage->rgpszUsageIdentifier[i]));

    *pEku = eku;
    err = BID_S_OK;

cleanup:
    BIDFree(pCertEnhkeyUsage);
    if (err != BID_S_OK)
        json_decref(eku);

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
    json_t *certChain = NULL;
    json_t *principal = NULL;
    json_t *eku = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    DWORD dwSubjectType;

    certChain = json_object_get(backedAssertion->Assertion->Header, "x5c");

    err = _BIDCertDataToContext(context, certChain, &pCertContext);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCertAltNames(context, pCertContext, &principal);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "principal",
                            principal, 0);
    BID_BAIL_ON_ERROR(err);

    if (ulReqFlags & BID_VERIFY_FLAG_RP)
        dwSubjectType = CERT_NAME_ATTR_TYPE;
    else
        dwSubjectType = CERT_NAME_RDN_TYPE;

    err = _BIDSetJsonCertNameString(context, identity->Attributes, "sub",
                                    pCertContext, dwSubjectType, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonCertNameString(context, identity->Attributes, "iss",
                                    pCertContext, CERT_NAME_RDN_TYPE,
                                    CERT_NAME_ISSUER_FLAG);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonFileTimeValue(context, identity->Attributes, "nbf",
                                   &pCertContext->pCertInfo->NotBefore);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetJsonFileTimeValue(context, identity->Attributes, "exp",
                                   &pCertContext->pCertInfo->NotAfter);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCertEKUs(context, pCertContext, &eku);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "eku", eku, 0);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (pCertContext != NULL)
        CertFreeCertificateContext(pCertContext);
    json_decref(principal);
    json_decref(eku);

    return err;
}

BIDError
_BIDValidateX509CertHash(
    BIDContext context,
    json_t *certParams,
    PCCERT_CONTEXT pCertContext)
{
    BIDError err;
    PBYTE pbAssertedHash = NULL;
    BYTE pbServerHash[32];
    SIZE_T cbAssertedHash = 0;
    DWORD cbServerHash = sizeof(pbServerHash);

    err = _BIDGetJsonBinaryValue(context, certParams, "x5t",
                                 &pbAssertedHash, &cbAssertedHash);
    BID_BAIL_ON_ERROR(err);

    if (!CryptHashCertificate((HCRYPTPROV_LEGACY)0,
                              CALG_SHA_256,
                              0,
                              pCertContext->pbCertEncoded,
                              pCertContext->cbCertEncoded,
                              pbServerHash,
                              &cbServerHash)) {
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    if (cbAssertedHash != cbServerHash ||
        memcmp(pbAssertedHash, pbServerHash, cbServerHash) != 0) {
        err = BID_S_UNTRUSTED_X509_CERT;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    BIDFree(pbAssertedHash);
    BIDFree(pbServerHash);

    return err;
}

static BIDError
_BIDCertStringToName(
    BIDContext context,
    const char *szName,
    PCERT_NAME_BLOB pCertNameBlob)
{
    BIDError err;
    PWSTR wszName = NULL;

    pCertNameBlob->pbData = NULL;
    pCertNameBlob->cbData = 0;

    err = _BIDUtf8ToUcs2(context, szName, &wszName);
    BID_BAIL_ON_ERROR(err);

    if (!CertStrToNameW(X509_ASN_ENCODING,
                        wszName,
                        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                        NULL,
                        NULL,
                        &pCertNameBlob->cbData,
                        NULL)) {
        err = BID_S_BAD_SUBJECT;
        goto cleanup;
    }

    pCertNameBlob->pbData = BIDMalloc(pCertNameBlob->cbData);
    if (pCertNameBlob->pbData == NULL) {
        err =  BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (!CertStrToNameW(X509_ASN_ENCODING,
                        wszName,
                        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                        NULL,
                        pCertNameBlob->pbData,
                        &pCertNameBlob->cbData,
                        NULL)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    BIDFree(wszName);

    return err;
}

BIDError
_BIDValidateX509CertSubject(
    BIDContext context,
    json_t *certParams,
    PCCERT_CONTEXT pCertContext)
{
    BIDError err;
    CERT_NAME_BLOB cnbSubjectConstraint = { 0 };
    const char *serverSubjectMatch;

    serverSubjectMatch = json_string_value(json_object_get(certParams,
                                                           "sub"));
    if (serverSubjectMatch == NULL)
        return BID_S_OK;

    err = _BIDCertStringToName(context, serverSubjectMatch,
                               &cnbSubjectConstraint);
    if (err != BID_S_OK)
        return err;

    if (CertCompareCertificateName(X509_ASN_ENCODING,
                                   &pCertContext->pCertInfo->Subject,
                                   &cnbSubjectConstraint)) {
        err = BID_S_OK;
    } else {
        err = BID_S_UNTRUSTED_X509_CERT;
    }

    BIDFree(cnbSubjectConstraint.pbData);

    return err;
}

BIDError
_BIDValidateX509CertAltSubject(
    BIDContext context,
    json_t *certParams,
    PCCERT_CONTEXT pCertContext)
{
    BIDError err;
    json_t *altSubjectConstraints = NULL;
    json_t *certNames = NULL;
    DWORD i, found = 0;
    void *iter;

    altSubjectConstraints = json_object_get(certParams, "san");
    if (altSubjectConstraints == NULL)
        return BID_S_OK;

    err = _BIDGetCertAltNames(context, pCertContext, &certNames);
    if (err != BID_S_OK)
        return BID_S_UNTRUSTED_X509_CERT;

    for (iter = json_object_iter(altSubjectConstraints);
         iter != NULL;
         iter = json_object_iter_next(altSubjectConstraints, iter)) {
        json_t *sans;

        /* Find all SANs in the certificate that match this constraint */
        sans = json_object_get(certNames, json_object_iter_key(iter));
        if (sans == NULL)
            continue;

        /* If one SAN value matches, return OK */
        for (i = 0; i < json_array_size(sans); i++) {
            json_t *san = json_array_get(sans, i);

            if (json_equal(san, json_object_iter_value(iter))) {
                found++;
                break;
            }
        }

        if (found)
            break;
    }

    json_decref(certNames);

    return (found == 0) ? BID_S_UNTRUSTED_X509_CERT : BID_S_OK;
}

static BIDError
_BIDGetSupportingCertificateStore(
    BIDContext context,
    json_t *certChain,
    HCERTSTORE *phCertStore)
{
    BIDError err = BID_S_OK;
    HCERTSTORE hCertStore = NULL;
    DWORD i;

    *phCertStore = NULL;

    hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                               X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                               (HCRYPTPROV_LEGACY)0,
                               CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
                               NULL);
    if (hCertStore == NULL) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

    for (i = 1; err == BID_S_OK && i < json_array_size(certChain); i++) {
        const char *szCert;
        PBYTE pbCert;
        SIZE_T cbCert;

        szCert = json_string_value(json_array_get(certChain, i));
        if (szCert == NULL) {
            err = BID_S_MISSING_CERT;
            goto cleanup;
        }

        err = _BIDBase64UrlDecode(szCert, &pbCert, &cbCert);
        BID_BAIL_ON_ERROR(err);

        err = CertAddEncodedCertificateToStore(hCertStore,
                                               X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                               pbCert,
                                               cbCert,
                                               CERT_STORE_ADD_ALWAYS,
                                               NULL)
             ? BID_S_OK : BID_S_CRYPTO_ERROR;

        BIDFree(pbCert);
    }
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *phCertStore = hCertStore;
    hCertStore = NULL;

cleanup:
    if (err != BID_S_OK)
        CertCloseStore(hCertStore, 0);

    return err;
}

BIDError
_BIDValidateX509CertChain(
    BIDContext context,
    json_t *certChain,
    json_t *certParams,
    time_t verificationTime)
{
    BIDError err;
    PCERT_CONTEXT pCertContext = NULL;
    PCCERT_CHAIN_CONTEXT pCertChainContext = NULL;
    CERT_CHAIN_PARA certChainPara = { 0 };
    CERT_CHAIN_POLICY_PARA certChainPolicyPara = { 0 };
    CERT_CHAIN_POLICY_STATUS certChainPolicyStatus = { 0 };
#if 0
    LPSTR rgszUsages[] = {
        szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE
    };
#endif
    DWORD dwFlags = 0;
    FILETIME ftVerify;
    BOOLEAN bServerCertOnly;
    HCERTSTORE hCertStore = NULL;

    err = _BIDCertDataToContext(context, certChain, &pCertContext);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetSupportingCertificateStore(context, certChain, &hCertStore);
    BID_BAIL_ON_ERROR(err);

    bServerCertOnly = !!(json_object_get(certParams, "x5t"));

    err = _BIDSecondsSince1970ToTime(context, verificationTime, &ftVerify);
    BID_BAIL_ON_ERROR(err);

    if (bServerCertOnly) {
        err = _BIDValidateX509CertHash(context, certParams, pCertContext);
        BID_BAIL_ON_ERROR(err);
    }

#if 0
    certChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    certChainPara.RequestedUsage.Usage.cUsageIdentifier = ARRAYSIZE(rgszUsages);
    certChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;
#endif

    dwFlags = CERT_CHAIN_ENABLE_PEER_TRUST;
    if (bServerCertOnly)
        dwFlags |= CERT_CHAIN_REVOCATION_CHECK_END_CERT;
    else
        dwFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;

    if (!CertGetCertificateChain(HCCE_CURRENT_USER,
                                 pCertContext,
                                 &ftVerify,
                                 hCertStore,
                                 &certChainPara,
                                 dwFlags,
                                 NULL,
                                 &pCertChainContext)) {
        err = BID_S_CERT_FILE_UNREADABLE;
        goto cleanup;
    }

    if (!bServerCertOnly &&
        !CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
                                          pCertChainContext,
                                          &certChainPolicyPara,
                                          &certChainPolicyStatus) ||
        certChainPolicyStatus.dwError != ERROR_SUCCESS) {
        err = BID_S_UNTRUSTED_X509_CERT;
        goto cleanup;
    }

    err = _BIDValidateX509CertSubject(context, certParams, pCertContext);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateX509CertAltSubject(context, certParams, pCertContext);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (pCertContext != NULL)
        CertFreeCertificateContext(pCertContext);
    if (pCertChainContext != NULL)
        CertFreeCertificateChain(pCertChainContext);
    if (hCertStore != NULL)
        CertCloseStore(hCertStore, 0);

    return err;
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
        secretHandle->SecretData.SecretAgreement =
            keyInput->SecretData.SecretAgreement;
        keyInput->SecretData.SecretAgreement = NULL;
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
        nts = BCryptDestroySecret(secretHandle->SecretData.SecretAgreement);
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

BIDError
_BIDGenerateECDHKey(
    BIDContext context,
    json_t *ecDhParams,
    BIDJWK *pEcDhKey)
{
    BIDError err;
    NTSTATUS nts;
    json_t *ecDhKey = NULL;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ECCKEY_BLOB *ecDhKeyBlob = NULL;
    DWORD cbEcDhKeyBlob = 0;
    PUCHAR pbEcDhKeyBlob;
    LPCWSTR wszAlgID;

    err = _BIDMapECDHAlgorithmID(context, ecDhParams, &wszAlgID);
    BID_BAIL_ON_ERROR(err);

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, wszAlgID, NULL, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptGenerateKeyPair(hAlgorithm, &hKey, context->ECDHCurve, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptFinalizeKeyPair(hKey, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    nts = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                          NULL, 0, &cbEcDhKeyBlob, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    ecDhKeyBlob = BIDMalloc(cbEcDhKeyBlob);
    if (ecDhKeyBlob == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    nts = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                          (PUCHAR)ecDhKeyBlob, cbEcDhKeyBlob, &cbEcDhKeyBlob, 0);
    BID_BAIL_ON_ERROR((err = _BIDNtStatusToBIDError(nts)));

    if (cbEcDhKeyBlob < sizeof(*ecDhKeyBlob) + 3 * ecDhKeyBlob->cbKey) {
        err = BID_S_INVALID_KEY;
        goto cleanup;
    }

    ecDhKey = json_object();
    if (ecDhKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, ecDhKey, "params", ecDhParams,
                            BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    pbEcDhKeyBlob = (PUCHAR)(ecDhKeyBlob + 1);

    /* Layout is ECCKEY_KEY_BLOB || x || y || d */
    /*                              0    1    2 */
    err = _BIDJsonObjectSetBinaryValue(context,
                                       ecDhKey,
                                       "x",
                                       &pbEcDhKeyBlob[0 * ecDhKeyBlob->cbKey],
                                       ecDhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context,
                                       ecDhKey,
                                       "y",
                                       &pbEcDhKeyBlob[1 * ecDhKeyBlob->cbKey],
                                       ecDhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSetBinaryValue(context,
                                       ecDhKey,
                                       "d",
                                       &pbEcDhKeyBlob[2 * ecDhKeyBlob->cbKey],
                                       ecDhKeyBlob->cbKey);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pEcDhKey = ecDhKey;

cleanup:
    if (err != BID_S_OK)
        json_decref(ecDhKey);
    if (hAlgorithm != NULL)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey != NULL)
        BCryptDestroyKey(hKey);
    if (ecDhKeyBlob != NULL) {
        SecureZeroMemory(ecDhKeyBlob, cbEcDhKeyBlob);
        BIDFree(ecDhKeyBlob);
    }

    return err;
}
