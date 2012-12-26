/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

typedef struct BIDJWTAlgorithmDesc {
    const char *szAlgID;
    const char *szKeyAlgID;
    size_t cbKey;
    const unsigned char *pbOid;
    size_t cbOid;
    BIDError (*MakeSignature)(struct BIDJWTAlgorithmDesc *, BIDContext, BIDJWT, BIDJWK);
    BIDError (*VerifySignature)(struct BIDJWTAlgorithmDesc *, BIDContext, BIDJWT, BIDJWK, int *);
    BIDError (*KeySize)(struct BIDJWTAlgorithmDesc *desc, BIDContext, BIDJWK, size_t *);
} *BIDJWTAlgorithm;

#include "bid_openssl.c"

static struct BIDJWTAlgorithmDesc
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
};

static int
_BIDKeyMatchesP(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWK jwk)
{
    const char *alg;
    size_t keySize;

    if (jwk == NULL)
        return 0;

    alg = json_string_value(json_object_get(jwk, "algorithm"));
    if (alg == NULL)
        alg = json_string_value(json_object_get(jwk, "alg"));
    if (alg == NULL)
        return 0;

    if (strncmp(alg, algorithm->szKeyAlgID, 2) != 0)
        return 0;

    if (algorithm->cbKey) {
        if (algorithm->KeySize(algorithm, context, jwk, &keySize) != BID_S_OK)
            return 0;

        if (keySize != algorithm->cbKey)
            return 0;
    }

    return 1;
}

static BIDError
_BIDFindKeyInKeyset(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWKSet keyset,
    BIDJWK *pKey)
{
    BIDError err;
    json_t *keys;
    size_t i, cKeys;

    *pKey = NULL;

    keys = json_object_get(keyset, "keys");
    if (keys == NULL) {
        BIDJWK jwk = json_object_get(keyset, "public-key");

        if (jwk == NULL)
            jwk = json_object_get(keyset, "secret-key");

        if (jwk == NULL) /* try directly without container */
            jwk = keyset;

        if (_BIDKeyMatchesP(context, algorithm, jwk)) {
            *pKey = json_incref(jwk);
            return BID_S_OK;
        }

        return BID_S_INVALID_KEYSET;
    }

    cKeys = json_array_size(keys);
    for (i = 0, err = BID_S_NO_KEY; i < cKeys; i++) {
        BIDJWK jwk = json_array_get(keys, i);

        if (_BIDKeyMatchesP(context, algorithm, jwk)) {
            err = BID_S_OK;
            *pKey = json_incref(jwk);
            break;
        }
    }

    return err;
}

BIDError
_BIDParseJWT(
    BIDContext context,
    const char *szJwt,
    BIDJWT *pJwt)
{
    BIDJWT jwt = NULL;
    BIDError err;
    char *szHeader, *szPayload, *szSignature;
    size_t cbSignature;
    const char *typ;
    const char *cty;

    *pJwt = NULL;

    jwt = BIDCalloc(1, sizeof(*jwt));
    if (jwt == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDDuplicateString(context, szJwt, &jwt->EncData);
    BID_BAIL_ON_ERROR(err);

    szHeader = jwt->EncData;

    szPayload = strchr(szHeader, '.');
    if (szPayload == NULL) {
        err = BID_S_INVALID_SIGNATURE;
        goto cleanup;
    }
    *szPayload++ = '\0';

    szSignature = strchr(szPayload, '.');
    if (szSignature == NULL) {
        err = BID_S_INVALID_SIGNATURE;
        goto cleanup;
    }
    *szSignature++ = '\0';

    err = _BIDDecodeJson(context, szHeader, &jwt->Header);
    BID_BAIL_ON_ERROR(err);

    typ = json_string_value(json_object_get(jwt->Header, "typ"));
    if (typ != NULL &&
        !(strcmp(typ, "JWT") == 0 ||
          strcmp(typ, "urn:ietf:params:oauth:token-type:jwt") == 0)) {
        err = BID_S_INVALID_JSON_WEB_TOKEN;
        goto cleanup;
    }

    cty = json_string_value(json_object_get(jwt->Header, "cty"));
    if (cty != NULL) {
        err = BID_S_INVALID_JSON_WEB_TOKEN;
        goto cleanup;
    }

    /* XXX check for other header attributes we do not understand */

    err = _BIDDecodeJson(context, szPayload, &jwt->Payload);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(jwt->Signature == NULL);

    err = _BIDBase64UrlDecode(szSignature, &jwt->Signature, &cbSignature);
    BID_BAIL_ON_ERROR(err);

    *(--szPayload) = '.'; /* Restore Header.Payload for signature verification */

    jwt->SignatureLength = (size_t)cbSignature;
    jwt->EncDataLength = strlen(jwt->EncData);

    err = BID_S_OK;
    *pJwt = jwt;

cleanup:
    if (err != BID_S_OK)
        _BIDReleaseJWT(context, jwt);

    return err;
}

static BIDError
_BIDMakeSignatureData(
    BIDContext context,
    BIDJWT jwt)
{
    BIDError err;
    char *szEncodedHeader = NULL;
    char *szEncodedPayload = NULL;
    char *p;
    size_t cchEncodedHeader, cchEncodedPayload;

    if (jwt->EncData != NULL) {
        BIDFree(jwt->EncData);
        jwt->EncData = NULL;
        jwt->EncDataLength = 0;
    }

    err = _BIDEncodeJson(context, jwt->Header, &szEncodedHeader, &cchEncodedHeader);
    BID_BAIL_ON_ERROR(err);

    err = _BIDEncodeJson(context, jwt->Payload, &szEncodedPayload, &cchEncodedPayload);
    BID_BAIL_ON_ERROR(err);

    jwt->EncData = BIDMalloc(cchEncodedHeader + 1 + cchEncodedPayload + 1);
    if (jwt->EncData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    p = jwt->EncData;
    memcpy(p, szEncodedHeader, cchEncodedHeader);
    p += cchEncodedHeader;
    *p++ = '.';
    memcpy(p, szEncodedPayload, cchEncodedPayload);
    p += cchEncodedPayload;
    *p = '\0';

    jwt->EncDataLength = cchEncodedHeader + 1 + cchEncodedPayload;
    BID_ASSERT(p - jwt->EncData == jwt->EncDataLength);

cleanup:
    BIDFree(szEncodedHeader);
    BIDFree(szEncodedPayload);

    return err;
}

BIDError
_BIDMakeSignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset,
    char **pszJwt,
    size_t *pcchJwt)
{
    BIDError err;
    BIDJWK key = NULL;
    size_t i;
    BIDJWTAlgorithm alg = NULL;
    char *szEncSignature = NULL, *p;
    size_t cchEncSignature;

    *pszJwt = NULL;
    *pcchJwt = 0;

    BID_CONTEXT_VALIDATE(context);

    err = BID_S_UNKNOWN_ALGORITHM;

    for (i = 0; i < sizeof(_BIDJWTAlgorithms) / sizeof(_BIDJWTAlgorithms[0]); i++) {
        alg = &_BIDJWTAlgorithms[i];

        err = _BIDFindKeyInKeyset(context, alg, keyset, &key);
        if (err == BID_S_OK)
            break;
    }

    BID_BAIL_ON_ERROR(err);

    if (jwt->Header == NULL) {
        jwt->Header = json_object();
        if (jwt->Header == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    if (/*json_object_set_new(jwt->Header, "typ", json_string("JWT")) < 0 ||*/
        json_object_set_new(jwt->Header, "alg", json_string(alg->szAlgID)) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDMakeSignatureData(context, jwt);
    BID_BAIL_ON_ERROR(err);

    jwt->Signature = NULL;
    jwt->SignatureLength = 0;

    err = alg->MakeSignature(alg, context, jwt, key);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64UrlEncode(jwt->Signature, jwt->SignatureLength, &szEncSignature, &cchEncSignature);
    BID_BAIL_ON_ERROR(err);

    *pszJwt = BIDMalloc(jwt->EncDataLength + 1 + cchEncSignature + 1);
    if (*pszJwt == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    BID_ASSERT(jwt->EncDataLength == strlen(jwt->EncData));

    p = *pszJwt;
    memcpy(p, jwt->EncData, jwt->EncDataLength);
    p += jwt->EncDataLength;
    *p++ = '.';
    memcpy(p, szEncSignature, cchEncSignature);
    p += cchEncSignature;
    *p = '\0';

    *pcchJwt = jwt->EncDataLength + 1 + cchEncSignature;
    BID_ASSERT(p - *pszJwt == *pcchJwt);

    err = BID_S_OK;

cleanup:
    json_decref(key);
    BIDFree(szEncSignature);

    return err;
}

BIDError
_BIDVerifySignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset)
{
    BIDError err;
    BIDJWK key = NULL;
    size_t i;
    const char *sigAlg;
    const char *keyAlg;
    BIDJWTAlgorithm alg = NULL;
    int bSignatureValid;

    BID_CONTEXT_VALIDATE(context);

    sigAlg = json_string_value(json_object_get(jwt->Header, "alg"));
    if (sigAlg == NULL) {
        err = BID_S_MISSING_ALGORITHM;
        goto cleanup;
    }

    err = BID_S_UNKNOWN_ALGORITHM;

    for (i = 0; i < sizeof(_BIDJWTAlgorithms) / sizeof(_BIDJWTAlgorithms[0]); i++) {
        alg = &_BIDJWTAlgorithms[i];

        if (strcmp(alg->szAlgID, sigAlg) == 0) {
            err = _BIDFindKeyInKeyset(context, alg, keyset, &key);
            if (err == BID_S_OK)
                break;
        }
    }

    BID_BAIL_ON_ERROR(err);

    keyAlg = json_string_value(json_object_get(key, "algorithm"));
    if (keyAlg == NULL)
        keyAlg = json_string_value(json_object_get(key, "alg"));
    if (keyAlg == NULL) {
        err = BID_S_MISSING_ALGORITHM;
        goto cleanup;
    }

    bSignatureValid = 0;

    err = alg->VerifySignature(alg, context, jwt, key, &bSignatureValid);
    BID_BAIL_ON_ERROR(err);

    if (!bSignatureValid) {
        err = BID_S_INVALID_SIGNATURE;
        goto cleanup;
    }

cleanup:
    json_decref(key);

    return err;
}

BIDError
_BIDReleaseJWT(
    BIDContext context,
    BIDJWT jwt)
{
    if (jwt == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(jwt->EncData);
    json_decref(jwt->Header);
    json_decref(jwt->Payload);
    BIDFree(jwt->Signature);
    BIDFree(jwt);

    return BID_S_OK;
}

int
_BIDIsLegacyJWK(BIDContext context, BIDJWK jwk)
{
    const char *version = json_string_value(json_object_get(jwk, "version"));

    return (version == NULL || strcmp(version, "2012.08.15") != 0);
}
