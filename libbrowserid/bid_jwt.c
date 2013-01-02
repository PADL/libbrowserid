/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

/*
 * Implementation of JSON Web Tokens. Note that this is not a generalised
 * implementation; it does not support encryption (JWE) and it requires
 * that the payload be valid JSON. It's enough to support BrowserID.
 */

static int
_BIDKeyMatchesP(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWK jwk)
{
    const char *alg;
    size_t keySize;
    int isSecretKey;

    if (jwk == NULL)
        return 0;

    isSecretKey = (json_object_get(jwk, "secret-key") != NULL);

    if (isSecretKey) {
        alg = "HS";
    } else {
        alg = json_string_value(json_object_get(jwk, "algorithm"));
        if (alg == NULL)
            alg = json_string_value(json_object_get(jwk, "alg"));
    }

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

    if (keyset == NULL)
        return BID_S_INVALID_KEYSET;

    keys = json_object_get(keyset, "keys");
    if (keys == NULL) {
        BIDJWK jwk = json_object_get(keyset, "public-key");

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

        err = _BIDFindKeyInKeyset(context, algorithm, jwk, pKey);
        if (err == BID_S_OK)
            break;
    }

    return err;
}

BIDError
_BIDValidateJWTHeader(
    BIDContext context,
    json_t *header)
{
    void *iter;

    if (!json_is_object(header))
        return BID_S_INVALID_JSON_WEB_TOKEN;

    /*
     * According to draft-ietf-oauth-json-web-token, implementations MUST
     * understand the entire contents of the header; otherwise, the JWT
     * MUST be rejected for processing.
     */
    for (iter = json_object_iter(header);
         iter != NULL;
         iter = json_object_iter_next(header, iter)) {
        const char *key = json_object_iter_key(iter);

        if (strcmp(key, "typ") == 0) {
            const char *typ = json_string_value(json_object_iter_value(iter));

            if (typ == NULL)
                return BID_S_INVALID_JSON_WEB_TOKEN;

            if (strcmp(typ, "JWT") != 0 &&
                strcmp(typ, "urn:ietf:params:oauth:token-type:jwt") != 0)
                return BID_S_INVALID_JSON_WEB_TOKEN;
        } else if (strcmp(key, "alg") == 0)
            continue;
        else
            return BID_S_INVALID_JSON_WEB_TOKEN;
    }

    return BID_S_OK;
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

    err = _BIDDecodeJson(context, szHeader, BID_JSON_ENCODING_BASE64, &jwt->Header);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateJWTHeader(context, jwt->Header);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDecodeJson(context, szPayload, BID_JSON_ENCODING_BASE64, &jwt->Payload);
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

    err = _BIDEncodeJson(context, jwt->Header, BID_JSON_ENCODING_BASE64, &szEncodedHeader, &cchEncodedHeader);
    BID_BAIL_ON_ERROR(err);

    err = _BIDEncodeJson(context, jwt->Payload, BID_JSON_ENCODING_BASE64, &szEncodedPayload, &cchEncodedPayload);
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
    size_t cchEncSignature = 0;

    *pszJwt = NULL;
    *pcchJwt = 0;

    BID_CONTEXT_VALIDATE(context);

    err = BID_S_UNKNOWN_ALGORITHM;

    if (keyset != NULL) {
        for (i = 0; _BIDJWTAlgorithms[i].szAlgID != NULL; i++) {
            alg = &_BIDJWTAlgorithms[i];

            err = _BIDFindKeyInKeyset(context, alg, keyset, &key);
            if (err == BID_S_OK)
                break;
        }
        BID_BAIL_ON_ERROR(err);
    }

    if (jwt->Header == NULL) {
        jwt->Header = json_object();
        if (jwt->Header == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    if (json_object_set_new(jwt->Header, "alg", json_string(alg ? alg->szAlgID : "none")) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDMakeSignatureData(context, jwt);
    BID_BAIL_ON_ERROR(err);

    jwt->Signature = NULL;
    jwt->SignatureLength = 0;

    if (key != NULL) {
        err = alg->MakeSignature(alg, context, jwt, key);
        BID_BAIL_ON_ERROR(err);

        err = _BIDBase64UrlEncode(jwt->Signature, jwt->SignatureLength, &szEncSignature, &cchEncSignature);
        BID_BAIL_ON_ERROR(err);
    }

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
    if (szEncSignature != NULL) {
        memcpy(p, szEncSignature, cchEncSignature);
        p += cchEncSignature;
    }
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
    BIDJWTAlgorithm alg = NULL;
    int bSignatureValid;

    BID_CONTEXT_VALIDATE(context);

    if (jwt == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    sigAlg = json_string_value(json_object_get(jwt->Header, "alg"));
    if (sigAlg == NULL) {
        err = BID_S_MISSING_ALGORITHM;
        goto cleanup;
    }

    err = BID_S_UNKNOWN_ALGORITHM;

    for (i = 0; _BIDJWTAlgorithms[i].szAlgID != NULL; i++) {
        alg = &_BIDJWTAlgorithms[i];

        if (strcmp(alg->szAlgID, sigAlg) == 0) {
            err = _BIDFindKeyInKeyset(context, alg, keyset, &key);
            if (err == BID_S_OK)
                break;
        }
    }

    BID_BAIL_ON_ERROR(err);

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
_BIDReleaseJWTInternal(
    BIDContext context,
    BIDJWT jwt,
    int freeit)
{
    if (jwt == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(jwt->EncData);
    json_decref(jwt->Header);
    json_decref(jwt->Payload);
    BIDFree(jwt->Signature);

    if (freeit)
        BIDFree(jwt);

    return BID_S_OK;
}

BIDError
_BIDReleaseJWT(
    BIDContext context,
    BIDJWT jwt)
{
    return _BIDReleaseJWTInternal(context, jwt, 1);
}

int
_BIDIsLegacyJWK(BIDContext context, BIDJWK jwk)
{
    const char *version = json_string_value(json_object_get(jwk, "version"));

    return (version == NULL || strcmp(version, "2012.08.15") != 0);
}

static BIDError
_BIDMakeJsonWebKey(
    BIDContext context,
    const unsigned char *pbKey,
    size_t cbKey,
    BIDJWK *key)
{
    BIDError err;
    json_t *sk = NULL;

    *key = NULL;

    err = _BIDJsonBinaryValue(context, pbKey, cbKey, &sk);
    if (err != BID_S_OK)
        return err;

    *key = json_object();
    if (*key == NULL)
        return BID_S_NO_MEMORY;

    json_object_set(*key, "secret-key", sk);

    return BID_S_OK;
}

BIDError
BIDMakeJsonWebToken(
    BIDContext context,
    json_t *Payload,
    const unsigned char *pbKey,
    size_t cbKey,
    char **pbJwt,
    size_t *pchJwt)
{
    BIDError err;
    struct BIDJWTDesc jwt;
    BIDJWK key = NULL;

    *pbJwt = NULL;
    *pchJwt = 0;

    jwt.EncData = NULL;
    jwt.EncDataLength = 0;
    jwt.Header = NULL;
    jwt.Payload = json_incref(Payload);
    jwt.Signature = NULL;
    jwt.SignatureLength = 0;

    if (pbKey != NULL) {
        err = _BIDMakeJsonWebKey(context, pbKey, cbKey, &key);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDMakeSignature(context, &jwt, key, pbJwt, pchJwt);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(key);
    _BIDReleaseJWTInternal(context, &jwt, 0);

    return err;
}

BIDError
BIDParseJsonWebToken(
    BIDContext context,
    const char *szJwt,
    BIDJWT *pJwt,
    json_t **pPayload)
{
    BIDError err;

    *pJwt = NULL;
    *pPayload = NULL;

    err = _BIDParseJWT(context, szJwt, pJwt);
    if (err == BID_S_OK)
        *pPayload = json_incref((*pJwt)->Payload);

    return err;
}

BIDError
BIDVerifyJsonWebToken(
    BIDContext context,
    BIDJWT jwt,
    const unsigned char *pbKey,
    size_t cbKey)
{
    BIDError err;
    BIDJWK key = NULL;

    if (pbKey != NULL) {
        err = _BIDMakeJsonWebKey(context, pbKey, cbKey, &key);
        BID_BAIL_ON_ERROR(err);

        err = _BIDVerifySignature(context, jwt, key);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    json_decref(key);

    return err;
}

BIDError
BIDReleaseJsonWebToken(
    BIDContext context,
    BIDJWT jwt)
{
    return _BIDReleaseJWT(context, jwt);
}
