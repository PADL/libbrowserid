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

BIDError
_BIDValidateJWTHeader(
    BIDContext context BID_UNUSED,
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
        } else if (strcmp(key, "alg") == 0 ||
                   strcmp(key, "x5c") == 0 ||
                   strncmp(key, "x5t", 3) == 0)
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

    if (strlen(szJwt) == 0) {
        err = BID_S_OK;
        goto cleanup;
    }

    err = _BIDDuplicateString(context, szJwt, &jwt->EncData);
    BID_BAIL_ON_ERROR(err);

    szHeader = jwt->EncData;

    szPayload = strchr(szHeader, '.');
    if (szPayload == NULL) {
        err = BID_S_INVALID_JSON_WEB_TOKEN;
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

    err = _BIDValidateJWTHeader(context, jwt->Header);
    BID_BAIL_ON_ERROR(err);

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
    json_t *certChain,
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

    err = _BIDJsonObjectSet(context, jwt->Header, "alg",
                            json_string(alg ? alg->szAlgID : "none"),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (certChain != NULL) {
        err = _BIDJsonObjectSet(context, jwt->Header, "x5c", certChain, BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
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

    if (jwt->SignatureLength == 0) {
        err = BID_S_MISSING_SIGNATURE;
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
    BIDContext context BID_UNUSED,
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

