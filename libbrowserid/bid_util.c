/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */
/*
 * Portions Copyright (c) 2009-2011 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "bid_private.h"

#include <gssapiP_bid.h> /* XXX */

BIDError
_BIDDuplicateString(
    BIDContext context,
    const char *szSrc,
    char **szDst)
{
    size_t cbSrc;

    if (szSrc == NULL)
        return BID_S_INVALID_PARAMETER;

    cbSrc = strlen(szSrc) + 1;

    *szDst = BIDMalloc(cbSrc);
    if (*szDst == NULL)
        return BID_S_NO_MEMORY;

    memcpy(*szDst, szSrc, cbSrc);
    return BID_S_OK;
}

BIDError
_BIDJsonBinaryValue(
    BIDContext context,
    const unsigned char *pbData,
    size_t cbData,
    json_t **pJson)
{
    BIDError err;
    char *szData;
    size_t len;
    json_t *json;

    *pJson = NULL;

    err = _BIDBase64UrlEncode(pbData, cbData, &szData, &len);
    if (err != BID_S_OK)
        return err;

    json = json_string(szData);
    if (json == NULL) {
        BIDFree(szData);
        return BID_S_NO_MEMORY;
    }

    *pJson = json;
    BIDFree(szData);

    return BID_S_OK;
}

BIDError
_BIDEncodeJson(
    BIDContext context,
    json_t *jData,
    uint32_t encoding,
    char **pEncodedJson,
    size_t *pEncodedJsonLen)
{
    BIDError err;
    char *szJson;
    size_t len;

    *pEncodedJson = NULL;

    szJson = json_dumps(jData, JSON_COMPACT);
    if (szJson == NULL)
        return BID_S_CANNOT_ENCODE_JSON;

    if (encoding == BID_JSON_ENCODING_BASE32)
        err = _BIDBase32UrlEncode((unsigned char *)szJson, strlen(szJson), pEncodedJson, &len);
    else
        err = _BIDBase64UrlEncode((unsigned char *)szJson, strlen(szJson), pEncodedJson, &len);
    if (err != BID_S_OK) {
        BIDFree(szJson);
        return err;
    }

    *pEncodedJsonLen = (size_t)len;

    BIDFree(szJson);

    return BID_S_OK;
}

BIDError
_BIDDecodeJson(
    BIDContext context,
    const char *encodedJson,
    uint32_t encoding,
    json_t **pjData)
{
    BIDError err;
    char *szJson = NULL;
    size_t cbJson;
    json_t *jData;

    *pjData = NULL;

    if (encoding == BID_JSON_ENCODING_BASE32)
        err = _BIDBase32UrlDecode(encodedJson, (unsigned char **)&szJson, &cbJson);
    else
        err = _BIDBase64UrlDecode(encodedJson, (unsigned char **)&szJson, &cbJson);
    if (err != BID_S_OK) {
        BIDFree(szJson);
        return err;
    }

    /* XXX check valid string first? */
    szJson[cbJson] = '\0';

    jData = json_loads(szJson, 0, &context->JsonError);
    if (jData == NULL) {
        BIDFree(szJson);
        return BID_S_INVALID_JSON;
    }

    BIDFree(szJson);
    *pjData = jData;

    return BID_S_OK;
}

BIDError
_BIDUnpackBackedAssertion(
    BIDContext context,
    const char *encodedJson,
    BIDBackedAssertion *pAssertion)
{
    BIDError err;
    char *tmp = NULL, *p;
    BIDBackedAssertion assertion = NULL;
    const char *aud = NULL;

    if (encodedJson == NULL) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    err = _BIDDuplicateString(context, encodedJson, &tmp);
    BID_BAIL_ON_ERROR(err);

    assertion = BIDCalloc(1, sizeof(*assertion));
    if (assertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (p = tmp; p != NULL; ) {
        char *q = strchr(p, '~');
        BIDJWT *pDst;

        if (q != NULL) {
            if (assertion->cCertificates >= BID_MAX_CERTS) {
                err = BID_S_TOO_MANY_CERTS;
                goto cleanup;
            }

            *q = '\0';
            q++;
            pDst = &assertion->rCertificates[assertion->cCertificates];
        } else {
            pDst = &assertion->Assertion;
        }

        err = _BIDParseJWT(context, p, pDst);
        BID_BAIL_ON_ERROR(err);

        if (*pDst != assertion->Assertion)
            assertion->cCertificates++;

        p = q;
    }

    if (assertion->Assertion == NULL) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    BID_ASSERT(assertion->Assertion->Payload != NULL);

    aud = json_string_value(json_object_get(assertion->Assertion->Payload, "aud"));
    if (aud == NULL) {
        err = BID_S_MISSING_AUDIENCE;
        goto cleanup;
    }

    if (assertion->cCertificates != 0) {
        /* no packing for reauth assertions */
        err = _BIDUnpackAudience(context, aud, &assertion->Claims);
        BID_BAIL_ON_ERROR(err);
    } else {
        /* claims directly stored in assertion for reauth */
        assertion->Claims = json_incref(assertion->Assertion->Payload);
    }

    *pAssertion = assertion;

cleanup:
    if (err != BID_S_OK)
        _BIDReleaseBackedAssertion(context, assertion);
    BIDFree(tmp);

    return err;
}

BIDError
_BIDPackBackedAssertion(
    BIDContext context,
    BIDBackedAssertion assertion,
    BIDJWKSet keyset,
    char **pEncodedJson)
{
    BIDError err;
    char *szEncodedAssertion = NULL;
    size_t cchEncodedAssertion;
    char *szEncodedCerts[BID_MAX_CERTS] = { NULL };
    size_t cchEncodedCerts[BID_MAX_CERTS] = { 0 };
    size_t i;
    size_t totalLen;
    char *p;

    *pEncodedJson = NULL;

    BID_ASSERT(assertion != NULL);

    if (keyset == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    err = _BIDMakeSignature(context, assertion->Assertion, keyset, &szEncodedAssertion, &cchEncodedAssertion);
    BID_BAIL_ON_ERROR(err);

    cchEncodedAssertion += 1; /* ~ */

    for (i = 0; i < assertion->cCertificates; i++) {
        err = _BIDMakeSignature(context, assertion->rCertificates[i], keyset, &szEncodedCerts[i], &cchEncodedCerts[i]);
        BID_BAIL_ON_ERROR(err);

        cchEncodedCerts[i] += 1; /* ~ */
    }

    totalLen = cchEncodedAssertion;
    for (i = 0; i < assertion->cCertificates && cchEncodedCerts[i] != 0; i++)
        totalLen += cchEncodedCerts[i];

    *pEncodedJson = BIDMalloc(totalLen + 1);
    if (*pEncodedJson == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    p = *pEncodedJson;
    *p++ = '~';
    memcpy(p, szEncodedAssertion, cchEncodedAssertion);
    p += cchEncodedAssertion;
    for (i = 0; i < assertion->cCertificates && cchEncodedCerts[i] != 0; i++) {
        *p++ = '~';
        memcpy(p, szEncodedCerts[i], cchEncodedCerts[i]);
    }
    *p = '\0';

    err = BID_S_OK;

cleanup:
    BIDFree(szEncodedAssertion);
    for (i = 0; i < assertion->cCertificates; i++)
        BIDFree(szEncodedCerts[i]);
    if (err != BID_S_OK)
        BIDFree(*pEncodedJson);

    return err;
}

BIDError
_BIDReleaseBackedAssertion(
    BIDContext context,
    BIDBackedAssertion assertion)
{
    size_t i;

    if (assertion == NULL)
        return BID_S_INVALID_PARAMETER;

    _BIDReleaseJWT(context, assertion->Assertion);
    for (i = 0; i < assertion->cCertificates; i++)
        _BIDReleaseJWT(context, assertion->rCertificates[i]);

    json_decref(assertion->Claims);
    BIDFree(assertion);

    return BID_S_OK;
}

static BIDError
CURLcodeToBIDError(CURLcode cc)
{
    return (cc == CURLE_OK) ? BID_S_OK : BID_S_HTTP_ERROR;
}

static BIDError
_BIDSetCurlCompositeUrl(
    BIDContext context,
    CURL *curlHandle,
    const char *szHostname,
    const char *szRelativeUrl)
{
    char *szUrl;
    size_t cchHostname;
    size_t cchRelativeUrl;
    CURLcode cc;

    BID_ASSERT(szHostname != NULL);
    BID_ASSERT(szRelativeUrl != NULL);

    cchHostname = strlen(szHostname);
    cchRelativeUrl = strlen(szRelativeUrl);

    szUrl = BIDMalloc(sizeof("https://") + cchHostname + cchRelativeUrl);
    if (szUrl == NULL)
        return BID_S_NO_MEMORY;

    snprintf(szUrl, sizeof("https://") + cchHostname + cchRelativeUrl,
             "https://%s%s", szHostname, szRelativeUrl);

    cc = curl_easy_setopt(curlHandle, CURLOPT_URL, szUrl);

    BIDFree(szUrl);

    return CURLcodeToBIDError(cc);
}

struct BIDCurlBufferDesc {
    char *Data;
    size_t Offset;
    size_t Size;
};

struct BIDCurlHeaderDesc {
    time_t Date;
    time_t Expires;
};

static size_t
_BIDCurlWriteCB(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct BIDCurlBufferDesc *buffer = (struct BIDCurlBufferDesc *)stream;
    size_t sizeRequired;

    sizeRequired = buffer->Offset + (size * nmemb) + 1; /* NUL */

    if (sizeRequired > buffer->Size) {
        size_t newSize = buffer->Size;
        void *tmpBuffer;

        while (newSize < sizeRequired)
            newSize *= 2;

        tmpBuffer = BIDRealloc(buffer->Data, newSize);
        if (tmpBuffer == NULL)
            return 0;

        buffer->Data = tmpBuffer;
        buffer->Size = newSize;
    }

    memcpy(buffer->Data + buffer->Offset, ptr, size * nmemb);
    buffer->Offset += size * nmemb;

    return size * nmemb;
}

static size_t
_BIDCurlHeaderCB(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct BIDCurlHeaderDesc *headers = (struct BIDCurlHeaderDesc *)stream;
    const char *s = (const char *)ptr;

    if (strncmp(s, "Date: ", 6) == 0)
        headers->Date = curl_getdate(&s[6], NULL);
    else if (strncmp(s, "Expires: ", 9) == 0)
        headers->Expires = curl_getdate(&s[9], NULL);

    return size * nmemb;
}

static BIDError
_BIDInitCurlHandle(
    BIDContext context,
    struct BIDCurlHeaderDesc *headers,
    struct BIDCurlBufferDesc *buffer,
    CURL **pCurlHandle)
{
    CURLcode cc;
    CURL *curlHandle = NULL;
    char szUserAgent[64];

    *pCurlHandle = NULL;

    curlHandle = curl_easy_init();
    if (curlHandle == NULL)
        return BID_S_HTTP_ERROR;

    cc = curl_global_init(CURL_GLOBAL_SSL);
    BID_BAIL_ON_ERROR(cc);

    cc = curl_easy_setopt(curlHandle, CURLOPT_FOLLOWLOCATION, 1);
    BID_BAIL_ON_ERROR(cc);

#ifdef GSSBID_DEBUG
    cc = curl_easy_setopt(curlHandle, CURLOPT_VERBOSE, 1);
    BID_BAIL_ON_ERROR(cc);
#endif

    if (headers != NULL) {
        cc = curl_easy_setopt(curlHandle, CURLOPT_HEADERFUNCTION, _BIDCurlHeaderCB);
        BID_BAIL_ON_ERROR(cc);

        cc = curl_easy_setopt(curlHandle, CURLOPT_HEADERDATA, headers);
        BID_BAIL_ON_ERROR(cc);
    }

    cc = curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, _BIDCurlWriteCB);
    BID_BAIL_ON_ERROR(cc);

    cc = curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, buffer);
    BID_BAIL_ON_ERROR(cc);

    cc = curl_easy_setopt(curlHandle, CURLOPT_FILETIME, 1);
    BID_BAIL_ON_ERROR(cc);

    snprintf(szUserAgent, sizeof(szUserAgent), "libbrowserid/%s", VERS_NUM);

    cc = curl_easy_setopt(curlHandle, CURLOPT_USERAGENT, szUserAgent);
    BID_BAIL_ON_ERROR(cc);

    *pCurlHandle = curlHandle;

cleanup:
    if (cc != CURLE_OK)
        curl_easy_cleanup(curlHandle);

    return CURLcodeToBIDError(cc);
}

#if 0
static BIDError
_BIDPopulateCacheMetadata(
    BIDContext context,
    struct BIDCurlBufferDesc *buffer,
    CURL *curlHandle,
    json_t *jsonDoc)
{
    CURLcode cc;

cleanup:
    return CURLcodeToBIDError(cc);
}
#endif

static BIDError
_BIDMakeHttpRequest(
    BIDContext context,
    struct BIDCurlBufferDesc *buffer,
    CURL *curlHandle,
    json_t **pJsonDoc)
{
    BIDError err;
    long httpStatus;

    *pJsonDoc = NULL;

    BID_ASSERT(buffer->Data != NULL);

    err = CURLcodeToBIDError(curl_easy_perform(curlHandle));
    BID_BAIL_ON_ERROR(err);

    buffer->Data[buffer->Offset] = '\0';

    err = CURLcodeToBIDError(curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpStatus));
    BID_BAIL_ON_ERROR(err);

    switch (httpStatus) {
    case 304:
        err = BID_S_DOCUMENT_NOT_MODIFIED;
        goto cleanup;
    case 200:
        break;
    default:
        err = BID_S_HTTP_ERROR;
    }

    *pJsonDoc = json_loads(buffer->Data, 0, &context->JsonError);
    if (*pJsonDoc == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

cleanup:
    return err;
}

static BIDError
_BIDSetCurlIfModifiedSince(
    BIDContext context,
    CURL *curlHandle,
    time_t tIfModifiedSince)
{
    CURLcode cc;
    long lIfModifiedSince = (long)tIfModifiedSince;
    curl_TimeCond timeCond;

    if (tIfModifiedSince <= 0)
        return BID_S_OK;

    timeCond = CURL_TIMECOND_IFMODSINCE;

    cc = curl_easy_setopt(curlHandle, CURLOPT_TIMECONDITION, timeCond);
    BID_BAIL_ON_ERROR(cc);

    cc = curl_easy_setopt(curlHandle, CURLOPT_TIMECONDITION, lIfModifiedSince);
    BID_BAIL_ON_ERROR(cc);

cleanup:
    return CURLcodeToBIDError(cc);
}

BIDError
_BIDRetrieveDocument(
    BIDContext context,
    const char *szHostname,
    const char *szRelativeUrl,
    time_t tIfModifiedSince,
    json_t **pJsonDoc,
    time_t *pExpiryTime)
{
    BIDError err;
    CURL *curlHandle = NULL;
    struct BIDCurlHeaderDesc headers = { 0 };
    struct BIDCurlBufferDesc buffer = { NULL };

    *pJsonDoc = NULL;
    if (pExpiryTime != NULL)
        *pExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    buffer.Offset = 0;
    buffer.Size = BUFSIZ;
    buffer.Data = BIDMalloc(buffer.Size);
    if (buffer.Data == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDInitCurlHandle(context, &headers, &buffer, &curlHandle);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCurlCompositeUrl(context, curlHandle, szHostname, szRelativeUrl);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCurlIfModifiedSince(context, curlHandle, tIfModifiedSince);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeHttpRequest(context, &buffer, curlHandle, pJsonDoc);
    BID_BAIL_ON_ERROR(err);

    if (pExpiryTime != NULL) {
        if (headers.Expires != 0)
            *pExpiryTime = headers.Expires;
        else
            *pExpiryTime = headers.Date + 60 * 60 * 24;
    }

cleanup:
    curl_easy_cleanup(curlHandle);
    BIDFree(buffer.Data);

    return err;
}

BIDError
_BIDPostDocument(
    BIDContext context,
    const char *szUrl,
    const char *szPostFields,
    json_t **pJsonDoc)
{
    BIDError err;
    CURL *curlHandle = NULL;
    struct BIDCurlBufferDesc buffer = { NULL };

    *pJsonDoc = NULL;

    BID_CONTEXT_VALIDATE(context);

    buffer.Offset = 0;
    buffer.Size = BUFSIZ; /* XXX */
    buffer.Data = BIDMalloc(buffer.Size);
    if (buffer.Data == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDInitCurlHandle(context, NULL, &buffer, &curlHandle);
    BID_BAIL_ON_ERROR(err);

    err = CURLcodeToBIDError(curl_easy_setopt(curlHandle, CURLOPT_URL, szUrl));
    BID_BAIL_ON_ERROR(err);

    err = CURLcodeToBIDError(curl_easy_setopt(curlHandle, CURLOPT_POST, 1));
    BID_BAIL_ON_ERROR(err);

    err = CURLcodeToBIDError(curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, szPostFields));
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeHttpRequest(context, &buffer, curlHandle, pJsonDoc);
    BID_BAIL_ON_ERROR(err);

cleanup:
    curl_easy_cleanup(curlHandle);
    BIDFree(buffer.Data);

    return err;
}

BIDError
_BIDGetJsonStringValue(
    BIDContext context,
    json_t *json,
    const char *key,
    char **pDst)
{
    const char *src = json_string_value(json_object_get(json, key));

    if (src == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    return _BIDDuplicateString(context, src, pDst);
}

BIDError
_BIDGetJsonBinaryValue(
    BIDContext context,
    json_t *json,
    const char *key,
    unsigned char **pbData,
    size_t *cbData)
{
    const char *src = json_string_value(json_object_get(json, key));

    if (src == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    return _BIDBase64UrlDecode(src, pbData, cbData);
}

BIDError
_BIDGetCurrentJsonTimestamp(
    BIDContext context,
    json_t **pTs)
{
    struct timeval tv;
    json_int_t ms;

    gettimeofday(&tv, NULL);

    ms = tv.tv_sec * 1000;
    ms += tv.tv_usec / 1000;

    *pTs = json_integer(ms);

    return (*pTs == NULL) ? BID_S_NO_MEMORY : BID_S_OK;
}

BIDError
_BIDGetJsonTimestampValue(
    BIDContext context,
    json_t *json,
    const char *key,
    time_t *ts)
{
    json_t *j;

    *ts = 0;

    j = (key != NULL) ? json_object_get(json, key) : json;
    if (j == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    *ts = json_integer_value(j);
    *ts /= 1000;

#if 0
    printf("_BIDGetJsonTimestampValue %s: %s", key, ctime(ts));
#endif
    return BID_S_OK;
}

BIDError
_BIDSetJsonTimestampValue(
    BIDContext context,
    json_t *json,
    const char *key,
    time_t ts)
{
    json_t *j;

#if 0
    printf("_BIDSetJsonTimestampValue %s: %s", key, ctime(&ts));
#endif
    ts *= 1000;

    j = json_integer(ts);
    if (j == NULL)
        return BID_S_NO_MEMORY;

    if (json_object_set(json, key, j) < 0)
        return BID_S_NO_MEMORY;

    return BID_S_OK;
}

const char *_BIDErrorTable[] = {
    "Success",
    "No context",
    "Out of memory",
    "Not implemented",
    "Invalid parameter",
    "Invalid usage",
    "Unavailable",
    "Unknown JSON key",
    "Invalid JSON",
    "Invalid Base64",
    "Invalid assertion",
    "Cannot encode JSON",
    "Cannot encode Base64",
    "Too many certs",
    "Untrusted issuer",
    "invalid issuer",
    "Missing issuer",
    "Missing audience",
    "Bad audience",
    "Expired assertion",
    "Expired certificate",
    "Invalid signature",
    "Missing algorithm",
    "Unknown algorithm",
    "Invalid key",
    "Invalid key set",
    "No key",
    "Internal crypto error",
    "HTTP error",
    "Buffer too small",
    "Buffer too large",
    "Remote verification failure",
    "Missing principal",
    "Unknown principal type",
    "Missing certificate",
    "Unknown attribute",
    "Missing channel bindings",
    "Channel bindings mismatch",
    "No session key",
    "Document not modified",
    "Process does not support UI interaction",
    "Failed to acquire assertion interactively",
    "Invalid audience URN",
    "Invalid JSON web token",
    "No more items",
    "Cache open error",
    "Cache read error",
    "Cache write error",
    "Cache close error",
    "Cache lock error",
    "Cache lock timed out",
    "Cache unlock error",
    "Cache delete error",
    "Cache permission denied",
    "Invalid cache version",
    "Cache scheme unknown",
    "Cache already exists",
    "Cache not found",
    "Cache key not found",
    "Assertion is a replay",
    "Failed to generate Diffie-Hellman parameters",
    "Failed to generate Diffie-Hellman key",
    "Diffie-Helman check not prime",
    "Diffie-Helman check not safe prime",
    "Diffie-Helman not suitable generator",
    "Diffie-Helman unable to check generator",
    "No ticket cache",
    "Corrupted ticket cache",
    "Unknown error code"
};

BIDError
BIDErrorToString(
    BIDError error,
    const char **pszErr)
{
    *pszErr = NULL;

    if (pszErr == NULL)
        return BID_S_INVALID_PARAMETER;

    if (error < BID_S_OK || error > BID_S_UNKNOWN_ERROR_CODE)
        return BID_S_UNKNOWN_ERROR_CODE;

    *pszErr = _BIDErrorTable[error];
    return BID_S_OK;
}

json_t *
_BIDLeafCert(
    BIDContext context,
    BIDBackedAssertion backedAssertion)
{
    if (backedAssertion->cCertificates == 0)
        return NULL;

    return backedAssertion->rCertificates[backedAssertion->cCertificates - 1]->Payload;
}

json_t *
_BIDRootCert(
    BIDContext context,
    BIDBackedAssertion backedAssertion)
{
    if (backedAssertion->cCertificates == 0)
        return NULL;

    return backedAssertion->rCertificates[0]->Payload;
}

BIDError
_BIDPopulateIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = NULL;
    json_t *assertion = backedAssertion->Assertion->Payload;
    json_t *leafCert = _BIDLeafCert(context, backedAssertion);
    json_t *principal;

    *pIdentity = NULL;

    identity = BIDCalloc(1, sizeof(*identity));
    if (identity == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    identity->Attributes = json_object();
    if (identity->Attributes == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    principal = json_object_get(leafCert, "principal");
    if (principal == NULL || json_object_get(principal, "email") == NULL) {
        err = BID_S_MISSING_PRINCIPAL;
        goto cleanup;
    }

    if (json_object_set(identity->Attributes, "email",    json_object_get(principal, "email")) < 0 ||
        json_object_set(identity->Attributes, "audience", json_object_get(assertion, "aud"))   < 0 ||
        json_object_set(identity->Attributes, "issuer",   json_object_get(leafCert, "iss"))    < 0 ||
        json_object_set(identity->Attributes, "expires",  json_object_get(assertion, "exp"))   < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    identity->PrivateAttributes = json_object();
    if (identity->PrivateAttributes == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        json_t *params = json_object_get(backedAssertion->Claims, "dh");

        if (params != NULL) {
            json_t *dh = json_object();

            if (dh == NULL                                          ||
                json_object_set(dh, "params", params) < 0           ||
                json_object_set(identity->PrivateAttributes, "dh", dh) < 0) {
                err = BID_S_NO_MEMORY;
                goto cleanup;
            }
        }
    }

    err = BID_S_OK;
    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

/*
 * XXX all very temporary until we have proper GSS URNs.
 */

static inline BIDError
_BIDSetJsonPrincComponent(
    BIDContext context,
    krb5_context krbContext,
    json_t *j,
    const char *key,
    krb5_principal krbPrinc,
    int index,
    int length)
{
    BIDError err;
    krb5_principal_data p = *krbPrinc;
    krb5_error_code code;
    char *s = NULL;

    KRB_PRINC_NAME(&p) += index;

    if (length == -1)
        KRB_PRINC_LENGTH(&p) -= index;
    else
        KRB_PRINC_LENGTH(&p) = length;

    code = krb5_unparse_name_flags(krbContext, &p, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &s);
    if (code == 0) {
        err = (json_object_set(j, key, json_string(s)) < 0) ? BID_S_NO_MEMORY : BID_S_OK;
#ifdef HAVE_HEIMDAL_VERSION
        krb5_xfree(ssi);
#else
        krb5_free_unparsed_name(krbContext, s);
#endif
    } else {
        err = BID_S_INVALID_AUDIENCE_URN;
    }

    return err;
}

/*
 * This is temporary until we can elegantly encode a principal name into a URN.
 */
static BIDError
_BIDPackSPN(
    BIDContext context,
    json_t *claims)
{
    BIDError err;
    krb5_error_code code;
    krb5_context krbContext = NULL;
    krb5_principal spn = NULL;
    const char *aud = json_string_value(json_object_get(claims, "aud"));

    if (aud == NULL) {
        err = BID_S_INVALID_AUDIENCE_URN;
        goto cleanup;
    }

    code = krb5_init_context(&krbContext);
    if (code != 0) {
        err = BID_S_CRYPTO_ERROR; /* XXX */
        goto cleanup;
    }

    code = krb5_parse_name_flags(krbContext, aud, KRB5_PRINCIPAL_PARSE_NO_REALM, &spn);
    if (code != 0) {
        err = BID_S_INVALID_AUDIENCE_URN;
        goto cleanup;
    }

    if (KRB_PRINC_LENGTH(spn) > 1) {
        err = _BIDSetJsonPrincComponent(context, krbContext, claims, "srv", spn, 0, 1);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonPrincComponent(context, krbContext, claims, "aud", spn, 1, 1);
        BID_BAIL_ON_ERROR(err);

        if (KRB_PRINC_LENGTH(spn) > 2) {
            err = _BIDSetJsonPrincComponent(context, krbContext, claims, "ssi", spn, 2, -1);
            BID_BAIL_ON_ERROR(err);
        }
    }

cleanup:
    krb5_free_principal(krbContext, spn);
    krb5_free_context(krbContext);

    return err;
}

/*
 * Takes (audience, protocol claims) and returns a SPN.
 */
static BIDError
_BIDUnpackSPN(
    BIDContext context,
    const char *aud,
    json_t *claims)
{
    krb5_error_code code = 0;
    krb5_context krbContext = NULL;
    krb5_principal spn = NULL;
    const char *srv = json_string_value(json_object_get(claims, "srv"));
    const char *ssi = json_string_value(json_object_get(claims, "ssi"));
    char *szSpn = NULL;

    if (aud == NULL)
        return BID_S_INVALID_AUDIENCE_URN;

    if (srv != NULL) {
        code = krb5_init_context(&krbContext);
        if (code != 0)
            return BID_S_CRYPTO_ERROR; /* XXX */

        code = krb5_build_principal(krbContext, &spn, 0, "", srv, aud, ssi, NULL);
        if (code == 0)
            code = krb5_unparse_name_flags(krbContext, spn, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &szSpn);

        json_object_del(claims, "srv");
        json_object_del(claims, "ssi");

        json_object_set_new(claims, "aud", json_string(szSpn));
        krb5_free_principal(krbContext, spn);

        krb5_free_context(krbContext);
    } else
        json_object_set_new(claims, "aud", json_string(aud));

    return code == 0 ? BID_S_OK : BID_S_INVALID_AUDIENCE_URN;
}

/*
 * Return a claims dictionary that we have packed into a URL.
 */
BIDError
_BIDUnpackAudience(
    BIDContext context,
    const char *szPackedAudience,
    json_t **pClaims)
{
    BIDError err;
    const char *p;
    char *szAudience = NULL;
    size_t cchAudienceOrSpn;
    json_t *claims = NULL;

    *pClaims = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (szPackedAudience == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    claims = json_object();
    if (claims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if ((context->ContextOptions & BID_CONTEXT_GSS) == 0) {
        if (json_object_set_new(claims, "aud", json_string(szPackedAudience)) < 0) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = BID_S_OK;
        *pClaims = json_incref(claims);
        goto cleanup;
    }

    cchAudienceOrSpn = strlen(szPackedAudience);

    if (cchAudienceOrSpn <= BID_GSS_AUDIENCE_PREFIX_LEN ||
        memcmp(szPackedAudience, BID_GSS_AUDIENCE_PREFIX, BID_GSS_AUDIENCE_PREFIX_LEN) != 0) {
        err = BID_S_INVALID_AUDIENCE_URN;
        goto cleanup;
    }

    szPackedAudience += BID_GSS_AUDIENCE_PREFIX_LEN;

#ifdef BROKEN_URL_PARSER
    p = strrchr(szPackedAudience, '.');
#else
    p = strrchr(szPackedAudience, '#');
#endif
    if (p != NULL) {
        if (p[1] != '\0') {
            err = _BIDDecodeJson(context, p + 1, BID_JSON_ENCODING_BASE32, &claims);
            BID_BAIL_ON_ERROR(err);
        }

        cchAudienceOrSpn = p - szPackedAudience;
    } else {
        cchAudienceOrSpn = strlen(szPackedAudience);
    }

    szAudience = BIDMalloc(cchAudienceOrSpn + 1);
    if (szAudience == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    memcpy(szAudience, szPackedAudience, cchAudienceOrSpn);
    szAudience[cchAudienceOrSpn] = '\0';

    err = _BIDUnpackSPN(context, szAudience, claims);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pClaims = claims;

#if 0
    printf("_BIDUnpackAudience: packed audience: %s\n", szPackedAudience);
    printf("_BIDUnpackAudience: unpacked audience: %s\n", szAudience);
    printf("_BIDUnpackAudience: unpacked claims: ");
    json_dumpf(claims, stdout, JSON_INDENT(4));
    printf("\n");
#endif

cleanup:
    BIDFree(szAudience);
    if (err != BID_S_OK)
        json_decref(claims);

    return err;
}

BIDError
_BIDPackAudience(
    BIDContext context,
    json_t *claims,
    char **pszPackedAudience)
{
    BIDError err;
    json_t *protocolClaims = NULL;
    const char *szAudience;
    char *szPackedAudience = NULL, *p;
    size_t cchAudience, cchPackedAudience;
    char *szEncodedClaims = NULL;
    size_t cchEncodedClaims;

    *pszPackedAudience = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (claims == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (json_object_get(claims, "aud") == NULL) {
        err = BID_S_MISSING_AUDIENCE;
        goto cleanup;
    }

    if ((context->ContextOptions & BID_CONTEXT_GSS) == 0) {
        szAudience = json_string_value(json_object_get(claims, "aud"));

        err = _BIDDuplicateString(context, szAudience, pszPackedAudience);
        BID_BAIL_ON_ERROR(err);

        err = BID_S_OK;
        goto cleanup;
    }

    protocolClaims = json_copy(claims);
    if (protocolClaims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDPackSPN(context, protocolClaims);
    BID_BAIL_ON_ERROR(err);

    szAudience = json_string_value(json_object_get(protocolClaims, "aud"));
    BID_ASSERT(szAudience != NULL);

    cchAudience = strlen(szAudience);

    err = _BIDEncodeJson(context, protocolClaims, BID_JSON_ENCODING_BASE32, &szEncodedClaims, &cchEncodedClaims);
    BID_BAIL_ON_ERROR(err);

    cchPackedAudience = BID_GSS_AUDIENCE_PREFIX_LEN + cchAudience;
    cchPackedAudience += 1 + cchEncodedClaims;

    szPackedAudience = BIDMalloc(cchPackedAudience + 1);
    if (szPackedAudience == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    p = szPackedAudience;
    memcpy(p, BID_GSS_AUDIENCE_PREFIX, BID_GSS_AUDIENCE_PREFIX_LEN);
    p += BID_GSS_AUDIENCE_PREFIX_LEN;
    memcpy(p, szAudience, cchAudience);
    p += cchAudience;
#ifdef BROKEN_URL_PARSER
    *p++ = '.';
#else
    *p++ = '#';
#endif
    memcpy(p, szEncodedClaims, cchEncodedClaims);
    p += cchEncodedClaims;
    *p = '\0';

#if 0
    printf("_BIDPackAudience: claims: ");
    json_dumpf(claims, stdout, JSON_INDENT(4));
    printf("_BIDPackAudience: unpacked audience: %s\n", szAudience);
    printf("_BIDPackAudience: packed audience: %s\n", szPackedAudience);
    printf("\n");
#endif

    err = BID_S_OK;
    *pszPackedAudience = szPackedAudience;

cleanup:
    json_decref(protocolClaims);
    if (err != BID_S_OK)
        BIDFree(szPackedAudience);
    BIDFree(szEncodedClaims);

    return err;
}

BIDError
BIDAcquireAssertionFromString(
    BIDContext context,
    const char *szAssertion,
    uint32_t ulReqFlags,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;

    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulRetFlags != NULL)
        *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    if (pAssertedIdentity != NULL) {
        err = _BIDPopulateIdentity(context, backedAssertion, pAssertedIdentity);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;

    if (ptExpiryTime != NULL)
        _BIDGetJsonTimestampValue(context, backedAssertion->Assertion->Payload, "exp", ptExpiryTime);

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);

    return err;
}

BIDError
BIDFreeData(
    BIDContext context,
    char *s)
{
    if (s == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(s);
    return BID_S_OK;
}
