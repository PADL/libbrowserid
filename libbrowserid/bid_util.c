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
/*
 * Portions Copyright (c) 2009-2011 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "bid_private.h"

BIDError
_BIDDuplicateString(
    BIDContext context BID_UNUSED,
    const char *szSrc,
    char **szDst)
{
    size_t cbSrc;

    *szDst = NULL;

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
    BIDContext context BID_UNUSED,
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
    BIDContext context BID_UNUSED,
    json_t *jData,
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
    json_t **pjData)
{
    BIDError err;
    char *szJson = NULL;
    size_t cbJson;
    json_t *jData;

    *pjData = NULL;

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
    char *p;
    BIDBackedAssertion assertion = NULL;

    if (encodedJson == NULL) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    assertion = BIDCalloc(1, sizeof(*assertion));
    if (assertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDDuplicateString(context, encodedJson, &assertion->EncData);
    BID_BAIL_ON_ERROR(err);

    assertion->EncDataLength = strlen(assertion->EncData);

    for (p = assertion->EncData; p != NULL; ) {
        char *q = strchr(p, '~');
        BIDJWT *pDst;

        if (q != NULL) {
            if (assertion->cCertificates >= BID_MAX_CERTS) {
                err = BID_S_TOO_MANY_CERTS;
                goto cleanup;
            }

            *q = '\0';
            pDst = &assertion->rCertificates[assertion->cCertificates];
        } else {
            pDst = &assertion->Assertion;
        }

        err = _BIDParseJWT(context, p, pDst);
        BID_BAIL_ON_ERROR(err);

        if (*pDst != assertion->Assertion)
            assertion->cCertificates++;

        if (q == NULL) {
            p = NULL;
        } else {
            *q = '~';
            p = q + 1;
        }
    }

    if (assertion->Assertion == NULL) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    BID_ASSERT(assertion->Assertion->Payload != NULL);

    _BIDOutputDebugJson(assertion->Assertion->Payload);

    *pAssertion = assertion;

cleanup:
    if (err != BID_S_OK)
        _BIDReleaseBackedAssertion(context, assertion);

    return err;
}

BIDError
_BIDPackBackedAssertion(
    BIDContext context,
    BIDBackedAssertion assertion,
    BIDJWKSet keyset,
    json_t *certChain,
    char **pEncodedJson)
{
    BIDError err;
    char *szEncodedAssertion = NULL;
    size_t cchEncodedAssertion;
    char *szEncodedCerts[BID_MAX_CERTS] = { NULL };
    size_t cchEncodedCerts[BID_MAX_CERTS] = { 0 };
    size_t i;
    size_t cchBackedAssertion;
    char *p;

    *pEncodedJson = NULL;

    BID_ASSERT(assertion != NULL);
    BID_ASSERT(assertion->Assertion != NULL);

    _BIDOutputDebugJson(assertion->Assertion->Payload);

    err = _BIDMakeSignature(context, assertion->Assertion, keyset, certChain,
                            &szEncodedAssertion, &cchEncodedAssertion);
    BID_BAIL_ON_ERROR(err);

    for (i = 0; i < assertion->cCertificates; i++) {
        err = _BIDMakeSignature(context, assertion->rCertificates[i], keyset,
                                NULL, &szEncodedCerts[i], &cchEncodedCerts[i]);
        BID_BAIL_ON_ERROR(err);
    }

    cchBackedAssertion = 1 /* leading ~ */ + cchEncodedAssertion;
    for (i = 0; i < assertion->cCertificates && cchEncodedCerts[i] != 0; i++) {
        cchBackedAssertion += 1 /* leading ~ */ + cchEncodedCerts[i];
    }

    *pEncodedJson = BIDMalloc(cchBackedAssertion + 1);
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
        p += cchEncodedCerts[i];
    }
    *p = '\0';

    BID_ASSERT(p - *pEncodedJson == cchBackedAssertion);

    err = BID_S_OK;

cleanup:
    BIDFree(szEncodedAssertion);
    for (i = 0; i < assertion->cCertificates; i++)
        BIDFree(szEncodedCerts[i]);
    if (err != BID_S_OK) {
        BIDFree(*pEncodedJson);
        *pEncodedJson = NULL;
    }

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

    BIDFree(assertion->EncData);
    _BIDReleaseJWT(context, assertion->Assertion);
    for (i = 0; i < assertion->cCertificates; i++)
        _BIDReleaseJWT(context, assertion->rCertificates[i]);

    BIDFree(assertion);

    return BID_S_OK;
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
_BIDGetJsonStringValueArray(
    BIDContext context,
    json_t *json,
    const char *szKey,
    char ***prgszValues)
{
    BIDError err;
    size_t i, j, cValues = 0;
    char **rgszValues = NULL;

    *prgszValues = NULL;

    if (szKey != NULL)
        json = json_object_get(json, szKey);
    if (json == NULL) {
        err = BID_S_UNKNOWN_JSON_KEY;
        goto cleanup;
    }

    if (json_is_string(json))
        cValues = 1;
    else if (json_is_array(json))
        cValues = json_array_size(json);
    else {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    rgszValues = BIDCalloc(cValues + 1, sizeof(char *));
    if (rgszValues == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (json_is_string(json)) {
        err = _BIDDuplicateString(context, json_string_value(json), &rgszValues[0]);
        BID_BAIL_ON_ERROR(err);

        rgszValues[1] = NULL;
    } else {
        json_t *value;

        for (i = 0, j = 0; i < cValues; i++) {
            value = json_array_get(json, i);

            if (!json_is_string(value))
                continue;

            err = _BIDDuplicateString(context, json_string_value(value), &rgszValues[j]);
            BID_BAIL_ON_ERROR(err);

            j++;
        }

        rgszValues[j] = NULL;
    }

    *prgszValues = rgszValues;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && rgszValues != NULL) {
        for (i = 0; rgszValues[i] != NULL; i++)
            BIDFree(rgszValues[i]);
        BIDFree(rgszValues);
    }

    return BID_S_OK;
}

BIDError
_BIDGetJsonBinaryValue(
    BIDContext context BID_UNUSED,
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
_BIDGetJsonTimestampValue(
    BIDContext context BID_UNUSED,
    json_t *json,
    const char *key,
    time_t *ts)
{
    json_t *j;

    *ts = 0;

    j = json_object_get(json, key);
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
    BIDError err;

    ts *= 1000;

    j = json_integer(ts);
    if (j == NULL)
        return BID_S_NO_MEMORY;

    err = _BIDJsonObjectSet(context, json, key, j, BID_JSON_FLAG_CONSUME_REF);

    return err;
}

json_t *
_BIDLeafCert(
    BIDContext context BID_UNUSED,
    BIDBackedAssertion backedAssertion)
{
    if (backedAssertion->cCertificates == 0)
        return NULL;

    return backedAssertion->rCertificates[backedAssertion->cCertificates - 1]->Payload;
}

json_t *
_BIDRootCert(
    BIDContext context BID_UNUSED,
    BIDBackedAssertion backedAssertion)
{
    if (backedAssertion->cCertificates == 0)
        return NULL;

    return backedAssertion->rCertificates[0]->Payload;
}

BIDError
BIDFreeData(
    BIDContext context BID_UNUSED,
    char *s)
{
    if (s == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(s);
    return BID_S_OK;
}

int
_BIDCanInteractP(
    BIDContext context,
    uint32_t ulReqFlags)
{
    if ((context->ContextOptions & BID_CONTEXT_INTERACTION_DISABLED) ||
        (ulReqFlags & BID_ACQUIRE_FLAG_NO_INTERACT))
        return 0;
    else
        return 1;
}

BIDError
_BIDJsonObjectSetOld(
    BIDContext context BID_UNUSED,
    json_t *dst,
    const char *key,
    json_t *src,
    uint32_t ulFlags)
{
    BIDError err;

    BID_ASSERT((ulFlags & BID_JSON_FLAG_CONSUME_REF) == 0);

    if (key == NULL)
        return BID_S_INVALID_PARAMETER;

    if (src == NULL) {
        if (ulFlags & BID_JSON_FLAG_REQUIRED)
            err = BID_S_UNKNOWN_JSON_KEY;
        else
            err = _BIDJsonObjectDel(context, dst, key, 0);
    } else {
        if (json_object_set(dst, key, src) < 0)
            err = BID_S_NO_MEMORY;
        else
            err = BID_S_OK;
    }

    return err;
}

BIDError
_BIDJsonObjectSetNew(
    BIDContext context BID_UNUSED,
    json_t *dst,
    const char *key,
    json_t *src,
    uint32_t ulFlags)
{
    BIDError err;

    BID_ASSERT(ulFlags & BID_JSON_FLAG_CONSUME_REF);

    ulFlags &= ~(BID_JSON_FLAG_CONSUME_REF);

    err = _BIDJsonObjectSetOld(context, dst, key, src, ulFlags);

    if (src != NULL)
        json_decref(src);

    return err;
}

BIDError
_BIDJsonObjectDel(
    BIDContext context BID_UNUSED,
    json_t *dst,
    const char *key,
    uint32_t ulFlags)
{
    if (json_object_del(dst, key) < 0 &&
        (ulFlags & BID_JSON_FLAG_REQUIRED))
        return BID_S_UNKNOWN_JSON_KEY;

    return BID_S_OK;
}

BIDError
_BIDAllocJsonObject(
    BIDContext context BID_UNUSED,
    json_t **pDst)
{
    *pDst = json_object();

    if (*pDst == NULL)
        return BID_S_NO_MEMORY;

    return BID_S_OK;
}

BIDError
_BIDJsonObjectSetBinaryValue(
    BIDContext context,
    json_t *dst,
    const char *key,
    const unsigned char *pbData,
    size_t cbData)
{
    BIDError err;
    json_t *value;

    err = _BIDJsonBinaryValue(context, pbData, cbData, &value);
    if (err != BID_S_OK)
        return err;

    err = _BIDJsonObjectSet(context, dst, key, value, BID_JSON_FLAG_CONSUME_REF);

    return err;
}

static struct {
    uint32_t ulAcquireOpt;
    uint32_t ulVerifyOpt;
    const char *szOpt;
} _BIDOptionsMap[] = {
    {
        BID_ACQUIRE_FLAG_EXTRA_ROUND_TRIP,
        BID_VERIFY_FLAG_EXTRA_ROUND_TRIP,
        "xrt"
    },
    {
        BID_ACQUIRE_FLAG_DCE,
        BID_VERIFY_FLAG_DCE,
        "dce"
    },
    {
        BID_ACQUIRE_FLAG_IDENTIFY,
        BID_VERIFY_FLAG_IDENTIFY,
        "ify"
    },
    {
        BID_ACQUIRE_FLAG_MUTUAL_AUTH,
        BID_VERIFY_FLAG_MUTUAL_AUTH,
        "ma"
    },
};

BIDError
_BIDMakeProtocolOpts(
    BIDContext context BID_UNUSED,
    uint32_t ulOpts,
    json_t **pOpts)
{
    BIDError err;
    json_t *opts = NULL;
    size_t i;

    opts = json_array();
    if (opts == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 0; i < sizeof(_BIDOptionsMap) / sizeof(_BIDOptionsMap[0]); i++) {
        if (ulOpts & _BIDOptionsMap[i].ulAcquireOpt) {
            json_t *opt = json_string(_BIDOptionsMap[i].szOpt);

            if (opt == NULL) {
                err = BID_S_NO_MEMORY;
                goto cleanup;
            }

            json_array_append_new(opts, opt);
        }
    }

    if (json_array_size(opts)) {
        *pOpts = opts;
        opts = NULL;
    }

    err = BID_S_OK;

cleanup:
    json_decref(opts);

    return err;
}

BIDError
_BIDParseProtocolOpts(
    BIDContext context BID_UNUSED,
    json_t *opts,
    uint32_t *pulOpts)  /* BID_VERIFY_FLAG_XXX */
{
    size_t i, j;

    /* don't zero pulOpts, caller may have already set some flags */

    if (opts == NULL)
        return BID_S_OK;

    if (!json_is_array(opts))
        return BID_S_INVALID_JSON;

    for (i = 0; i < json_array_size(opts); i++) {
        json_t *opt = json_array_get(opts, i);
        const char *szOpt;

        szOpt = json_string_value(opt);
        if (szOpt == NULL)
            continue;

        for (j = 0; j < sizeof(_BIDOptionsMap) / sizeof(_BIDOptionsMap[0]); j++) {
            if (strcmp(szOpt, _BIDOptionsMap[j].szOpt) == 0) {
                *pulOpts |= _BIDOptionsMap[j].ulVerifyOpt;
                break;
            }
        }
    }

    return BID_S_OK;
}

/*
 * Transform a GSS BrowserID audience into a host SPN one.
 * Service-specific and realms are discarded.
 */
BIDError
_BIDHostifySpn(
    BIDContext context BID_UNUSED,
    const char *szSpn,
    char **pszAudienceOrSpn)
{
    const char *q, *szSpnHost = NULL;
    size_t cchSpnHost = 0, i;
    int bEscape = 0;
    char *p;

    *pszAudienceOrSpn = NULL;

    for (q = szSpn; *q != '\0'; q++) {
        if (*q == '\\') {
            bEscape++;
        } else if (bEscape) {
            bEscape = 0;
        } else {
            if (szSpnHost == NULL && *q == '/') {
                szSpnHost = q + 1;
                continue;
            } else if (*q == '/' || *q == '@')
                break;
        }
        if (szSpnHost != NULL)
            cchSpnHost++;
    }

    if (szSpnHost == NULL)
        return BID_S_BAD_AUDIENCE;

    *pszAudienceOrSpn = BIDMalloc(5 + cchSpnHost + 1);
    if (*pszAudienceOrSpn == NULL)
        return BID_S_NO_MEMORY;

    p = *pszAudienceOrSpn;

    memcpy(p, "host/", 5);
    p += 5;

    /* lowercase the hostname */
    for (i = 0; i < cchSpnHost; i++)
        *p++ = tolower(szSpnHost[i]);

    *p = '\0';

    return BID_S_OK;
}

json_t *
_BIDJsonObjectGet(
    BIDContext context BID_UNUSED,
    json_t *object,
    const char *key)
{
    return json_object_get(object, key);
}

json_int_t
_BIDJsonIntegerValue(json_t *object)
{
    return json_integer_value(object);
}

uint32_t
_BIDJsonUInt32Value(json_t *object)
{
    return (uint32_t)json_integer_value(object);
}

const char *
_BIDJsonStringValue(json_t *object)
{
    return json_string_value(object);
}
