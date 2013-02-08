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
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
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

#include <curl/curl.h>
#include <curl/easy.h>

static BIDError
CURLcodeToBIDError(CURLcode cc)
{
    return (cc == CURLE_OK) ? BID_S_OK : BID_S_HTTP_ERROR;
}

static BIDError
_BIDSetCurlCompositeUrl(
    BIDContext context BID_UNUSED,
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
    BIDContext context BID_UNUSED,
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

    cc = curl_easy_setopt(curlHandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
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
    BIDContext context BID_UNUSED,
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
