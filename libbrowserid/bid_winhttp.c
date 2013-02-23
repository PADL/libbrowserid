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

#include <winhttp.h>

#define BID_IMS_HTTP_HEADER         L"If-Modified-Since: "
#define BID_IMS_HTTP_HEADER_SIZE    (sizeof(BID_IMS_HTTP_HEADER) - sizeof(WCHAR))

/* XXX */
static BIDError
WinHttpStatusToBIDError(void)
{
    BIDError err;

    switch (GetLastError()) {
    case ERROR_SUCCESS:
        err = BID_S_OK;
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
        err = BID_S_NO_MEMORY;
        break;
    default:
        err = BID_S_HTTP_ERROR;
        break;
    }

    return err;
}

static BIDError
_BIDInitWinHttpHandle(
    BIDContext context BID_UNUSED,
    HINTERNET *pHandle)
{
    WCHAR szUserAgent[64];

    _snwprintf(szUserAgent, sizeof(szUserAgent), L"libbrowserid/%S", VERS_NUM);

    *pHandle = WinHttpOpen(szUserAgent,
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (*pHandle == NULL)
        return WinHttpStatusToBIDError();

    return BID_S_OK;
}

struct BIDWinHttpBufferDesc {
    PCHAR Data;
    DWORD Offset;
    DWORD Size;
};

static BIDError
_BIDGrowHttpBuffer(
    struct BIDWinHttpBufferDesc *buffer,
    DWORD size)
{
    DWORD sizeRequired;

    sizeRequired = buffer->Offset + size + 1; /* NUL */

    if (sizeRequired > buffer->Size) {
        DWORD newSize = buffer->Size == 0 ? BUFSIZ : buffer->Size;
        PCHAR tmpBuffer;

        while (newSize < sizeRequired)
            newSize *= 2;

        if (buffer->Size == 0)
            tmpBuffer = LocalAlloc(LMEM_FIXED, newSize);
        else
            tmpBuffer = LocalReAlloc(buffer->Data, newSize, LMEM_MOVEABLE);
        if (tmpBuffer == NULL)
            return BID_S_NO_MEMORY;

        buffer->Data = tmpBuffer;
        buffer->Size = newSize;
    }

    return BID_S_OK;
}

static BIDError
_BIDGetHttpExpiry(
    BIDContext context,
    HINTERNET hRequest,
    time_t *pExpiryTime)
{
    DWORD dwSize;
    SYSTEMTIME st;
    FILETIME ft;
    enum { HEADER_NONE, HEADER_EXPIRES, HEADER_DATE } h = HEADER_NONE;
    BIDError err;

    *pExpiryTime = 0;

    dwSize = sizeof(st);
    if (WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_EXPIRES |
                               WINHTTP_QUERY_FLAG_SYSTEMTIME,
                            NULL,
                            &st,
                            &dwSize,
                            WINHTTP_NO_HEADER_INDEX))
        h = HEADER_EXPIRES;
    else if (WinHttpQueryHeaders(hRequest,
                                WINHTTP_QUERY_DATE |
                                   WINHTTP_QUERY_FLAG_SYSTEMTIME,
                                NULL,
                                &st,
                                &dwSize,
                                WINHTTP_NO_HEADER_INDEX))
        h = HEADER_DATE;

    if (h != HEADER_NONE) {
        SystemTimeToFileTime(&st, &ft);
        err = _BIDTimeToSecondsSince1970(context, &ft, pExpiryTime);
        if (err != BID_S_OK)
            return err;

        if (h == HEADER_DATE)
            *pExpiryTime += 60 * 60 * 24;
    }

    return BID_S_OK;
}

static BIDError
_BIDMakeHttpRequest(
    BIDContext context,
    HINTERNET hRequest,
    const char *szRequestData,
    json_t **pJsonDoc,
    time_t *pExpiryTime)
{
    BIDError err;
    DWORD dwStatusCode, dwSize;
    DWORD cchRequestData = szRequestData ? strlen(szRequestData) : 0;
    struct BIDWinHttpBufferDesc buffer = { NULL, 0, 0 };

    if (!WinHttpSendRequest(hRequest,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0,
                            (PCHAR)szRequestData,
                            cchRequestData,
                            cchRequestData,
                            0)) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    while (1) {
        DWORD dwRead = 0;

        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            err = WinHttpStatusToBIDError();
            goto cleanup;
        }

        if (dwSize == 0)
            break;

        err = _BIDGrowHttpBuffer(&buffer, dwSize);
        BID_BAIL_ON_ERROR(err);

        if (!WinHttpReadData(hRequest, buffer.Data, dwSize, &dwRead)) {
            err = WinHttpStatusToBIDError();
            goto cleanup;
        }

        buffer.Offset += dwRead;
    }

    dwSize = sizeof(dwStatusCode);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE |
                                WINHTTP_QUERY_FLAG_NUMBER,
                             NULL,
                             &dwStatusCode,
                             &dwSize,
                             WINHTTP_NO_HEADER_INDEX)) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    switch (dwStatusCode) {
    case 304:
        err = BID_S_DOCUMENT_NOT_MODIFIED;
        goto cleanup;
    case 200:
        err = BID_S_OK;
        break;
    default:
        err = BID_S_HTTP_ERROR;
        break;
    }

    if (buffer.Offset == buffer.Size) {
        err = _BIDGrowHttpBuffer(&buffer, 1);
        BID_BAIL_ON_ERROR(err);
    }

    buffer.Data[buffer.Offset] = '\0';

    *pJsonDoc = json_loads(buffer.Data, 0, &context->JsonError);
    if (*pJsonDoc == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    if (pExpiryTime != NULL)
        _BIDGetHttpExpiry(context, hRequest, pExpiryTime);

cleanup:
    LocalFree(buffer.Data);

    return err;
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
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    LPWSTR wszHostname = NULL;
    LPWSTR wszRelativeUrl = NULL;
    LPWSTR pwszAcceptTypes[] = { L"application/json", NULL };

    *pJsonDoc = NULL;
    if (pExpiryTime != NULL)
        *pExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDUtf8ToUcs2(context, szHostname, &wszHostname);
    BID_BAIL_ON_ERROR(err);

    err = _BIDUtf8ToUcs2(context, szRelativeUrl, &wszRelativeUrl);
    BID_BAIL_ON_ERROR(err);

    err = _BIDInitWinHttpHandle(context, &hSession);
    BID_BAIL_ON_ERROR(err);

    hConnect = WinHttpConnect(hSession, wszHostname,
                              INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect == NULL) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }
    
    hRequest = WinHttpOpenRequest(hConnect, L"GET",
                                  wszRelativeUrl, NULL, /* HTTP version */
                                  WINHTTP_NO_REFERER,
                                  pwszAcceptTypes,
                                  WINHTTP_FLAG_SECURE);
    if (hRequest == NULL) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    if (tIfModifiedSince) {
        WCHAR wszTimeStr[(BID_IMS_HTTP_HEADER_SIZE + WINHTTP_TIME_FORMAT_BUFSIZE) / sizeof(WCHAR)] = BID_IMS_HTTP_HEADER;
        FILETIME ft;
        SYSTEMTIME sTime;

        _BIDSecondsSince1970ToTime(context, tIfModifiedSince, &ft);
        FileTimeToSystemTime(&ft, &sTime);

        if (!WinHttpTimeFromSystemTime(&sTime,
            &wszTimeStr[BID_IMS_HTTP_HEADER_SIZE / sizeof(WCHAR)])) {
            err = WinHttpStatusToBIDError();
            goto cleanup;
        }

        if (!WinHttpAddRequestHeaders(hRequest, wszTimeStr, (ULONG)-1,
                                      WINHTTP_ADDREQ_FLAG_ADD)) {
            err = WinHttpStatusToBIDError();
            goto cleanup;
        }
    }

    err = _BIDMakeHttpRequest(context, hRequest, WINHTTP_NO_REQUEST_DATA,
                              pJsonDoc, pExpiryTime);
    BID_BAIL_ON_ERROR(err);

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    BIDFree(wszHostname);
    BIDFree(wszRelativeUrl);

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
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    URL_COMPONENTS urlComp;
    LPWSTR wszUrl = NULL;
    LPWSTR pwszAcceptTypes[] = { L"application/json", NULL };
    LPWSTR wszHostname = NULL;
    LPWSTR wszRelativeUrl = NULL;

    *pJsonDoc = NULL;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDUtf8ToUcs2(context, szUrl, &wszUrl);
    BID_BAIL_ON_ERROR(err);

    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wszUrl, (DWORD)wcslen(wszUrl), 0, &urlComp)) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    wszHostname = BIDMalloc((urlComp.dwHostNameLength + 1) * sizeof(WCHAR));
    if (wszHostname == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    CopyMemory(wszHostname, urlComp.lpszHostName, urlComp.dwHostNameLength);
    wszHostname[urlComp.dwHostNameLength] = 0;

    wszRelativeUrl = BIDMalloc((urlComp.dwUrlPathLength + 1) * sizeof(WCHAR));
    if (wszHostname == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }
    CopyMemory(wszRelativeUrl, urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    wszRelativeUrl[urlComp.dwUrlPathLength] = 0;

    err = _BIDInitWinHttpHandle(context, &hSession);
    BID_BAIL_ON_ERROR(err);

    hConnect = WinHttpConnect(hSession, urlComp.lpszHostName,
                              INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect == NULL) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }
    
    hRequest = WinHttpOpenRequest(hConnect, L"POST",
                                  urlComp.lpszUrlPath, NULL, /* HTTP version */
                                  WINHTTP_NO_REFERER,
                                  pwszAcceptTypes,
                                  WINHTTP_FLAG_SECURE);
    if (hRequest == NULL) {
        err = WinHttpStatusToBIDError();
        goto cleanup;
    }

    err = _BIDMakeHttpRequest(context, hRequest, szPostFields,
                              pJsonDoc, NULL);
    BID_BAIL_ON_ERROR(err);

cleanup:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    BIDFree(wszUrl);
    BIDFree(wszHostname);
    BIDFree(wszRelativeUrl);

    return err;
}
