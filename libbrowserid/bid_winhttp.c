/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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
        DWORD newSize = buffer->Size;
        PCHAR tmpBuffer;

        while (newSize < sizeRequired)
            newSize *= 2;

        tmpBuffer = LocalReAlloc(buffer->Data, newSize, 0);
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
