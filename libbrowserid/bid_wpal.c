/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#pragma section(".CRT$XCU", read)

static void __cdecl
_BIDLibraryInit(void);

__declspec(allocate(".CRT$XCU"))
void (__cdecl *__BIDLibraryInit)(void) = _BIDLibraryInit;

static void __cdecl
_BIDLibraryInit(void)
{
    json_set_alloc_funcs(BIDMalloc, BIDFree);
}

BIDError
_BIDSecondsSince1970ToTime(
    BIDContext context BID_UNUSED,
    time_t t,
    PFILETIME pft)
{
    LONGLONG ll;

    ll = Int32x32To64(t, 10000000) + 116444736000000000;
    pft->dwLowDateTime = (DWORD)ll;
    pft->dwHighDateTime = ll >> 32;

    return BID_S_OK;
}

BIDError
_BIDTimeToSecondsSince1970(
    BIDContext context BID_UNUSED,
    PFILETIME pft,
    time_t *pt)
{
    LARGE_INTEGER ll;

    ll.HighPart = pft->dwHighDateTime;
    ll.LowPart = pft->dwLowDateTime;

    ll.QuadPart -= 116444736000000000;

    *pt = ll.QuadPart / 10000000;

    return BID_S_OK;
}

BIDError
_BIDGetCurrentJsonTimestamp(
    BIDContext context BID_UNUSED,
    json_t **pTs)
{
    FILETIME ft;
    LARGE_INTEGER ll;
    json_int_t ms;

    GetSystemTimeAsFileTime(&ft);

    ll.HighPart = ft.dwHighDateTime;
    ll.LowPart = ft.dwLowDateTime;

    ll.QuadPart -= 116444736000000000;

    ms = ll.QuadPart / 10000;

    *pTs = json_integer(ms);

    return (*pTs == NULL) ? BID_S_NO_MEMORY : BID_S_OK;
}

BIDError
_BIDUtf8ToUcs2(
    BIDContext context BID_UNUSED,
    const char *utf8String,
    PWSTR *pUcs2String)
{
    size_t cchUcs2String, cchUtf8String;

    *pUcs2String = NULL;

    if (utf8String == NULL)
        return BID_S_INVALID_PARAMETER;

    cchUtf8String = strlen(utf8String);
    cchUcs2String = MultiByteToWideChar(CP_UTF8, 0, utf8String,
                                        cchUtf8String, NULL, 0);
    if (cchUcs2String == 0)
        return BID_S_INVALID_PARAMETER;

    *pUcs2String = BIDMalloc((cchUcs2String + 1) * sizeof(WCHAR));
    if (*pUcs2String == NULL)
        return BID_S_NO_MEMORY;

    MultiByteToWideChar(CP_UTF8, 0, utf8String,
                        cchUtf8String, *pUcs2String, cchUcs2String);

    (*pUcs2String)[cchUcs2String] = 0;

    return BID_S_OK;
}

BIDError
_BIDUcs2ToUtf8(
    BIDContext context BID_UNUSED,
    PCWSTR ucs2String,
    char **pUtf8String)
{
    size_t cchUtf8String, cchUcs2String;

    *pUtf8String = NULL;

    if (ucs2String == NULL)
        return BID_S_INVALID_PARAMETER;

    cchUcs2String = wcslen(ucs2String);
    cchUtf8String = WideCharToMultiByte(CP_UTF8, 0, ucs2String, cchUcs2String,
                                        NULL, 0, NULL, NULL);
    if (cchUtf8String == 0)
        return BID_S_INVALID_PARAMETER;

    *pUtf8String = BIDMalloc(cchUtf8String + 1);
    if (*pUtf8String == NULL)
        return BID_S_NO_MEMORY;

    WideCharToMultiByte(CP_UTF8, 0, ucs2String, cchUcs2String,
                        *pUtf8String, cchUtf8String, NULL, NULL);
    (*pUtf8String)[cchUtf8String] = '\0';

    return BID_S_OK;
}
