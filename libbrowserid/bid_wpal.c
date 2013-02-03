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
    if (cchUcs2String == 0 && cchUtf8String != 0)
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
    if (cchUtf8String == 0 && cchUcs2String != 0)
        return BID_S_INVALID_PARAMETER;

    *pUtf8String = BIDMalloc(cchUtf8String + 1);
    if (*pUtf8String == NULL)
        return BID_S_NO_MEMORY;

    WideCharToMultiByte(CP_UTF8, 0, ucs2String, cchUcs2String,
                        *pUtf8String, cchUtf8String, NULL, NULL);
    (*pUtf8String)[cchUtf8String] = '\0';

    return BID_S_OK;
}

BIDError
_BIDGetJsonUcs2Value(
    BIDContext context,
    json_t *json,
    const char *key,
    PWSTR *pDst)
{
    const char *src = json_string_value(json_object_get(json, key));

    *pDst = NULL;

    if (src == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    return  _BIDUtf8ToUcs2(context, src, pDst);
}

BIDError
_BIDSetJsonUcs2Value(
    BIDContext context,
    json_t *json,
    const char *key,
    PWSTR wsz)
{
    BIDError err;
    char *sz = NULL;

    err = _BIDUcs2ToUtf8(context, wsz, &sz);
    if (err != BID_S_OK)
        return err;

    err = _BIDJsonObjectSet(context, json, key,
                            json_string(sz),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);

    BIDFree(sz);

    return err;
}

BIDError
_BIDSetJsonFileTimeValue(
    BIDContext context,
    json_t *json,
    const char *key,
    PFILETIME pft)
{
    BIDError err;
    time_t t;

    err = _BIDTimeToSecondsSince1970(context, pft, &t);
    if (err != BID_S_OK)
        return err;

    err = _BIDSetJsonTimestampValue(context, json, key, t);

    return err;
}

#ifdef GSSBID_DEBUG
void
_BIDOutputDebugJson(json_t *j)
{
    char *szJson = json_dumps(j, JSON_INDENT(8));

    OutputDebugString(szJson);
    OutputDebugString("\r\n");

    BIDFree(szJson);
}
#endif
