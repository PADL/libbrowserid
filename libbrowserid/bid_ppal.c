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

#include <sys/time.h>

#ifdef __APPLE__
static CFTypeID _BIDIdentityTypeID;
static CFTypeID _BIDContextTypeID;
static CFTypeID _BIDCacheTypeID;
#endif

static void
_BIDLibraryInit(void) __attribute__((__constructor__));

#ifdef __APPLE__
CFTypeID
BIDIdentityGetTypeID(void)
{
    return _BIDIdentityTypeID;
}

CFTypeID
BIDContextGetTypeID(void)
{
    return _BIDContextTypeID;
}

CFTypeID
BIDCacheGetTypeID(void)
{
    return _BIDCacheTypeID;
}

static const CFRuntimeClass _BIDIdentityClass = {
    0,
    "BIDIdentity",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeIdentity,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    NULL, // copyDebugDesc
};

static const CFRuntimeClass _BIDContextClass = {
    0,
    "BIDContext",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeContext,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    NULL, // copyDebugDesc
};

static const CFRuntimeClass _BIDCacheClass = {
    0,
    "BIDCache",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeCache,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    NULL, // copyDebugDesc
};
#endif /* __APPLE__ */

static void
_BIDLibraryInit(void)
{
    json_set_alloc_funcs(BIDMalloc, BIDFree);

#ifdef __APPLE__
    _BIDIdentityTypeID = _CFRuntimeRegisterClass(&_BIDIdentityClass);
    _BIDContextTypeID = _CFRuntimeRegisterClass(&_BIDContextClass);
    _BIDCacheTypeID = _CFRuntimeRegisterClass(&_BIDCacheClass);
#endif
}

BIDError
_BIDGetCurrentJsonTimestamp(
    BIDContext context BID_UNUSED,
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

#ifdef GSSBID_DEBUG
void
_BIDOutputDebugJson(json_t *j)
{
    if (j == NULL)
        return;

    json_dumpf(j, stdout, JSON_INDENT(8));
    fprintf(stdout, "\n");
}
#endif
