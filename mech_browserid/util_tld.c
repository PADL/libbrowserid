/*
 * Copyright (c) 2011, JANET(UK)
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
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Thread local data abstraction, using pthreads on Unix and the TlsXXX
 * APIs on Windows.
 */

#include "gssapiP_bid.h"

/* Clean up thread-local data; called on thread detach */
static void
destroyThreadLocalData(struct gss_bid_thread_local_data *tld)
{
    if (tld->statusInfo != NULL)
        gssBidDestroyStatusInfo(tld->statusInfo);
    if (tld->krbContext != NULL)
        gssBidDestroyKrbContext(tld->krbContext);
    GSSBID_FREE(tld);
}

#ifdef WIN32

/*
 * This is the TLS index returned by TlsAlloc() on process init.
 * Each thread, on thread attach in DllMain(), allocates its thread-local
 * data and uses this index with TlsSetValue() to store it.
 * It can then subsequently be retrieved with TlsGetValue().
 */
static DWORD tlsIndex = TLS_OUT_OF_INDEXES;

/* Access thread-local data */
struct gss_bid_thread_local_data *
gssBidGetThreadLocalData(void)
{
    struct gss_bid_thread_local_data *tlsData;

    GSSBID_ASSERT(tlsIndex != TLS_OUT_OF_INDEXES);

    tlsData = TlsGetValue(tlsIndex);
    if (tlsData == NULL) {
        tlsData = GSSBID_CALLOC(1, sizeof(*tlsData));
        TlsSetValue(tlsIndex, tlsData);
    }

    return tlsData;
}

BOOL WINAPI
DllMain(HINSTANCE hDLL,     /* DLL module handle */
        DWORD reason,       /* reason called */
        LPVOID reserved)    /* reserved */
{
    struct gss_bid_thread_local_data *tlsData;
    OM_uint32 major, minor;

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            /* Allocate a TLS index. */
            major = gssBidInitiatorInit(&minor);
            if (GSS_ERROR(major))
                return FALSE;

            tlsIndex = TlsAlloc();
            if (tlsIndex == TLS_OUT_OF_INDEXES)
                return FALSE;
            /* No break: Initialize the index for first thread.*/
        case DLL_THREAD_ATTACH:
            /* Initialize the TLS index for this thread. */
            tlsData = GSSBID_CALLOC(1, sizeof(*tlsData));
            if (tlsData == NULL)
                return FALSE;
            TlsSetValue(tlsIndex, tlsData);
            break;
        case DLL_THREAD_DETACH:
            /* Release the allocated memory for this thread. */
            tlsData = TlsGetValue(tlsIndex);
            if (tlsData != NULL) {
                destroyThreadLocalData(tlsData);
                TlsSetValue(tlsIndex, NULL);
            }
            break;
        case DLL_PROCESS_DETACH:
            /* Release the TLS index. */
            TlsFree(tlsIndex);
            gssBidFinalize();
            break;
        default:
            break;
    }

    return TRUE;
    UNREFERENCED_PARAMETER(hDLL);
    UNREFERENCED_PARAMETER(reserved);
}

#else /* WIN32 */

/* pthreads implementation */

static GSSBID_THREAD_ONCE tldKeyOnce = GSSBID_ONCE_INITIALIZER;
static GSSBID_THREAD_KEY tldKey;

static void
pthreadDestroyThreadLocalData(void *arg)
{
    struct gss_bid_thread_local_data* tld = arg;

    if (tld != NULL)
        destroyThreadLocalData(tld);
}

static void
createThreadLocalDataKey(void)
{
    GSSBID_KEY_CREATE(&tldKey, pthreadDestroyThreadLocalData);
}

struct gss_bid_thread_local_data *
gssBidGetThreadLocalData(void)
{
    struct gss_bid_thread_local_data *tld;

    GSSBID_ONCE(&tldKeyOnce, createThreadLocalDataKey);

    tld = GSSBID_GETSPECIFIC(tldKey);
    if (tld == NULL) {
        tld = GSSBID_CALLOC(1, sizeof(*tld));
        if (tld == NULL)
            return NULL;

        GSSBID_SETSPECIFIC(tldKey, tld);
    }

    return tld;
}

#endif /* WIN32 */
