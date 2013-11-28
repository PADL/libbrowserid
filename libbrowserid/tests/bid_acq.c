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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <AppKit/AppKit.h>
#endif

#include "bid_private.h"
#include "browserid.h"

/*
 * Test acquiring an assertion and verifying it.
 */

#ifdef BUILD_AS_DSO
int _BIDTestAcquire(void)
#else
int main(int argc, const char *argv[])
#endif
{
    BIDError err;
    BIDContext context = NULL;
    char *assertion = NULL;
    const char *s;
    BIDIdentity identity = NULL;
    const char *audience = NULL;
    const char *szIdentity = NULL;
    time_t expires;
    json_t *j = NULL;
    uint32_t flags = 0;
    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_USER_AGENT | BID_CONTEXT_BROWSER_SILENT |
                       BID_CONTEXT_GSS | BID_CONTEXT_AUTHORITY_CACHE;

#ifndef BUILD_AS_DSO
    if (argc > 2 && !strcmp(argv[1], "-identity")) {
        szIdentity = argv[2];
        argc -= 2;
        argv += 2;
    }
    if (argc > 1 && !strcmp(argv[1], "-remote")) {
        options |= BID_CONTEXT_VERIFY_REMOTE;
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-nogss")) {
        options &= ~(BID_CONTEXT_GSS);
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-noauthoritycache")) {
        options &= ~(BID_CONTEXT_AUTHORITY_CACHE);
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-dh")) {
        options |= BID_CONTEXT_DH_KEYEX;
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-ecdh")) {
        options |= BID_CONTEXT_ECDH_KEYEX;
        argc--;
        argv++;
    }
    if (argc > 1) {
        audience = argv[1];
        argc--;
        argv++;
    }
#endif /* !BUILD_AS_DSO */

#ifdef __APPLE__
    /*
     * As of OS X Mavericks, the workaround in bid_webkit.m for app-ifying console
     * applications no longer works. So we need to initialize things here.
     */
    [NSApplication sharedApplication];
#endif

    err = BIDAcquireContext(NULL, options, NULL, &context);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertion(context, BID_C_NO_TICKET_CACHE,
                              audience ? audience : "host/www.persona.org",
                              NULL, 0, szIdentity, 0,
                              &assertion, NULL, &expires, &flags);
    BID_BAIL_ON_ERROR(err);

    printf("Assertion is %s\n", assertion);

#ifdef WIN32
    OutputDebugString(assertion);
    OutputDebugString("\r\n");
#endif

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE,
                             assertion, audience ? audience : "host/www.persona.org",
                             NULL, 0, time(NULL), 0, &identity, &expires, &flags);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentityJsonObject(context, identity, NULL, &j);
    BID_BAIL_ON_ERROR(err);

    json_dumpf(j, stdout, 0);
    printf("\n");

cleanup:
    if (context != BID_C_NO_CONTEXT) {
        BIDReleaseIdentity(context, identity);
        BIDReleaseContext(context);
    }
    BIDFree(assertion);
    json_decref(j);

    if (err != BID_S_OK) {
        BIDErrorToString(err, &s);
        fprintf(stderr, "libbrowserid error %s[%d]\n", s, err);
    }

    exit(err);
}
