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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "browserid.h"
#include "bid_private.h"

/*
 * Test verification
 */

int main(int argc, char *argv[])
{
    BIDError err;
    BIDContext context = NULL;
    BIDIdentity id = NULL;
    time_t expires;
    json_t *j = NULL;
    uint32_t flags = 0;
    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_GSS | BID_CONTEXT_AUTHORITY_CACHE;

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
    if (argc > 1 && !strcmp(argv[1], "-rcache")) {
        options |= BID_CONTEXT_REPLAY_CACHE;
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-noauthoritycache")) {
        options &= ~(BID_CONTEXT_AUTHORITY_CACHE);
        argc--;
        argv++;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-remote] [-nogss] [-rcache] [-noauthoritycache] assertion\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    err = BIDAcquireContext(options, &context);
    BID_BAIL_ON_ERROR(err);

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE, argv[1], argv[2], NULL, 0,
                             time(NULL), 0, &id, &expires, &flags);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentityJsonObject(context, id, NULL, &j);
    BID_BAIL_ON_ERROR(err);

    json_dumpf(j, stdout, 0);
    printf("\n");

cleanup:
    json_decref(j);
    BIDReleaseIdentity(context, id);
    BIDReleaseContext(context);
    if (err) {
        const char *s;
        BIDErrorToString(err, &s);
        fprintf(stderr, "Error %d %s\n", err, s);
    }

    exit(err);
}
