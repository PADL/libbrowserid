/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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

    err = BIDVerifyAssertion(context, argv[1], argv[2], NULL, 0,
                             time(NULL), &id, &expires);
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
