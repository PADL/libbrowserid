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

#include <AppKit/AppKit.h>

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
    time_t expires;
    json_t *j = NULL;

    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_USER_AGENT |
                       BID_CONTEXT_GSS | BID_CONTEXT_ASSERTION_CACHE | BID_CONTEXT_AUTHORITY_CACHE;

#ifndef BUILD_AS_DSO
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
    if (argc > 1 && !strcmp(argv[1], "-nocache")) {
        options &= ~(BID_CONTEXT_ASSERTION_CACHE);
        argc--;
        argv++;
    }
    if (argc > 1 && !strcmp(argv[1], "-noauthoritycache")) {
        options &= ~(BID_CONTEXT_AUTHORITY_CACHE);
        argc--;
        argv++;
    }
    if (argc > 1) {
        audience = argv[1];
        argc--;
        argv++;
    }
#endif /* !BUILD_AS_DSO */

    err = BIDAcquireContext(options, &context);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertion(context, "host/www.browserid.org", NULL, 0,
                              &assertion, NULL, &expires);
    BID_BAIL_ON_ERROR(err);

    err = BIDVerifyAssertion(context, assertion, audience ? audience : "host/www.browserid.org",
                             NULL, 0, time(NULL), &identity, &expires);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentityJsonObject(context, identity, NULL, &j);
    BID_BAIL_ON_ERROR(err);

    json_dumpf(j, stdout, 0);
    printf("\n");

cleanup:
    BIDReleaseIdentity(context, identity);
    BIDReleaseContext(context);
    BIDFree(assertion);
    json_decref(j);

    if (err != BID_S_OK) {
        BIDErrorToString(err, &s);
        fprintf(stderr, "libbrowserid error %s[%d]\n", s, err);
    }

    exit(err);
}
