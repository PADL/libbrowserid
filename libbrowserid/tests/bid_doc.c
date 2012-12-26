/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"
#include "bid_private.h"

int main(int argc, char *argv[])
{
    BIDError err;
    BIDContext context = NULL;
    BIDAuthority authority = NULL;
    BIDJWK pkey = NULL;
    const char *s;

    err = BIDAcquireContext(BID_CONTEXT_RP | BID_CONTEXT_VERIFY_REMOTE, &context);
    BID_BAIL_ON_ERROR(err);

    err = _BIDAcquireAuthority(context, "login.persona.org", &authority);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetAuthorityPublicKey(context, authority, &pkey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDIssuerIsAuthoritative(context, "padl.com", "login.persona.org");
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(pkey);
    _BIDReleaseAuthority(context, authority);
    BIDReleaseContext(context);

    if (err) {
        BIDErrorToString(err, &s);
        fprintf(stderr, "Error %d %s\n", err, s);
    }

    exit(err);
}
