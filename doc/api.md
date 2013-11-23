# libbrowserid C API

## Overview

The libbrowserid API is defined in browserid.h (which will be installed in
/usr/local/include unless you've specified otherwise). The easiest way to learn
the API is to look at the example code in sample/, but here's a brief overview.

## Context object

Almost all libbrowserid APIs require a context. You can create a context with
the BIDAcquireContext() API. Contexts can be used for acquiring assertions
(BID\_CONTEXT\_USER\_AGENT), verifying them (BID\_CONTEXT\_RP) or both.

There are other flags in browserid.h that can be passed into
BIDAcquireContext(). For example, BID\_CONTEXT\_VERIFY\_REMOTE will use a
remote rather than a local verifier; BID\_CONTEXT\_AUTHORITY\_CACHE will cache
IdP certificates in a persistent database; BID\_CONTEXT\_REPLAY\_CACHE will use
a replay cache when verifying assertions. These are documented in browserid.h.

Example:

    err = BIDAcquireContext(NULL, /* szConfigFile */
                            BID_CONTEXT_USER_AGENT,
                            NULL, /* pvReserved */
                            &context);
    ...
    BIDReleaseContext(context);

## Identity object

TBC

## Acquiring an assertion

TBC

Example:

    err = BIDAcquireAssertion(context, BID_C_NO_TICKET_CACHE, argv[1],
                              NULL, 0, NULL, 0,
                              &assertion, NULL, &expires, &flags);
    ...
    BIDFreeAssertion(context, assertion);

## Verifying an assertion

TBC

Example:

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE,
                             argv[2], argv[1],
                             NULL, 0, time(NULL), 0, &identity,
                             &expires, &flags);
    ...
    if (BIDGetIdentitySubject(context, identity, &sub) == BID_S_OK)
        printf("Subject: %s\n", sub);
    if (BIDGetIdentityIssuer(context, identity, &iss) == BID_S_OK)
        printf("Issuer:  %s\n", sub);
    BIDReleaseIdentity(context, identity);

## CoreFoundation support

If you have the CoreFoundation internal headers installed (CFRuntime.h), then
you can build libbrowserid such that it exposes its types as first-class
CoreFoundation objects. You can also use the helper APIs in CFBrowserID.h.

## Windows port

The Windows port comes with some fairly significant limitations. First, the
build environment is not included. If you require support for legacy JWK keys
(the answer to which is probably yes), then you will need to link in the
OpenSSL bignum library and compile with -DBID\_DECIMAL\_BIGNUM.

Finally, and this is the greatest usability limitation: there is a bug where
you are only able to acquire an assertion with a fresh cookie/localstorage
state. On subsequent attempts, the Persona login window will hang.

On the positive side, the Windows port uses the platform native web, HTTP and
crypto APIs, so you do not need to link in WebKit, Curl or OpenSSL.
