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

#include "bid_private.h"

BIDError
_BIDAcquireDefaultAuthorityCache(BIDContext context)
{
    return _BIDAcquireCacheForUser(context, "browserid.authority", &context->AuthorityCache);
}

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *szHostname,
    time_t verificationTime,
    int bUseCacheIfAvailable,
    BIDAuthority *pAuthority)
{
    BIDError err = BID_S_CACHE_NOT_FOUND;
    json_t *authority = NULL;
    time_t expiryTime = 0;

    *pAuthority = NULL;

    BID_CONTEXT_VALIDATE(context);

    if ((context->ContextOptions & BID_CONTEXT_AUTHORITY_CACHE) && bUseCacheIfAvailable) {
        err = _BIDGetCacheObject(context, context->AuthorityCache, szHostname, &authority);
        if (err == BID_S_OK) {
            err = _BIDValidateExpiry(context, verificationTime, authority);
            if (err == BID_S_EXPIRED_ASSERTION)
                err = BID_S_EXPIRED_CERT;
        }
    }

    if (err != BID_S_OK) {
        err = _BIDRetrieveDocument(context, szHostname, BID_WELL_KNOWN_URL, 0, &authority, &expiryTime);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetJsonTimestampValue(context, authority, "exp", expiryTime);
        BID_BAIL_ON_ERROR(err);

        if (context->ContextOptions & BID_CONTEXT_AUTHORITY_CACHE)
            _BIDSetCacheObject(context, context->AuthorityCache, szHostname, authority);
    }

    *pAuthority = authority;

cleanup:
    return err;
}

BIDError
_BIDGetAuthorityPublicKey(
    BIDContext context BID_UNUSED,
    BIDAuthority authority,
    BIDJWKSet *pKey)
{
    json_t *key;

    key = json_object_get(authority, "public-key");
    if (key == NULL)
        return BID_S_NO_KEY;

    *pKey = json_incref(authority); /* yes, because bid_jwt.c looks at this as keybag */

    return BID_S_OK;
}

static int
_BIDAuthorityEqual(
    const char *a1,
    const char *a2)
{
    return (strcasecmp(a1, a2) == 0);
}

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If the expected issuer was designated by the certificate rather than
 * discovered given the user's email address, then the issuer SHOULD be
 * login.persona.org, otherwise reject the assertion.
 */
BIDError
_BIDIssuerIsAuthoritative(
    BIDContext context,
    const char *szHostname,
    const char *szIssuer,
    time_t verificationTime)
{
    BIDError err;
    size_t i;
    int bIsAuthoritative = 0;
    BIDAuthority authority = NULL;
    const char **secondaryAuthorities = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (szHostname == NULL || szIssuer == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    /* XXX case-sensitive? */
    if (_BIDAuthorityEqual(szHostname, szIssuer))
        bIsAuthoritative = 1;

    if (!bIsAuthoritative) {
        err = BIDGetContextParam(context, BID_PARAM_SECONDARY_AUTHORITIES, (void **)&secondaryAuthorities);
        BID_BAIL_ON_ERROR(err);

        if (secondaryAuthorities != NULL) {
            for (i = 0; secondaryAuthorities[i] != NULL; i++) {
                if (_BIDAuthorityEqual(szIssuer, secondaryAuthorities[i])) {
                    bIsAuthoritative = 1;
                    break;
                }
            }
        }
    }

    if (!bIsAuthoritative) {
        uint32_t maxDelegs;
        const char *szAuthority;

        err = BIDGetContextParam(context, BID_PARAM_MAX_DELEGATIONS, (void **)&maxDelegs);
        BID_BAIL_ON_ERROR(err);

        err = _BIDAcquireAuthority(context, szHostname, verificationTime, TRUE, &authority);
        BID_BAIL_ON_ERROR(err);

        for (i = 0, bIsAuthoritative = -1; i < maxDelegs; i++) {
            szAuthority = json_string_value(json_object_get(authority, "authority"));
            if (szAuthority != NULL) {
                if (_BIDAuthorityEqual(szIssuer, szAuthority)) {
                    bIsAuthoritative = 1;
                } else {
                    BIDAuthority tmp;

                    err = _BIDAcquireAuthority(context, szAuthority, verificationTime, TRUE, &tmp);
                    BID_BAIL_ON_ERROR(err);

                    json_decref(authority);
                    authority = tmp;
                }
            } else {
                bIsAuthoritative = 0;
            }

            if (bIsAuthoritative != -1) {
                break;
            }
        }
    }

    err = (bIsAuthoritative == 1) ? BID_S_OK : BID_S_UNTRUSTED_ISSUER;

cleanup:
    json_decref(authority);

    return err;
}

BIDError
_BIDReleaseAuthority(
    BIDContext context BID_UNUSED,
    BIDAuthority authority)
{
    if (authority == NULL)
        return BID_S_INVALID_PARAMETER;

    json_decref(authority);
    return BID_S_OK;
}
