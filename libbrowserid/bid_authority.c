/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
_BIDAcquireDefaultAuthorityCache(BIDContext context)
{
    BIDError err;

    err = _BIDAcquireCache(context, ".browserid.authority.json", 0, &context->AuthorityCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *szHostname,
    time_t verificationTime,
    BIDAuthority *pAuthority)
{
    BIDError err = BID_S_CACHE_NOT_FOUND;
    json_t *authority = NULL;
    time_t expiryTime = 0;

    *pAuthority = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (context->ContextOptions & BID_CONTEXT_AUTHORITY_CACHE) {
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
    const char **secondaryAuthorities;

    BID_CONTEXT_VALIDATE(context);

    if (szHostname == NULL || szIssuer == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    /* XXX case-sensitive? */
    if (strcasecmp(szHostname, szIssuer) == 0)
        bIsAuthoritative = 1;

    if (!bIsAuthoritative) {
        err = BIDGetContextParam(context, BID_PARAM_SECONDARY_AUTHORITIES, (void **)&secondaryAuthorities);
        BID_BAIL_ON_ERROR(err);

        for (i = 0; secondaryAuthorities[i] != NULL; i++) {
            if (strcasecmp(szIssuer, secondaryAuthorities[i]) == 0) {
                bIsAuthoritative = 1;
                break;
            }
        }
    }

    if (!bIsAuthoritative) {
        uint32_t maxDelegs;
        const char *szAuthority;

        err = BIDGetContextParam(context, BID_PARAM_MAX_DELEGATIONS, (void **)&maxDelegs);
        BID_BAIL_ON_ERROR(err);

        err = _BIDAcquireAuthority(context, szHostname, verificationTime, &authority);
        BID_BAIL_ON_ERROR(err);

        for (i = 0, bIsAuthoritative = -1; i < maxDelegs; i++) {
            szAuthority = json_string_value(json_object_get(authority, "authority"));
            if (szAuthority != NULL) {
                if (strcasecmp(szIssuer, szAuthority) == 0) {
                    bIsAuthoritative = 1;
                } else {
                    BIDAuthority tmp;

                    err = _BIDAcquireAuthority(context, szAuthority, verificationTime, &tmp);
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
