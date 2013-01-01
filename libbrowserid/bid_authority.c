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

    err = _BIDAcquireCache(context, ".browserid.authority.json", &context->AuthorityCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *szHostname,
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
            expiryTime = json_integer_value(json_object_get(authority, "expires"));
            if (expiryTime != 0 && expiryTime < time(NULL))
                err = BID_S_EXPIRED_CERT;
        }
    }

    if (err != BID_S_OK) {
        err = _BIDRetrieveDocument(context, szHostname, BID_WELL_KNOWN_URL, 0, &authority, &expiryTime);
        BID_BAIL_ON_ERROR(err);

        if (expiryTime != 0)
            json_object_set_new(authority, "expires", json_integer(expiryTime));

        json_dumpf(authority, stdout, JSON_INDENT(4));

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

BIDError
_BIDIssuerIsAuthoritative(
    BIDContext context,
    const char *szHostname,
    const char *szIssuer)
{
    BIDError err;
    size_t i;
    int ok = 0;
    BIDAuthority authority = NULL;
    const char **secondaryAuthorities;

    BID_CONTEXT_VALIDATE(context);

    if (szHostname == NULL || szIssuer == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    /* XXX case-sensitive? */
    if (strcasecmp(szHostname, szIssuer) == 0)
        ok = 1;

    if (!ok) {
        err = BIDGetContextParam(context, BID_PARAM_SECONDARY_AUTHORITIES, (void **)&secondaryAuthorities);
        BID_BAIL_ON_ERROR(err);

        for (i = 0; secondaryAuthorities[i] != NULL; i++) {
            if (strcasecmp(szIssuer, secondaryAuthorities[i]) == 0) {
                ok = 1;
                break;
            }
        }
    }

    if (!ok) {
        uint32_t maxDelegs;
        const char *szAuthority;

        err = BIDGetContextParam(context, BID_PARAM_MAX_DELEGATIONS, (void **)&maxDelegs);
        BID_BAIL_ON_ERROR(err);

        err = _BIDAcquireAuthority(context, szHostname, &authority);
        BID_BAIL_ON_ERROR(err);

        for (i = 0, ok = -1; i < maxDelegs; i++) {
            szAuthority = json_string_value(json_object_get(authority, "authority"));
            if (szAuthority != NULL) {
                if (strcasecmp(szIssuer, szAuthority) == 0) {
                    ok = 1;
                } else {
                    BIDAuthority tmp;

                    err = _BIDAcquireAuthority(context, szAuthority, &tmp);
                    BID_BAIL_ON_ERROR(err);

                    json_decref(authority);
                    authority = tmp;
                }
            } else {
                ok = 0;
            }

            if (ok != -1) {
                break;
            }
        }
    }

    err = (ok == 1) ? BID_S_OK : BID_S_UNTRUSTED_ISSUER;

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
