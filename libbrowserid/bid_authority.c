/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

/* TODO make these configurable per context */
static const char *
_BIDSecondaryAuthorities[] = {
    "browserid.org",
    "diresworb.org",
    "dev.diresworb.org",
    "login.anosrep.org",
    "login.persona.org",
};

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *szHostname,
    BIDAuthority *pAuthority)
{
    BIDError err;
    json_t *authority = NULL;

    *pAuthority = NULL;

    BID_CONTEXT_VALIDATE(context);

    authority = json_object_get(context->AuthorityCache, szHostname);
    if (authority != NULL) {
        json_incref(authority);
        err = BID_S_OK;
    } else { 
        err = _BIDRetrieveDocument(context, szHostname, BID_WELL_KNOWN_URL, 0, &authority);
        BID_BAIL_ON_ERROR(err);

        json_object_set(context->AuthorityCache, szHostname, authority);
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

    BID_CONTEXT_VALIDATE(context);

    if (szHostname == NULL || szIssuer == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (strcasecmp(szHostname, szIssuer) == 0) {
        ok = 1;
    } else {
        for (i = 0; _BIDSecondaryAuthorities[i] != NULL; i++) {
            if (strcasecmp(szIssuer, _BIDSecondaryAuthorities[i]) == 0) {
                ok = 1;
                break;
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
