/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

static const char *
_BIDSecondaryAuthorities[] = {
    "browserid.org",
    "diresworb.org",
    "dev.diresworb.org",
    "login.anosrep.org",
    "login.persona.org",
};

BIDError
BIDAcquireContext(
    uint32_t ulContextOptions,
    BIDContext *pContext)
{
    BIDError err;
    BIDContext context = NULL;

    *pContext = BID_C_NO_CONTEXT;

    context = BIDCalloc(1, sizeof(*context));
    if (context == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    context->ContextOptions = ulContextOptions;
    context->MaxDelegations = 6;

    if (ulContextOptions & BID_CONTEXT_AUTHORITY_CACHE) {
        if ((ulContextOptions & BID_CONTEXT_RP) == 0) {
            err = BID_S_INVALID_PARAMETER;
            goto cleanup;
        }

        err = _BIDAcquireDefaultAuthorityCache(context);
        BID_BAIL_ON_ERROR(err);
    }

    if (ulContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        if ((ulContextOptions & BID_CONTEXT_RP) == 0) {
            err = BID_S_INVALID_PARAMETER;
            goto cleanup;
        }

        err = _BIDAcquireDefaultReplayCache(context);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    *pContext = context;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseContext(context);

    return err;
}

BIDError
BIDReleaseContext(BIDContext context)
{
    if (context == BID_C_NO_CONTEXT)
        return BID_S_NO_CONTEXT;

    if (context->SecondaryAuthorities) {
        char **p;

        for (p = context->SecondaryAuthorities; *p != NULL; p++)
            BIDFree(*p);
        BIDFree(context->SecondaryAuthorities);
    }

    BIDFree(context->VerifierUrl);
    _BIDReleaseCache(context, context->AuthorityCache);
    _BIDReleaseCache(context, context->ReplayCache);

    memset(context, 0, sizeof(*context));
    BIDFree(context);

    return BID_S_OK;
}

BIDError
BIDSetContextParam(
    BIDContext context,
    uint32_t ulParam,
    void *value)
{
    BIDError err = BID_S_OK;

    BID_CONTEXT_VALIDATE(context);

    switch (ulParam) {
    case BID_PARAM_SECONDARY_AUTHORITIES:
        err = BID_S_NOT_IMPLEMENTED;
        break;
    case BID_PARAM_VERIFIER_URL:
        err = _BIDDuplicateString(context, value, &context->VerifierUrl);
        break;
    case BID_PARAM_MAX_DELEGATIONS:
        context->MaxDelegations = *(uint32_t *)value;
        break;
    case BID_PARAM_SKEW:
        context->Skew = *(uint32_t *)value;
        break;
    case BID_PARAM_AUTHORITY_CACHE:
    case BID_PARAM_REPLAY_CACHE: {
        const char *szCacheName;
        BIDCache cache, *pCache;

        if (ulParam == BID_PARAM_AUTHORITY_CACHE)
            pCache = &context->AuthorityCache;
        else
            pCache = &context->ReplayCache;

        err = _BIDGetCacheName(context, *pCache, &szCacheName);
        if (err != BID_S_OK)
            return err;

        if (strcmp(szCacheName, (const char *)value) == 0)
            break;

        err = _BIDAcquireCache(context, (const char *)value, &cache);
        if (err == BID_S_OK) {
            _BIDReleaseCache(context, *pCache);
            *pCache = cache;
        }
        break;
    }
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}

BIDError
BIDGetContextParam(
    BIDContext context,
    uint32_t ulParam,
    void **pValue)
{
    BIDError err = BID_S_OK;

    BID_CONTEXT_VALIDATE(context);

    *pValue = NULL;

    switch (ulParam) {
    case BID_PARAM_SECONDARY_AUTHORITIES:
        *pValue = context->SecondaryAuthorities;
        if (*pValue == NULL)
            *pValue = _BIDSecondaryAuthorities;
        break;
    case BID_PARAM_VERIFIER_URL:
        if (context->VerifierUrl != NULL)
            *pValue = context->VerifierUrl;
        else
            *pValue = BID_VERIFIER_URL;
        break;
    case BID_PARAM_MAX_DELEGATIONS:
        *((uint32_t *)pValue) = context->MaxDelegations;
        break;
    case BID_PARAM_JSON_ERROR_INFO:
        *pValue = &context->JsonError;
        break;
    case BID_PARAM_SKEW:
        *((uint32_t *)pValue) = context->Skew;
        break;
    case BID_PARAM_CONTEXT_OPTIONS:
        *((uint32_t *)pValue) = context->ContextOptions;
        break;
    case BID_PARAM_REPLAY_CACHE:
        err = _BIDGetCacheName(context, context->ReplayCache, (const char **)pValue);
        break;
    case BID_PARAM_AUTHORITY_CACHE:
        err = _BIDGetCacheName(context, context->AuthorityCache, (const char **)pValue);
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}
