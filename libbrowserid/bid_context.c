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
    context->Skew = 60 * 5; /* 5 minutes */
    context->MaxDelegations = 6;
    context->DhKeySize = 1024;

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

    if ((ulContextOptions & BID_CONTEXT_REAUTH) &&
        (ulContextOptions & BID_CONTEXT_USER_AGENT)) {
        err = _BIDAcquireDefaultTicketCache(context);
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
    _BIDReleaseCache(context, context->TicketCache);
    _BIDReleaseCache(context, context->RPCertConfig);

    memset(context, 0, sizeof(*context));
    BIDFree(context);

    return BID_S_OK;
}

BIDError
BIDSetContextParam(
    BIDContext context,
    BIDContextParameter ulParam,
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
    case BID_PARAM_DH_KEYEX_SIZE:
        context->DhKeySize = *(uint32_t *)value;
        break;
    case BID_PARAM_AUTHORITY_CACHE_NAME:
    case BID_PARAM_REPLAY_CACHE_NAME:
    case BID_PARAM_TICKET_CACHE_NAME:
    case BID_PARAM_RP_CERT_CONFIG_NAME: {
        const char *szCacheName;
        BIDCache cache, *pCache = NULL;
        uint32_t ulFlags = 0;

        if (ulParam == BID_PARAM_AUTHORITY_CACHE_NAME)
            pCache = &context->AuthorityCache;
        else if (ulParam == BID_PARAM_REPLAY_CACHE_NAME)
            pCache = &context->ReplayCache;
        else if (ulParam == BID_PARAM_TICKET_CACHE_NAME)
            pCache = &context->TicketCache;
        else if (ulParam == BID_PARAM_RP_CERT_CONFIG_NAME) {
            pCache = &context->RPCertConfig;
            ulFlags |= BID_CACHE_FLAG_UNVERSIONED;
        }

        if (*pCache != NULL) {
            err = _BIDGetCacheName(context, *pCache, &szCacheName);
            if (err != BID_S_OK)
                return err;

            if (strcmp(szCacheName, (const char *)value) == 0)
                break;
        }

        err = _BIDAcquireCache(context, (const char *)value, ulFlags, &cache);
        if (err == BID_S_OK) {
            _BIDReleaseCache(context, *pCache);
            *pCache = cache;
        }
        break;
    }
    case BID_PARAM_AUTHORITY_CACHE:
    case BID_PARAM_REPLAY_CACHE:
    case BID_PARAM_TICKET_CACHE: {
        BIDCache *pCache = NULL;

        if (ulParam == BID_PARAM_AUTHORITY_CACHE_NAME)
            pCache = &context->AuthorityCache;
        else if (ulParam == BID_PARAM_REPLAY_CACHE_NAME)
            pCache = &context->ReplayCache;
        else if (ulParam == BID_PARAM_TICKET_CACHE_NAME)
            pCache = &context->TicketCache;

        _BIDReleaseCache(context, *pCache);
        *pCache = (BIDCache)value;
    }
    case BID_PARAM_PARENT_WINDOW:
        context->ParentWindow = value;
        break;
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}

BIDError
BIDGetContextParam(
    BIDContext context,
    BIDContextParameter ulParam,
    void **pValue)
{
    BIDError err = BID_S_OK;

    BID_CONTEXT_VALIDATE(context);

    *pValue = NULL;

    switch (ulParam) {
    case BID_PARAM_SECONDARY_AUTHORITIES:
        *pValue = context->SecondaryAuthorities;
        if (*pValue == NULL)
            *pValue = (void *)_BIDSecondaryAuthorities;
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
    case BID_PARAM_REPLAY_CACHE_NAME:
        err = _BIDGetCacheName(context, context->ReplayCache, (const char **)pValue);
        break;
    case BID_PARAM_AUTHORITY_CACHE_NAME:
        err = _BIDGetCacheName(context, context->AuthorityCache, (const char **)pValue);
        break;
    case BID_PARAM_TICKET_CACHE_NAME:
        err = _BIDGetCacheName(context, context->TicketCache, (const char **)pValue);
        break;
    case BID_PARAM_RP_CERT_CONFIG_NAME:
        err = _BIDGetCacheName(context, context->TicketCache, (const char **)pValue);
        break;
    case BID_PARAM_REPLAY_CACHE:
        *pValue = context->ReplayCache;
        break;
    case BID_PARAM_AUTHORITY_CACHE:
        *pValue = context->AuthorityCache;
        break;
    case BID_PARAM_TICKET_CACHE:
        *pValue = context->TicketCache;
        break;
    case BID_PARAM_DH_KEYEX_SIZE:
        *((uint32_t *)pValue) = context->DhKeySize;
        break;
    case BID_PARAM_PARENT_WINDOW:
        *((void **)pValue) = context->ParentWindow;
        break;
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}
