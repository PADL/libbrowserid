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

static const char *
_BIDSecondaryAuthorities[] = {
    "browserid.org",
    "diresworb.org",
    "dev.diresworb.org",
    "login.anosrep.org",
    "login.persona.org",
    NULL
};

static BIDError
_BIDGetConfigIntegerValue(
    BIDContext context,
    const char *szKey,
    uint32_t ulDefaultValue,
    uint32_t *pulValue)
{
    json_t *value;

    *pulValue = 0;

    if (_BIDGetCacheObject(context, context->Config, szKey, &value) == BID_S_OK) {
        *pulValue = _BIDJsonUInt32Value(value);
        json_decref(value);
    } else if (ulDefaultValue != 0) {
        *pulValue = ulDefaultValue;
    } else {
        return BID_S_UNKNOWN_JSON_KEY;
    }

    return BID_S_OK;
}

#if 0
static BIDError
_BIDGetConfigStringValue(
    BIDContext context,
    const char *szKey,
    const char *szDefaultValue,
    char **pszValue)
{
    BIDError err;
    json_t *value;
    const char *szValue = NULL;

    *pszValue = NULL;

    if (_BIDGetCacheObject(context, context->Config, szKey, &value) == BID_S_OK)
        szValue = json_string_value(value);

    if (szValue == NULL)
        szValue = szDefaultValue;
    if (szValue == NULL)
        return BID_S_UNKNOWN_JSON_KEY;

    err = _BIDDuplicateString(context, szDefaultValue, pszValue);

    json_decref(value);

    return err;
}
#endif

static BIDError
_BIDGetConfigStringValueArray(
    BIDContext context,
    const char *szKey,
    const char **rgszDefaultValues,
    char ***prgszValues)
{
    BIDError err;
    size_t i;
    char **rgszValues = NULL;
    json_t *value = NULL;

    *prgszValues = NULL;

    if (_BIDGetCacheObject(context, context->Config, szKey, &value) == BID_S_OK &&
        _BIDGetJsonStringValueArray(context, value, NULL, prgszValues) == BID_S_OK) {
        err = BID_S_OK;
        goto cleanup;
    }

    if (rgszDefaultValues == NULL) {
        err = BID_S_UNKNOWN_JSON_KEY;
        goto cleanup;
    }

    for (i = 0; rgszDefaultValues[i] != NULL; i++)
        ;

    rgszValues = BIDCalloc(i + 1, sizeof(char *));
    if (rgszValues == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 0; rgszDefaultValues[i] != NULL; i++) {
        err = _BIDDuplicateString(context, rgszDefaultValues[i], &rgszValues[i]);
        BID_BAIL_ON_ERROR(err);
    }

    rgszValues[i] = NULL;

    *prgszValues = rgszValues;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && rgszValues != NULL) {
        for (i = 0; rgszValues[i] != NULL; i++)
            BIDFree(rgszValues[i]);
        BIDFree(rgszValues);
    }

    json_decref(value);

    return BID_S_OK;
}

BIDError
BIDAcquireContext(
    const char *szConfig,
    uint32_t ulContextOptions,
    BIDAcquireContextArgs args,
    BIDContext *pContext)
{
    BIDError err;
    BIDContext context = NULL;

    *pContext = BID_C_NO_CONTEXT;

    if (args != NULL &&
        (args->Version != BID_ACQUIRE_CONTEXT_ARGS_VERSION ||
         args->cbHeaderLength != sizeof(*args) ||
         args->cbStructureLength < args->cbHeaderLength)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

#ifdef __APPLE__
    context = (BIDContext)_CFRuntimeCreateInstance(args && args->CFAllocator ? args->CFAllocator : kCFAllocatorDefault,
                                                   BIDContextGetTypeID(),
                                                   sizeof(*context) - sizeof(CFRuntimeBase), NULL);
#else
    context = BIDMalloc(sizeof(*context));
#endif
    if (context == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    context->ContextOptions         = ulContextOptions;
    context->SecondaryAuthorities   = NULL;
    memset(&context->JsonError, 0, sizeof(context->JsonError));
    context->VerifierUrl            = NULL;
    context->MaxDelegations         = 0;
    context->Skew                   = 0;
    context->AuthorityCache         = BID_C_NO_AUTHORITY_CACHE;
    context->ReplayCache            = BID_C_NO_REPLAY_CACHE;
    context->TicketCache            = BID_C_NO_TICKET_CACHE;
    context->ECDHCurve              = 0;
    context->TicketLifetime         = 0;
    context->RenewLifetime          = 0;
    context->Config                 = NULL;
    context->ParentWindow           = NULL;

    if (szConfig != NULL) {
        err = BIDSetContextParam(context, BID_PARAM_CONFIG_NAME, (void *)szConfig);
        BID_BAIL_ON_ERROR(err);
    }

    /* default clock skew is 5 minutes */
    _BIDGetConfigIntegerValue(context, "maxclockskew",    60 * 5,
                              &context->Skew);

    if (ulContextOptions & BID_CONTEXT_RP) {
        /* default delegations level is 6 */
        _BIDGetConfigIntegerValue(context, "maxdelegations",  6,
                                  &context->MaxDelegations);
        /* default ticket lifetime is 10 hours */
        _BIDGetConfigIntegerValue(context, "maxticketage",    60 * 60 * 10,
                                  &context->TicketLifetime);
        /* default renew lifetime is 7 days */
        _BIDGetConfigIntegerValue(context, "maxrenewage",     60 * 60 * 24 * 7,
                                  &context->RenewLifetime);

        err = _BIDGetConfigStringValueArray(context, "secondaryauthorities",
                                            _BIDSecondaryAuthorities,
                                            &context->SecondaryAuthorities);
        BID_BAIL_ON_ERROR(err);
    }

    if (ulContextOptions & BID_CONTEXT_AUTHORITY_CACHE) {
        if ((ulContextOptions & BID_CONTEXT_RP) == 0) {
            err = BID_S_INVALID_PARAMETER;
            goto cleanup;
        }

        if (args != NULL && args->AuthorityCache != BID_C_NO_AUTHORITY_CACHE) {
            context->AuthorityCache = args->AuthorityCache;
        } else {
            err = _BIDAcquireDefaultAuthorityCache(context);
            BID_BAIL_ON_ERROR(err);
        }

        BID_ASSERT(context->AuthorityCache != BID_C_NO_AUTHORITY_CACHE);
    }

    if (ulContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        if ((ulContextOptions & BID_CONTEXT_RP) == 0) {
            err = BID_S_INVALID_PARAMETER;
            goto cleanup;
        }

        if (args != NULL && args->ReplayCache != BID_C_NO_REPLAY_CACHE) {
            context->ReplayCache = args->ReplayCache;
        } else {
            err = _BIDAcquireDefaultReplayCache(context);
            BID_BAIL_ON_ERROR(err);
        }

        BID_ASSERT(context->ReplayCache != BID_C_NO_REPLAY_CACHE);
    }

    if (ulContextOptions & BID_CONTEXT_TICKET_CACHE) {
        if ((ulContextOptions & BID_CONTEXT_REAUTH) == 0 ||
            (ulContextOptions & BID_CONTEXT_USER_AGENT) == 0) {
            err = BID_S_INVALID_PARAMETER;
            goto cleanup;
        }

        if (args != NULL && args->TicketCache != BID_C_NO_TICKET_CACHE) {
            context->TicketCache = args->TicketCache;
        } else {
            err = _BIDAcquireDefaultTicketCache(context);
            BID_BAIL_ON_ERROR(err);
        }

        BID_ASSERT(context->TicketCache != BID_C_NO_TICKET_CACHE);
    }

    if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX)
        context->ECDHCurve = BID_CONTEXT_ECDH_CURVE_P256;
    else
        context->ECDHCurve = 0;

    err = BID_S_OK;
    *pContext = context;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseContext(context);

    return err;
}

void
_BIDFinalizeContext(BIDContext context)
{
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
    _BIDReleaseCache(context, context->Config);
}

BIDError
BIDReleaseContext(BIDContext context)
{
    if (context == BID_C_NO_CONTEXT)
        return BID_S_NO_CONTEXT;

#ifdef __APPLE__
    CFRelease(context);
#else
    _BIDFinalizeContext(context);
    BIDFree(context);
#endif

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
    case BID_PARAM_AUTHORITY_CACHE_NAME:
    case BID_PARAM_REPLAY_CACHE_NAME:
    case BID_PARAM_TICKET_CACHE_NAME:
    case BID_PARAM_CONFIG_NAME: {
        const char *szCacheName;
        BIDCache cache, *pCache = NULL;
        uint32_t ulFlags = 0;

        if (ulParam == BID_PARAM_AUTHORITY_CACHE_NAME)
            pCache = &context->AuthorityCache;
        else if (ulParam == BID_PARAM_REPLAY_CACHE_NAME)
            pCache = &context->ReplayCache;
        else if (ulParam == BID_PARAM_TICKET_CACHE_NAME)
            pCache = &context->TicketCache;
        else if (ulParam == BID_PARAM_CONFIG_NAME) {
            pCache = &context->Config;
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
    case BID_PARAM_TICKET_CACHE:
    case BID_PARAM_CONFIG_CACHE: {
        BIDCache *pCache = NULL;

        if (ulParam == BID_PARAM_AUTHORITY_CACHE)
            pCache = &context->AuthorityCache;
        else if (ulParam == BID_PARAM_REPLAY_CACHE)
            pCache = &context->ReplayCache;
        else if (ulParam == BID_PARAM_TICKET_CACHE)
            pCache = &context->TicketCache;
        else if (ulParam == BID_PARAM_CONFIG_CACHE)
            pCache = &context->Config;

        BID_ASSERT(pCache != NULL);

        *pCache = (BIDCache)value;
    }
    case BID_PARAM_PARENT_WINDOW:
        context->ParentWindow = value;
        break;
    case BID_PARAM_TICKET_LIFETIME:
        context->TicketLifetime = *((uint32_t *)value);
        break;
    case BID_PARAM_RENEW_LIFETIME:
        context->RenewLifetime = *((uint32_t *)value);
        break;
    case BID_PARAM_ECDH_CURVE:
        if ((context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) == 0 ||
            value == NULL)
            return BID_S_INVALID_PARAMETER;

        if (strcmp(value, BID_ECDH_CURVE_P256) == 0)
            context->ECDHCurve = BID_CONTEXT_ECDH_CURVE_P256;
        else if (strcmp(value, BID_ECDH_CURVE_P384) == 0)
            context->ECDHCurve = BID_CONTEXT_ECDH_CURVE_P384;
        else if (strcmp(value, BID_ECDH_CURVE_P521) == 0)
            context->ECDHCurve = BID_CONTEXT_ECDH_CURVE_P521;
        else
            return BID_S_INVALID_PARAMETER;
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

    switch (ulParam) {
    case BID_PARAM_SECONDARY_AUTHORITIES:
        *pValue = context->SecondaryAuthorities;
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
    case BID_PARAM_CONFIG_NAME:
        err = _BIDGetCacheName(context, context->Config, (const char **)pValue);
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
    case BID_PARAM_CONFIG_CACHE:
        *pValue = context->Config;
        break;
    case BID_PARAM_PARENT_WINDOW:
        *((void **)pValue) = context->ParentWindow;
        break;
    case BID_PARAM_TICKET_LIFETIME:
        *((uint32_t *)pValue) = context->TicketLifetime;
        break;
    case BID_PARAM_RENEW_LIFETIME:
        *((uint32_t *)pValue) = context->RenewLifetime;
        break;
    case BID_PARAM_ECDH_CURVE:
        if ((context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) == 0)
            return BID_S_INVALID_PARAMETER;

        if (context->ECDHCurve == BID_CONTEXT_ECDH_CURVE_P256)
            *pValue = BID_ECDH_CURVE_P256;
        else if (context->ECDHCurve == BID_CONTEXT_ECDH_CURVE_P384)
            *pValue = BID_ECDH_CURVE_P384;
        else if (context->ECDHCurve == BID_CONTEXT_ECDH_CURVE_P521)
            *pValue = BID_ECDH_CURVE_P521;
        else
            return BID_S_INVALID_PARAMETER;
        break;
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}
