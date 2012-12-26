/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
BIDAcquireContext(
    uint32_t ulContextOptions,
    BIDContext *pContext)
{
    BIDContext context;

    *pContext = BID_C_NO_CONTEXT;

    context = BIDCalloc(1, sizeof(*context));
    if (context == NULL)
        return BID_S_NO_MEMORY;

    context->ContextOptions = ulContextOptions;
    context->MaxDelegations = 6;

    if (ulContextOptions & BID_CONTEXT_RP) {
        context->AuthorityCache = json_object();
        if (context->AuthorityCache == NULL) {
            BIDReleaseContext(context);
            return BID_S_NO_MEMORY;
        }
    }

    *pContext = context;
    return BID_S_OK;
}

BIDError
BIDReleaseContext(BIDContext context)
{
    if (context == BID_C_NO_CONTEXT)
        return BID_S_NO_CONTEXT;

    BIDFree(context->VerifierUrl);
    json_decref(context->AuthorityCache);

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
    case BID_PARAM_VERIFIER_URL:
        err = _BIDDuplicateString(context, value, &context->VerifierUrl);
        break;
    case BID_PARAM_MAX_DELEGATIONS:
        context->MaxDelegations = *(uint32_t *)value;
        break;
    case BID_PARAM_SKEW:
        context->Skew = *(uint32_t *)value;
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
    uint32_t ulParam,
    void **pValue)
{
    BIDError err = BID_S_OK;

    BID_CONTEXT_VALIDATE(context);

    *pValue = NULL;

    switch (ulParam) {
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
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}
