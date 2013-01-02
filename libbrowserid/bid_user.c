/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
BIDAcquireAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    json_t *claims = NULL;
    char *szAssertion = NULL;
    char *szPackedAudience = NULL;
    const char *szSiteName = NULL;

    *pAssertion = NULL;
    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    if (context->ContextOptions & BID_USER_INTERACTION_DISABLED) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    err = _BIDMakeClaims(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, &claims);
    BID_BAIL_ON_ERROR(err);

    err = _BIDPackAudience(context, claims, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    szSiteName = strchr(szAudienceOrSpn, '/');
    if (szSiteName != NULL)
        szSiteName++;

    err = _BIDBrowserGetAssertion(context, szPackedAudience, szSiteName, &szAssertion);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertionFromString(context, szAssertion, pAssertedIdentity, ptExpiryTime);
    BID_BAIL_ON_ERROR(err);

    *pAssertion = szAssertion;

cleanup:
    if (err != BID_S_OK)
        BIDFree(szAssertion);
    json_decref(claims);
    _BIDReleaseBackedAssertion(context, backedAssertion);
    BIDFree(szPackedAudience);

    return err;
}

BIDError
BIDFreeAssertion(
    BIDContext context,
    char *assertion)
{
    BID_CONTEXT_VALIDATE(context);

    if (assertion == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(assertion);
    return BID_S_OK;
}
