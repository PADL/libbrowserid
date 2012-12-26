/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
BIDAcquireAssertion(
    BIDContext context,
    const char *szAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;

    *pAssertedIdentity = NULL;
    *ptExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDPopulateIdentity(context, backedAssertion, pAssertedIdentity);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

    *ptExpiryTime = json_integer_value(json_object_get(backedAssertion->Assertion->Payload, "exp"));

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);

    return err;
}

BIDError
BIDAcquireAssertionInteractive(
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
    char *szAssertion = NULL;
    char *szPackedAudience = NULL;

    *pAssertion = NULL;
    *pAssertedIdentity = NULL;
    *ptExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDPackAudience(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBrowserGetAssertion(context, szPackedAudience, &szAssertion);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertion(context, szAssertion, pAssertedIdentity, ptExpiryTime);
    BID_BAIL_ON_ERROR(err);

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);
    BIDFree(szAssertion);
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

