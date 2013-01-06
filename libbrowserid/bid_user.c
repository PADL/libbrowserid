/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

static BIDError
_BIDMakeClaims(
    BIDContext context,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    json_t **pClaims)
{
    BIDError err;
    json_t *claims = NULL;
    json_t *cbt = NULL;
    json_t *dh = NULL;

    *pClaims = NULL;

    claims = json_object();
    if (claims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (pbChannelBindings != NULL) {
        err = _BIDJsonBinaryValue(context, pbChannelBindings, cbChannelBindings, &cbt);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, claims, "cbt", cbt, 0);
        BID_BAIL_ON_ERROR(err);
    }

    if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        err = _BIDGenerateDHParams(context, &dh);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, claims, "dh", dh, 0);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    *pClaims = claims;

cleanup:
    if (err != BID_S_OK)
        json_decref(claims);
    json_decref(cbt);
    json_decref(dh);

    return err;
}

BIDError
BIDAcquireAssertion(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    json_t *claims = NULL;
    json_t *key = NULL;
    char *szAssertion = NULL;
    char *szPackedAudience = NULL;
    uint32_t ulRetFlags = 0;

    *pAssertion = NULL;
    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulRetFlags != NULL)
        *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDMakeAudience(context, szAudienceOrSpn, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    if ((context->ContextOptions & BID_CONTEXT_REAUTH) &&
        (ulReqFlags & BID_ACQUIRE_FLAG_NO_CACHED) == 0) {
        err = _BIDGetReauthAssertion(context, ticketCache, szPackedAudience,
                                     pbChannelBindings, cbChannelBindings, szIdentityName,
                                     pAssertion, pAssertedIdentity, ptExpiryTime);
        if (err == BID_S_OK) {
            ulRetFlags |= BID_VERIFY_FLAG_REAUTH;
            goto cleanup;
        }
    }

#if 0
    if (!_BIDCanInteractP(context, ulReqFlags)) {
        (ulReqFlags & BID_ACQUIRE_FLAG_NO_INTERACT)) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }
#endif

    err = _BIDMakeClaims(context, pbChannelBindings, cbChannelBindings, &claims);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        json_t *dh = json_object_get(claims, "dh");

        err = _BIDGenerateDHKey(context, dh, &key);
        BID_BAIL_ON_ERROR(err);

        /* Copy public value to parameters so we can send them. */
        err = _BIDJsonObjectSet(context, dh, "y", json_object_get(key, "y"), BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDBrowserGetAssertion(context, szPackedAudience, szAudienceOrSpn, claims,
                                  szIdentityName, ulReqFlags, &szAssertion);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertionFromString(context, szAssertion, ulReqFlags,
                                        pAssertedIdentity, ptExpiryTime, &ulRetFlags);
    BID_BAIL_ON_ERROR(err);

    if (pAssertedIdentity != NULL && (context->ContextOptions & BID_CONTEXT_DH_KEYEX)) {
        BIDIdentity assertedIdentity = *pAssertedIdentity;

        assertedIdentity->PrivateAttributes = json_object();
        if (assertedIdentity->PrivateAttributes == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = _BIDJsonObjectSet(context, assertedIdentity->PrivateAttributes, "dh", key, 0);
        BID_BAIL_ON_ERROR(err);
    }

    *pAssertion = szAssertion;

cleanup:
    if (pulRetFlags != NULL)
        *pulRetFlags = ulRetFlags;
    if (err != BID_S_OK)
        BIDFree(szAssertion);
    json_decref(claims);
    json_decref(key);
    _BIDReleaseBackedAssertion(context, backedAssertion);
    BIDFree(szPackedAudience);

    return err;
}

BIDError
BIDAcquireAssertionFromString(
    BIDContext context,
    const char *szAssertion,
    uint32_t ulReqFlags BID_UNUSED,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;

    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulRetFlags != NULL)
        *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    if (pAssertedIdentity != NULL) {
        err = _BIDPopulateIdentity(context, backedAssertion, pAssertedIdentity);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;

    if (ptExpiryTime != NULL)
        _BIDGetJsonTimestampValue(context, _BIDLeafCert(context, backedAssertion), "exp", ptExpiryTime);

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);

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
