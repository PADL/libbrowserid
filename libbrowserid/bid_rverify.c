/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

/*
 * Remote verifier
 */
static BIDError
_BIDRemoteVerifierResponseToIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    json_t *response,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = NULL;
    const char *status;

    status = json_string_value(json_object_get(response, "status"));
    if (status == NULL || strcmp(status, "okay") != 0) {
        err = BID_S_REMOTE_VERIFY_FAILURE;
        goto cleanup;
    }

    err = _BIDPopulateIdentity(context, backedAssertion, &identity);
    BID_BAIL_ON_ERROR(err);

    json_object_set(identity->Attributes, "sub", json_object_get(response, "email"));
    json_object_set(identity->Attributes, "aud", json_object_get(response, "audience"));
    json_object_set(identity->Attributes, "iss", json_object_get(response, "issuer"));

    json_object_set(identity->PrivateAttributes, "a-exp", json_object_get(response, "expires"));

    err = BID_S_OK;
    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

BIDError
_BIDVerifyRemote(
    BIDContext context,
    BIDReplayCache replayCache BID_UNUSED,
    const char *szAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    const char *szVerifierUrl;
    char *szPostFields = NULL;
    const char *szPackedAudience = NULL;
    json_t *claims = NULL;
    json_t *response = NULL;
    size_t cchAssertion, cchPackedAudience;

    *pVerifiedIdentity = NULL;
    *pulRetFlags = BID_VERIFY_FLAG_REMOTE;

    BID_CONTEXT_VALIDATE(context);

    err = BIDGetContextParam(context, BID_PARAM_VERIFIER_URL, (void **)&szVerifierUrl);
    BID_BAIL_ON_ERROR(err);

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateAudience(context, backedAssertion, szAudienceOrSpn, pbChannelBindings, cbChannelBindings);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion != NULL);
    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);

    szPackedAudience = json_string_value(json_object_get(backedAssertion->Assertion->Payload, "aud"));
    if (szPackedAudience == NULL) {
        err = BID_S_MISSING_AUDIENCE;
        goto cleanup;
    }

    cchAssertion = strlen(szAssertion);
    cchPackedAudience = strlen(szPackedAudience);

    szPostFields = BIDMalloc(sizeof("assertion=&audience=") + cchAssertion + cchPackedAudience);
    if (szPostFields == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    snprintf(szPostFields, sizeof("assertion=&audience=") + cchAssertion + cchPackedAudience,
             "assertion=%s&audience=%s", szAssertion, szPackedAudience);

    err = _BIDPostDocument(context, szVerifierUrl, szPostFields, &response);
    BID_BAIL_ON_ERROR(err);

    err = _BIDRemoteVerifierResponseToIdentity(context, backedAssertion, response, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

    BIDGetIdentityExpiryTime(context, *pVerifiedIdentity, pExpiryTime);

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);
    BIDFree(szPostFields);
    json_decref(claims);
    json_decref(response);

    return err;
}
