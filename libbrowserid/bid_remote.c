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

    identity = BIDCalloc(1, sizeof(*identity));
    if (identity == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    identity->Attributes = json_incref(response);

    *pIdentity = identity;

    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

BIDError
_BIDVerifyRemote(
    BIDContext context,
    const char *szAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    const char *szVerifierUrl;
    char *szPostFields = NULL;
    char *szPackedAudience = NULL;
    json_t *response = NULL;
    size_t cchAssertion, cchPackedAudience;

    *pVerifiedIdentity = NULL;

    BID_CONTEXT_VALIDATE(context);

    err = BIDGetContextParam(context, BID_PARAM_VERIFIER_URL, (void **)&szVerifierUrl);
    BID_BAIL_ON_ERROR(err);

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateAudience(context, backedAssertion, szAudienceOrSpn, pbChannelBindings, cbChannelBindings);
    BID_BAIL_ON_ERROR(err);

    err = _BIDPackAudience(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

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

    err = _BIDRemoteVerifierResponseToIdentity(context, response, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

    *pExpiryTime = json_integer_value(json_object_get(response, "expires"));

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);
    BIDFree(szPackedAudience);
    BIDFree(szPostFields);
    json_decref(response);

    return err;
}
