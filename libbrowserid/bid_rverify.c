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

    err = _BIDPopulateIdentity(context, backedAssertion, 0, &identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "sub", json_object_get(response, "email"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "aud", json_object_get(response, "audience"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "iss", json_object_get(response, "issuer"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "a-exp", json_object_get(response, "expires"), 0);
    BID_BAIL_ON_ERROR(err);

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
    BIDBackedAssertion backedAssertion,
    const char *szAudienceOrSpn,
    const char *szSubjectName,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime BID_UNUSED,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    uint32_t *pulRetFlags)
{
    BIDError err;
    const char *szVerifierUrl;
    char *szPostFields = NULL;
    json_t *claims = NULL;
    json_t *response = NULL;
    size_t cchAssertion, cchAudienceOrSpn;

    *pVerifiedIdentity = NULL;
    *pulRetFlags = BID_VERIFY_FLAG_REMOTE;

    BID_CONTEXT_VALIDATE(context);

    err = BIDGetContextParam(context, BID_PARAM_VERIFIER_URL, (void **)&szVerifierUrl);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateAudience(context, backedAssertion, szAudienceOrSpn, pbChannelBindings, cbChannelBindings);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion != NULL);
    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);

    if (szAudienceOrSpn == NULL) {
        szAudienceOrSpn = json_string_value(json_object_get(backedAssertion->Assertion->Payload, "aud"));
        if (szAudienceOrSpn == NULL) {
            err = BID_S_MISSING_AUDIENCE;
            goto cleanup;
        }
    }

    cchAssertion = backedAssertion->EncDataLength;
    cchAudienceOrSpn = strlen(szAudienceOrSpn);

    szPostFields = BIDMalloc(sizeof("assertion=&audience=") + cchAssertion + cchAudienceOrSpn);
    if (szPostFields == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    snprintf(szPostFields, sizeof("assertion=&audience=") + cchAssertion + cchAudienceOrSpn,
             "assertion=%s&audience=%s", backedAssertion->EncData, szAudienceOrSpn);

    err = _BIDPostDocument(context, szVerifierUrl, szPostFields, &response);
    BID_BAIL_ON_ERROR(err);

    err = _BIDRemoteVerifierResponseToIdentity(context, backedAssertion, response, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateSubject(context, *pVerifiedIdentity, szSubjectName, ulReqFlags);
    BID_BAIL_ON_ERROR(err);

    *pulRetFlags |= BID_VERIFY_FLAG_VALIDATED_CERTS;

cleanup:
    BIDFree(szPostFields);
    json_decref(claims);
    json_decref(response);

    return err;
}
