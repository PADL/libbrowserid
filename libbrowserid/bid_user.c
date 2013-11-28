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

static BIDError
_BIDMakeClaims(
    BIDContext context,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    uint32_t ulReqFlags,
    json_t **pClaims,
    json_t **pKey)
{
    BIDError err;
    json_t *claims = NULL;
    json_t *cb = NULL;
    json_t *dh = NULL;
    json_t *key = NULL;
    json_t *opts = NULL;

    *pClaims = NULL;
    *pKey = NULL;

    claims = json_object();
    if (claims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (pbChannelBindings != NULL) {
        err = _BIDJsonBinaryValue(context, pbChannelBindings, cbChannelBindings, &cb);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, claims, "cb", cb, 0);
        BID_BAIL_ON_ERROR(err);
    }

    if (context->ContextOptions & BID_CONTEXT_KEYEX_MASK) {
        err = _BIDGetKeyAgreementParams(context, &dh);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetKeyAgreementObject(context, claims, dh);
        BID_BAIL_ON_ERROR(err);

        if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX)
            err = _BIDGenerateECDHKey(context, dh, &key);
        else if (context->ContextOptions & BID_CONTEXT_DH_KEYEX)
            err = _BIDGenerateDHKey(context, dh, &key);
        BID_BAIL_ON_ERROR(err);

        /* Copy public value to parameters so we can send them. */
        if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
            err = _BIDJsonObjectSet(context, dh, "x", json_object_get(key, "x"), BID_JSON_FLAG_REQUIRED);
            BID_BAIL_ON_ERROR(err);
        }

        err = _BIDJsonObjectSet(context, dh, "y", json_object_get(key, "y"), BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDMakeProtocolOpts(context, ulReqFlags, &opts);
    BID_BAIL_ON_ERROR(err);

    if (opts != NULL) {
        err = _BIDJsonObjectSet(context, claims, "opts", opts, 0);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    *pClaims = claims;
    *pKey = key;

cleanup:
    if (err != BID_S_OK) {
        json_decref(claims);
        json_decref(key);
    }
    json_decref(cb);
    json_decref(dh);
    json_decref(opts);

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
    json_t *nonce = NULL;
    char *szAssertion = NULL;
    uint32_t ulRetFlags = 0;
    uint32_t ulTicketFlags = 0;

    *pAssertion = NULL;
    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulRetFlags != NULL)
        *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    if ((context->ContextOptions & BID_CONTEXT_REAUTH) &&
        (ulReqFlags & BID_ACQUIRE_FLAG_NO_CACHED) == 0) {
        err = _BIDGetReauthAssertion(context, ticketCache, szAudienceOrSpn,
                                     pbChannelBindings, cbChannelBindings, szIdentityName,
                                     ulReqFlags, pAssertion, pAssertedIdentity, ptExpiryTime,
                                     &ulTicketFlags);
        if (err == BID_S_OK) {
            ulRetFlags |= BID_ACQUIRE_FLAG_REAUTH;
            if (ulTicketFlags & BID_TICKET_FLAG_MUTUAL_AUTH)
                ulRetFlags |= BID_ACQUIRE_FLAG_REAUTH_MUTUAL;
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

    err = _BIDMakeClaims(context, pbChannelBindings, cbChannelBindings, ulReqFlags, &claims, &key);
    BID_BAIL_ON_ERROR(err);

    if (ulReqFlags & BID_ACQUIRE_FLAG_MUTUAL_AUTH) {
        err = _BIDGenerateNonce(context, &nonce);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, claims, "nonce", nonce, BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDBrowserGetAssertion(context, szAudienceOrSpn, claims,
                                  szIdentityName, ulReqFlags, &szAssertion);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertionFromString(context, szAssertion, ulReqFlags,
                                        pAssertedIdentity, ptExpiryTime, &ulRetFlags);
    BID_BAIL_ON_ERROR(err);

    if (pAssertedIdentity != NULL) {
        BIDIdentity assertedIdentity = *pAssertedIdentity;

        if (context->ContextOptions & BID_CONTEXT_KEYEX_MASK) {
            err = _BIDSetKeyAgreementObject(context, assertedIdentity->PrivateAttributes, key);
            BID_BAIL_ON_ERROR(err);
        }

        if (ulReqFlags & BID_ACQUIRE_FLAG_MUTUAL_AUTH) {
            err = _BIDJsonObjectSet(context, assertedIdentity->PrivateAttributes, "nonce", nonce, 0);
            BID_BAIL_ON_ERROR(err);
        }
    }

    *pAssertion = szAssertion;

cleanup:
    if (pulRetFlags != NULL)
        *pulRetFlags = ulRetFlags;
    if (err != BID_S_OK)
        BIDFree(szAssertion);
    json_decref(claims);
    json_decref(key);
    json_decref(nonce);
    _BIDReleaseBackedAssertion(context, backedAssertion);

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
        err = _BIDPopulateIdentity(context, backedAssertion, 0, pAssertedIdentity);
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
