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

struct BIDModalSessionDesc {
    uint32_t ulReqFlags;
    json_t *Claims;
    json_t *Key;
    void (*CompletionHandler)(BIDContext, BIDError, const char *, BIDIdentity, time_t, uint32_t, int *, void *);
    void *CompletionContext;
    void (*FinalizeCompletionContext)(BIDContext, void *);
    void *UIContext;
    void (*FinalizeUIContext)(BIDContext, void *);
};

BIDError
_BIDAllocModalSession(
    BIDContext context BID_UNUSED,
    void (*completionHandler)(BIDContext, BIDError, const char *, BIDIdentity, time_t, uint32_t, int *, void *),
    void *completionContext,
    void (*finalizeCompletionContext)(BIDContext, void *),
    BIDModalSession *pModalSession)
{
    BIDModalSession modalSession;

    modalSession = (BIDModalSession)BIDCalloc(1, sizeof(*modalSession));
    if (modalSession == NULL)
        return BID_S_NO_MEMORY;

    modalSession->CompletionHandler = completionHandler;
    modalSession->CompletionContext = completionContext;
    modalSession->FinalizeCompletionContext = finalizeCompletionContext;

    *pModalSession = modalSession;
    return BID_S_OK;
}

BIDError
_BIDReleaseModalSession(
    BIDContext context,
    BIDModalSession modalSession)
{
    if (modalSession == NULL)
        return BID_S_INVALID_PARAMETER;

    if (modalSession->FinalizeCompletionContext != NULL)
        modalSession->FinalizeCompletionContext(context, modalSession->CompletionContext);
    if (modalSession->FinalizeUIContext != NULL)
        modalSession->FinalizeUIContext(context, modalSession->UIContext);
    json_decref(modalSession->Claims);
    json_decref(modalSession->Key);

    BIDFree(modalSession);

    return BID_S_OK;
}

void
_BIDCompleteModalSession(
    BIDContext context,
    BIDError err,
    const char *szAssertion,
    BIDModalSession *pModalSession)
{
    BIDIdentity identity = BID_C_NO_IDENTITY;
    time_t expiryTime = 0;
    uint32_t ulRetFlags = 0;
    int freeIdentity = 1;
    BIDModalSession modalSession = *pModalSession;
    
    if (err == BID_S_OK) {
        err = BIDAcquireAssertionFromString(context, szAssertion, modalSession->ulReqFlags,
                                            &identity, &expiryTime, &ulRetFlags);
        BID_BAIL_ON_ERROR(err);

        BID_ASSERT(identity->PrivateAttributes != NULL);
        
        if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
            err = _BIDSetKeyAgreementObject(context, identity->PrivateAttributes, modalSession->Key);
            BID_BAIL_ON_ERROR(err);
        }

        if (modalSession->ulReqFlags & BID_ACQUIRE_FLAG_MUTUAL_AUTH) {
            json_t *nonce = json_object_get(modalSession->Claims, "nonce");

            BID_ASSERT(nonce != NULL);

            err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "nonce", nonce, 0);
            BID_BAIL_ON_ERROR(err);
        }
    }

cleanup:
    modalSession->CompletionHandler(context, err, szAssertion, identity, expiryTime, ulRetFlags,
                                    &freeIdentity, modalSession->CompletionContext);

    if (freeIdentity)
        BIDReleaseIdentity(context, identity);

    _BIDReleaseModalSession(context, modalSession);
    *pModalSession = NULL;
}

void
_BIDSetModalSessionUIContext(
    BIDContext context BID_UNUSED,
    BIDModalSession modalSession,
    void *uiContext,
    void (*finalize)(BIDContext, void *))
{
    if (modalSession->UIContext != NULL)
        modalSession->FinalizeUIContext(context, modalSession->UIContext);

    modalSession->UIContext = uiContext;
    modalSession->FinalizeUIContext = finalize;
}

void *
_BIDGetModalSessionUIContext(
    BIDContext context BID_UNUSED,
    BIDModalSession modalSession)
{
    return modalSession->UIContext;
}

static BIDError
_BIDMakeClaims(
    BIDContext context,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    uint32_t ulReqFlags,
    json_t *userClaims,
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

    claims = (userClaims != NULL) ? json_copy(userClaims) : json_object();
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

    if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
        err = _BIDGetKeyAgreementParams(context, &dh);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSetKeyAgreementObject(context, claims, dh);
        BID_BAIL_ON_ERROR(err);

        err = _BIDGenerateECDHKey(context, dh, &key);
        BID_BAIL_ON_ERROR(err);

        /* Copy public value to parameters so we can send them. */
        err = _BIDJsonObjectSet(context, dh, "x", json_object_get(key, "x"), BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);

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
    return BIDAcquireAssertionEx(context,
                                 ticketCache,
                                 szAudienceOrSpn,
                                 pbChannelBindings,
                                 cbChannelBindings,
                                 szIdentityName,
                                 ulReqFlags,
                                 NULL,
                                 pAssertion,
                                 pAssertedIdentity,
                                 ptExpiryTime,
                                 pulRetFlags);
}

static BIDError
_BIDBeginModalSessionReauth(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    BIDModalSession *pModalSession)
{
    BIDError err;
    char *szAssertion = NULL;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    time_t expiryTime;
    uint32_t ulTicketFlags = 0;
    uint32_t ulRetFlags = 0;
    int freeIdentity = 1;
    BIDModalSession modalSession = *pModalSession;

    err = _BIDGetReauthAssertion(context, ticketCache, szAudienceOrSpn,
                                 pbChannelBindings, cbChannelBindings, szIdentityName,
                                 ulReqFlags, &szAssertion, &identity, &expiryTime,
                                 &ulTicketFlags);
    if (err != BID_S_OK)
        return err;

    ulRetFlags |= BID_ACQUIRE_FLAG_REAUTH;
    if (ulTicketFlags & BID_TICKET_FLAG_MUTUAL_AUTH)
        ulRetFlags |= BID_ACQUIRE_FLAG_REAUTH_MUTUAL;

    modalSession->CompletionHandler(context, BID_S_OK, szAssertion, identity, expiryTime,
                                    ulRetFlags, &freeIdentity, modalSession->CompletionContext);

    BIDFree(szAssertion);
    if (freeIdentity)
        BIDReleaseIdentity(context, identity);

    _BIDReleaseModalSession(context, modalSession);
    *pModalSession = NULL;

    return BID_S_OK;
}

BIDError
_BIDBeginModalSession(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    json_t *userClaims,
    BIDModalSession *pModalSession)
{
    BIDError err;
    json_t *nonce = NULL;
    BIDModalSession modalSession = *pModalSession;

    BID_CONTEXT_VALIDATE(context);
    BID_ASSERT(modalSession->CompletionHandler != NULL);

    modalSession->ulReqFlags = ulReqFlags;

    if (szAudienceOrSpn == NULL) {
        err = BID_S_INVALID_AUDIENCE_URN;
        goto cleanup;
    }

    if ((context->ContextOptions & BID_CONTEXT_REAUTH) &&
        (ulReqFlags & BID_ACQUIRE_FLAG_NO_CACHED) == 0) {
        err = _BIDBeginModalSessionReauth(context, ticketCache, szAudienceOrSpn,
                                          pbChannelBindings, cbChannelBindings, szIdentityName,
                                          ulReqFlags, pModalSession);
        if (err == BID_S_OK)
            goto cleanup;
    }

    if (!_BIDCanInteractP(context, ulReqFlags)) {
        err = BID_S_INTERACT_REQUIRED;
        goto cleanup;
    }

    err = _BIDMakeClaims(context, pbChannelBindings, cbChannelBindings,
                         ulReqFlags, userClaims, &modalSession->Claims, &modalSession->Key);
    BID_BAIL_ON_ERROR(err);

    if (ulReqFlags & BID_ACQUIRE_FLAG_MUTUAL_AUTH) {
        err = _BIDGenerateNonce(context, &nonce);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, modalSession->Claims, "nonce", nonce, BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDBrowserGetAssertion(context, szAudienceOrSpn, modalSession->Claims,
                                  szIdentityName, ulReqFlags, modalSession);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(nonce);

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

struct BIDAcquireAssertionCompletionContextDesc {
    BIDError bidError;
    char *szAssertion;
    BIDIdentity identity;
    time_t expiryTime;
    uint32_t ulRetFlags;
};

static void
_BIDAcquireAssertion_CompletionHandler(
    BIDContext context,
    BIDError err,
    const char *szAssertion,
    BIDIdentity identity,
    time_t expiryTime,
    uint32_t ulRetFlags,
    int *freeIdentity,
    void *completionContext)
{
    struct BIDAcquireAssertionCompletionContextDesc *cc = completionContext;

    cc->bidError = err;

    if (cc->bidError == BID_S_OK) {
        _BIDDuplicateString(context, szAssertion, &cc->szAssertion);
        cc->identity = identity;
        cc->expiryTime = expiryTime;
        cc->ulRetFlags = ulRetFlags;
        *freeIdentity = 0;
    }
}

BIDError
BIDAcquireAssertionEx(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    json_t *userClaims,
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDModalSession modalSession = NULL;
    struct BIDAcquireAssertionCompletionContextDesc cc = { 0 };

    *pAssertion = NULL;
    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulRetFlags != NULL)
        *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDAllocModalSession(context, _BIDAcquireAssertion_CompletionHandler, &cc, NULL, &modalSession);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBeginModalSession(context, ticketCache, szAudienceOrSpn,
                                pbChannelBindings, cbChannelBindings,
                                szIdentityName, ulReqFlags, userClaims,
                                &modalSession);
    BID_BAIL_ON_ERROR(err);

    if (modalSession != NULL) {
        err = _BIDRunModalSession(context, &modalSession);
        BID_BAIL_ON_ERROR(err);
    }

    err = cc.bidError;

    if (pAssertion != NULL)
        *pAssertion = cc.szAssertion;
    else
        BIDFree(cc.szAssertion);

    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = cc.identity;
    else
        BIDReleaseIdentity(context, cc.identity);

    if (ptExpiryTime != NULL)
        *ptExpiryTime = cc.expiryTime;

    if (pulRetFlags != NULL)
        *pulRetFlags = cc.ulRetFlags;

cleanup:
    _BIDReleaseModalSession(context, modalSession);

    return err;
}
