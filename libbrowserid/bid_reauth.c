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
 * Fast reauthentication support
 */

static BIDError
_BIDMakeTicketCacheKey(
    BIDContext context,
    const char *szAudienceOrSpn,
    char **pszCacheKey)
{
    BIDError err;
    char szCachePrefix[64];
    char *szCacheKey = NULL;
    size_t cchCachePrefix, cchAudienceOrSpn;
    size_t cchCacheKey;

    *pszCacheKey = NULL;

    if (szAudienceOrSpn == NULL)
        return BID_S_INVALID_PARAMETER;

    /*
     * Encode the number of bits in the DH key, or the ECDH curve, so we can
     * quickly find a ticket that suits the context encryption type.
     */
    if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
        const char *szCurve;

        err = BIDGetContextParam(context, BID_PARAM_ECDH_CURVE, (void **)&szCurve);
        if (err != BID_S_OK)
            return err;

        snprintf(szCachePrefix, sizeof(szCachePrefix), "%s$", szCurve);
    } else if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        snprintf(szCachePrefix, sizeof(szCachePrefix), "%u$", context->DHKeySize);
    } else {
        return BID_S_CACHE_KEY_NOT_FOUND;
    }

    cchCachePrefix = strlen(szCachePrefix);
    cchAudienceOrSpn = strlen(szAudienceOrSpn);
    cchCacheKey = cchCachePrefix + cchAudienceOrSpn;

    szCacheKey = BIDMalloc(cchCacheKey + 1);
    if (szCacheKey == NULL)
        return BID_S_NO_MEMORY;

    memcpy(szCacheKey, szCachePrefix, cchCachePrefix);
    memcpy(&szCacheKey[cchCachePrefix], szAudienceOrSpn, cchAudienceOrSpn);
    szCacheKey[cchCachePrefix + cchAudienceOrSpn] = '\0';

    *pszCacheKey = szCacheKey;

    return BID_S_OK;
}

static BIDError
_BIDDeriveAuthenticatorSessionKey(
    BIDContext context,
    BIDJWK ark,
    BIDJWT ap,
    BIDSecretHandle *pSecretHandle)
{
    BIDError err;
    BIDSecretHandle secretHandle = NULL;
    unsigned char *pbNonce = NULL;
    size_t cbNonce = 0;
    unsigned char *pbASK = NULL;
    size_t cbASK = 0;

    *pSecretHandle = NULL;

    err = _BIDImportSecretKey(context, ark, &secretHandle);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonBinaryValue(context, ap->Payload, "nonce", &pbNonce, &cbNonce);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, secretHandle, pbNonce, cbNonce, &pbASK, &cbASK);
    BID_BAIL_ON_ERROR(err);

    err = _BIDImportSecretKeyData(context, pbASK, cbASK, pSecretHandle);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    _BIDDestroySecret(context, secretHandle);
    BIDFree(pbNonce);
    if (pbASK != NULL) {
        memset(pbASK, 0, cbASK);
        BIDFree(pbASK);
    }

    return err;
}

BIDError
_BIDAcquireDefaultTicketCache(BIDContext context)
{
    return _BIDAcquireCacheForUser(context, "browserid.tickets", &context->TicketCache);
}

BIDError
_BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szUnused BID_UNUSED,
    json_t *ticket,
    uint32_t ulTicketFlags)
{
    BIDError err;
    json_t *cred = NULL;
    BIDJWK ark = NULL;
    const char *szAudienceOrSpn = NULL;
    const char *szSubject = NULL;
    char *szCacheKey = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY || ticket == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (context->TicketCache == BID_C_NO_TICKET_CACHE) {
        err = BID_S_NO_TICKET_CACHE;
        goto cleanup;
    }

    szAudienceOrSpn = json_string_value(json_object_get(identity->PrivateAttributes, "aud"));
    if (szAudienceOrSpn == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDDeriveSessionSubkey(context, identity, "ARK", &ark);
    BID_BAIL_ON_ERROR(err);

    cred = json_copy(identity->Attributes);
    if (cred == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, cred, "tkt", ticket, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, cred, "ark", ark, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, cred, "flags",
                            json_integer(ulTicketFlags),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSaveKeyAgreementStrength(context, identity, 0, cred);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentitySubject(context, identity, &szSubject);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeTicketCacheKey(context, szAudienceOrSpn, &szCacheKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCacheObject(context, context->TicketCache, szCacheKey, cred);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(cred);
    json_decref(ark);
    BIDFree(szCacheKey);

    return err;
}

BIDError
BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    const char *szTicket)
{
    json_t *ticket;
    BIDError err;

    ticket = json_loads(szTicket, 0, &context->JsonError);
    if (ticket == NULL)
        return BID_S_INVALID_JSON;

    err = _BIDStoreTicketInCache(context, identity, szAudienceOrSpn, ticket, 0);

    json_decref(ticket);

    return err;
}

static BIDError
_BIDMakeAuthenticator(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    uint32_t ulReqFlags,
    json_t *tid,
    BIDJWT *pAuthenticator)
{
    BIDError err;
    BIDJWT ap = NULL;
    json_t *nonce = NULL;
    json_t *iat = NULL;
    json_t *exp = NULL;
    json_t *aud = NULL;
    json_t *cb = NULL;
    json_t *opts = NULL;
    json_t *tkt = NULL;

    *pAuthenticator = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (tid == NULL) {
        err = BID_S_BAD_TICKET_CACHE;
        goto cleanup;
    }

    err = _BIDGetCurrentJsonTimestamp(context, &iat);
    BID_BAIL_ON_ERROR(err);

    exp = json_integer(json_integer_value(iat) + context->Skew * 1000);
    if (exp == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDGenerateNonce(context, &nonce);
    BID_BAIL_ON_ERROR(err);

    aud = json_string(szAudienceOrSpn);
    if (aud == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (pbChannelBindings != NULL) {
        err = _BIDJsonBinaryValue(context, pbChannelBindings, cbChannelBindings, &cb);
        BID_BAIL_ON_ERROR(err);
    }

    ap = BIDCalloc(1, sizeof(*ap));
    if (ap == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    ap->Payload = json_object();
    if (ap->Payload == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, ap->Payload, "iat", iat, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ap->Payload, "exp", exp, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ap->Payload, "nonce", nonce, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    tkt = json_object();
    if (tkt == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, tkt, "tid", tid, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ap->Payload, "tkt", tkt, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ap->Payload, "aud", aud, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ap->Payload, "cb", cb, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeProtocolOpts(context, ulReqFlags, &opts);
    BID_BAIL_ON_ERROR(err);

    if (opts != NULL) {
        err = _BIDJsonObjectSet(context, ap->Payload, "opts", opts, 0);
        BID_BAIL_ON_ERROR(err);
    }

    *pAuthenticator = ap;

cleanup:
    if (err != BID_S_OK)
        _BIDReleaseJWT(context, ap);
    json_decref(iat);
    json_decref(exp);
    json_decref(nonce);
    json_decref(tkt);
    json_decref(aud);
    json_decref(cb);
    json_decref(opts);

    return err;
}

static BIDError
_BIDMakeReauthIdentity(
    BIDContext context,
    json_t *cred,
    BIDJWT ap,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    json_t *credCopy = NULL;

    *pIdentity = NULL;

    credCopy = json_copy(cred);
    if (credCopy == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDAllocIdentity(context, credCopy, &identity);
    BID_BAIL_ON_ERROR(err);

    /* remove the secret stuff from the attribute cache */
    err = _BIDJsonObjectDel(context, identity->Attributes, "ark", 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectDel(context, identity->Attributes, "a-exp", 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectDel(context, identity->Attributes, "flags", 0);
    BID_BAIL_ON_ERROR(err);

    /* copy over the assertion expiry time */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "a-exp",
                            json_object_get(cred, "a-exp"), 0);
    BID_BAIL_ON_ERROR(err);

    /* Save protocol options, internal use only */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "opts",
                            json_object_get(ap->Payload, "opts"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveAuthenticatorSessionKey(context, json_object_get(cred, "ark"), ap,
                                            &identity->SecretHandle);
    BID_BAIL_ON_ERROR(err);

    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);
    json_decref(credCopy);

    return err;
}

struct BIDMatchTicketArgsDesc {
    char *szCacheKey;
    const char *szIdentityName;
    json_t *cred;
};

static BIDError
_BIDMatchTicketInCacheCB(
    BIDContext context BID_UNUSED,
    BIDCache cache BID_UNUSED,
    const char *szKey,
    json_t *cacheVal,
    void *data)
{
    struct BIDMatchTicketArgsDesc *args = (struct BIDMatchTicketArgsDesc *)data;
    const char *szCacheIdentity;

    BID_ASSERT(szKey != NULL);
    BID_ASSERT(args->szIdentityName != NULL);
    BID_ASSERT(args->cred == NULL);

    szCacheIdentity = json_string_value(json_object_get(cacheVal, "sub"));

    if (strcmp(szKey, args->szCacheKey) == 0 &&
        szCacheIdentity != NULL &&
        strcmp(szCacheIdentity, args->szIdentityName) == 0) {
        args->cred = json_incref(cacheVal);
        return BID_S_NO_MORE_ITEMS;
    }

    return BID_S_OK;
}

static BIDError
_BIDFindTicketInCache(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szAudienceOrSpn,
    const char *szIdentityName,
    json_t **pCred)
{
    BIDError err;
    struct BIDMatchTicketArgsDesc args = { 0 };

    args.szCacheKey = NULL;
    args.szIdentityName = szIdentityName;
    args.cred = NULL;

    err = _BIDMakeTicketCacheKey(context, szAudienceOrSpn, &args.szCacheKey);
    BID_BAIL_ON_ERROR(err);

    if (szIdentityName != NULL) {
        err = _BIDPerformCacheObjects(context, ticketCache, _BIDMatchTicketInCacheCB, &args);
        if (err == BID_S_NO_MORE_ITEMS && args.cred != NULL)
            err = BID_S_OK;
        BID_BAIL_ON_ERROR(err);

        if (args.cred == NULL) {
            err = BID_S_CACHE_KEY_NOT_FOUND;
            goto cleanup;
        }
    } else {
        err = _BIDGetCacheObject(context, ticketCache, args.szCacheKey, &args.cred);
        BID_BAIL_ON_ERROR(err);
    }

    BID_ASSERT(err == BID_S_OK || args.cred == NULL);

    err = BID_S_OK;
    *pCred = args.cred;

cleanup:
    if (err != BID_S_OK)
        json_decref(args.cred);
    BIDFree(args.szCacheKey);

    return err;
}

static BIDError
_BIDValidateReauthCredStrength(
    BIDContext context,
    json_t *cred)
{
    BIDError err;

    if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
        const char *szCredCurve = json_string_value(json_object_get(cred, "crv"));
        const char *szContextCurve;

        err = BIDGetContextParam(context, BID_PARAM_ECDH_CURVE, (void **)&szContextCurve);
        if (err != BID_S_OK)
            return err;

        if (szCredCurve == NULL || strcmp(szCredCurve, szContextCurve) != 0)
            return BID_S_INVALID_EC_CURVE;
    } else if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        uint32_t ulDHKeySize = _BIDJsonUInt32Value(json_object_get(cred, "dh-key-size"));

        if (ulDHKeySize < context->DHKeySize)
            return BID_S_KEY_TOO_SHORT;
    }

    return BID_S_OK;
}

/*
 * Try to make a reauthentication assertion.
 */
BIDError
_BIDGetReauthAssertion(
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
    uint32_t *pulTicketFlags)
{
    BIDError err;
    json_t *cred = NULL;
    json_t *tkt = NULL;
    BIDJWT ap = NULL;
    struct BIDBackedAssertionDesc backedAssertion = { 0 };
    time_t now = 0;

    BID_CONTEXT_VALIDATE(context);
    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REAUTH);

    if (pAssertion != NULL)
        *pAssertion = NULL;
    if (pAssertedIdentity != NULL)
        *pAssertedIdentity = NULL;
    if (ptExpiryTime != NULL)
        *ptExpiryTime = 0;
    if (pulTicketFlags != NULL)
        *pulTicketFlags = 0;

    if (ticketCache == BID_C_NO_TICKET_CACHE)
        ticketCache = context->TicketCache;

    err = _BIDFindTicketInCache(context, ticketCache, szAudienceOrSpn, szIdentityName, &cred);
    if (err == BID_S_CACHE_KEY_NOT_FOUND &&
        (context->ContextOptions & BID_CONTEXT_HOST_SPN_ALIAS)) {
        char *szHostSpnAudience;

        err = _BIDHostifySpn(context, szAudienceOrSpn, &szHostSpnAudience);
        if (err == BID_S_OK) {
            err = _BIDFindTicketInCache(context, ticketCache, szHostSpnAudience, szIdentityName, &cred);
            BIDFree(szHostSpnAudience);
        }
    }
    BID_BAIL_ON_ERROR(err);

    tkt = json_object_get(cred, "tkt");
    if (tkt == NULL) {
        err = BID_S_BAD_TICKET_CACHE;
        goto cleanup;
    }

    err = _BIDMakeAuthenticator(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings,
                                ulReqFlags, json_object_get(tkt, "tid"), &ap);
    BID_BAIL_ON_ERROR(err);

    _BIDGetJsonTimestampValue(context, ap->Payload, "iat", &now);

    /*
     * In the current implementation, we only send the expiry time.
     */
    err = _BIDJsonObjectDel(context, ap->Payload, "iat", 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateExpiry(context, now, tkt);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateReauthCredStrength(context, cred);
    BID_BAIL_ON_ERROR(err);

    backedAssertion.Assertion = ap;
    backedAssertion.cCertificates = 0;

    if (pAssertion != NULL) {
        err = _BIDPackBackedAssertion(context, &backedAssertion, json_object_get(cred, "ark"), NULL, pAssertion);
        BID_BAIL_ON_ERROR(err);
    }

    if (pAssertedIdentity != NULL) {
        err = _BIDMakeReauthIdentity(context, cred, ap, pAssertedIdentity);
        BID_BAIL_ON_ERROR(err);
    }

    if (ptExpiryTime != NULL)
        _BIDGetJsonTimestampValue(context, tkt, "exp", ptExpiryTime);

    if (pulTicketFlags != NULL)
        *pulTicketFlags = _BIDJsonUInt32Value(json_object_get(cred, "flags"));

cleanup:
    json_decref(cred);
    _BIDReleaseJWT(context, ap);

    return err;
}

BIDError
_BIDVerifyReauthAssertion(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion assertion,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    BIDJWK *pVerifierCred,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDJWT ap = assertion->Assertion;
    const char *szTicket;
    json_t *cred = NULL;
    uint32_t ulTicketFlags = 0;
    json_t *tkt = NULL;

    *pVerifiedIdentity = BID_C_NO_IDENTITY;
    *pVerifierCred = NULL;

    BID_CONTEXT_VALIDATE(context);

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REPLAY_CACHE);
    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REAUTH);
    BID_ASSERT(assertion->cCertificates == 0);

    tkt = json_object_get(ap->Payload, "tkt");

    szTicket = json_string_value(json_object_get(tkt, "tid"));
    if (szTicket == NULL) {
        err = BID_S_NOT_REAUTH_ASSERTION;
        goto cleanup;
    }

    if (replayCache == BID_C_NO_REPLAY_CACHE)
        replayCache = context->ReplayCache;

    *pulRetFlags |= BID_VERIFY_FLAG_REAUTH;

    err = _BIDGetCacheObject(context, replayCache, szTicket, &cred);
    if (err == BID_S_CACHE_NOT_FOUND || err == BID_S_CACHE_KEY_NOT_FOUND)
        err = BID_S_INVALID_ASSERTION;
    BID_BAIL_ON_ERROR(err);

    ulTicketFlags = _BIDJsonUInt32Value(json_object_get(cred, "flags"));

    err = _BIDValidateReauthCredStrength(context, cred);
    BID_BAIL_ON_ERROR(err);

    /*
     * _BIDVerifyLocal will verify the authenticator expiry as it is in the
     * claims and is the moral equivalent of the assertion expiry. However,
     * we also need to verify the ticket is still valid. We need to create
     * new object as _BIDValidateExpiry expects the expiry time to be in
     * the exp attribute.
     */
    err = _BIDValidateExpiry(context, verificationTime, cred);
    BID_BAIL_ON_ERROR(err);

    if (ulTicketFlags & BID_TICKET_FLAG_MUTUAL_AUTH)
        *pulRetFlags |= BID_VERIFY_FLAG_REAUTH_MUTUAL;

    *pVerifierCred = json_incref(json_object_get(cred, "ark"));

    err = _BIDVerifySignature(context, ap, *pVerifierCred);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeReauthIdentity(context, cred, ap, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

    /*
     * Propagate the renew-exp, crv and/or dh-key-size attributes from the
     * original ticket into the identity so that any additional tickets
     * also have this same value.
     */
    err = _BIDJsonObjectSet(context, (*pVerifiedIdentity)->PrivateAttributes,
                            "renew-exp", json_object_get(cred, "renew-exp"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, (*pVerifiedIdentity)->PrivateAttributes,
                            "crv", json_object_get(cred, "crv"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, (*pVerifiedIdentity)->PrivateAttributes,
                            "dh-key-size", json_object_get(cred, "dh-key-size"), 0);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (err != BID_S_OK) {
        json_decref(*pVerifierCred);
        *pVerifierCred = NULL;
    }

    json_decref(cred);

    return err;
}

BIDError
BIDAcquireTicketCache(
    BIDContext context,
    const char *szCacheName,
    BIDTicketCache *pCache)
{
    return _BIDAcquireCache(context, szCacheName, 0, pCache);
}

BIDError
BIDReleaseTicketCache(
    BIDContext context,
    BIDTicketCache cache)
{
    return _BIDReleaseCache(context, cache);
}

