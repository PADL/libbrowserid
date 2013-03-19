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
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
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

BIDError
_BIDAcquireDefaultReplayCache(BIDContext context)
{
    return _BIDAcquireCacheForUser(context, "browserid.replay", &context->ReplayCache);
}

BIDError
_BIDCheckReplayCache(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    time_t verificationTime)
{
    BIDError err;
    json_t *rdata = NULL;
    unsigned char hash[32];
    char *szHash = NULL;
    size_t cbHash = sizeof(hash), cchHash;
    time_t tsHash, expHash;

    err = _BIDDigestAssertion(context, szAssertion, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64UrlEncode(hash, cbHash, &szHash, &cchHash);
    BID_BAIL_ON_ERROR(err);

    if (replayCache == BID_C_NO_REPLAY_CACHE)
        replayCache = context->ReplayCache;

    err = _BIDGetCacheObject(context, replayCache, szHash, &rdata);
    if (err == BID_S_OK) {
        _BIDGetJsonTimestampValue(context, rdata, "iat", &tsHash);
        _BIDGetJsonTimestampValue(context, rdata, "exp", &expHash);

        if (verificationTime < expHash)
            err = BID_S_REPLAYED_ASSERTION;
    } else
        err = BID_S_OK;

cleanup:
    BIDFree(szHash);
    json_decref(rdata);

    return err;
}

static BIDError
_BIDGetReauthPolicy(
    BIDContext context,
    uint32_t *pulTicketLifetime,
    uint32_t *pulRenewLifetime)
{
    json_t *tmp = NULL;
    uint32_t ulTicketLifetime = 0;
    uint32_t ulRenewLifetime = 0;

    if (_BIDGetCacheObject(context, context->RPConfig, "maxticketage", &tmp) == BID_S_OK) {
        ulTicketLifetime = json_integer_value(tmp);
        json_decref(tmp);
    }

    if (ulTicketLifetime == 0)
        BIDGetContextParam(context, BID_PARAM_TICKET_LIFETIME, (void **)&ulTicketLifetime);

    *pulTicketLifetime = ulTicketLifetime;

    if (_BIDGetCacheObject(context, context->RPConfig, "maxrenewage", &tmp) == BID_S_OK) {
        ulRenewLifetime = json_integer_value(tmp);
        json_decref(tmp);
    }

    if (ulRenewLifetime == 0)
        BIDGetContextParam(context, BID_PARAM_RENEW_LIFETIME, (void **)&ulRenewLifetime);

    *pulRenewLifetime = ulRenewLifetime;

    return BID_S_OK;
}

BIDError
_BIDUpdateReplayCache(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDIdentity identity,
    const char *szAssertion,
    time_t verificationTime,
    uint32_t ulFlags)
{
    BIDError err;
    json_t *rdata = NULL;
    unsigned char hash[32];
    char *szHash = NULL;
    size_t cbHash = sizeof(hash), cchHash;
    json_t *ark = NULL;
    json_t *tkt = NULL;
    int bStoreReauthCreds = 0;
    uint32_t ticketLifetime = 0, renewLifetime = 0;
    time_t ticketExpiry = 0, renewExpiry = 0;

    err = _BIDDigestAssertion(context, szAssertion, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64UrlEncode(hash, cbHash, &szHash, &cchHash);
    BID_BAIL_ON_ERROR(err);

    _BIDGetJsonTimestampValue(context, identity->PrivateAttributes, "renew-exp", &renewExpiry);

    /*
     * Issue a new ticket if we have a certificate-signed assertion or if the
     * re-authentication ticket is within the renewable lifetime.
     */
    if (context->ContextOptions & BID_CONTEXT_REAUTH) {
        bStoreReauthCreds =
            (ulFlags & BID_VERIFY_FLAG_REAUTH) == 0 ||
            (verificationTime - renewExpiry <= context->Skew);
    }

    err = _BIDGetReauthPolicy(context, &ticketLifetime, &renewLifetime);
    BID_BAIL_ON_ERROR(err);

    rdata = bStoreReauthCreds ? json_copy(identity->Attributes) : json_object();
    if (rdata == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDSetJsonTimestampValue(context, rdata, "iat", verificationTime);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, rdata, "a-exp",
                            json_object_get(identity->PrivateAttributes, "a-exp"), 0);
    BID_BAIL_ON_ERROR(err);

    if (context->TicketLifetime)
        ticketExpiry = verificationTime + ticketLifetime;
    if ((ulFlags & BID_VERIFY_FLAG_REAUTH) == 0)
        renewExpiry = verificationTime + renewLifetime;

    if (bStoreReauthCreds) {
        uint32_t ulTicketFlags;

        err = _BIDDeriveSessionSubkey(context, identity, "ARK", &ark);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, rdata, "ark", ark, 0);
        BID_BAIL_ON_ERROR(err);

        ulTicketFlags = 0;
        if (ulFlags & BID_VERIFY_FLAG_REAUTH)
            ulTicketFlags |= BID_TICKET_FLAG_RENEWED;
        if (_BIDCanMutualAuthP(context))
            ulTicketFlags |= BID_TICKET_FLAG_MUTUAL_AUTH;

        if (ulTicketFlags) {
            err = _BIDJsonObjectSet(context, rdata, "flags", json_integer(ulTicketFlags),
                                    BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
            BID_BAIL_ON_ERROR(err);
        }

        if (ticketExpiry) {
            err = _BIDSetJsonTimestampValue(context, rdata, "exp", ticketExpiry);
            BID_BAIL_ON_ERROR(err);
        }

        if (renewExpiry) {
            err = _BIDSetJsonTimestampValue(context, rdata, "renew-exp", renewExpiry);
            BID_BAIL_ON_ERROR(err);
        }

        /*
         * Store the number of bits of entropy in the original key so that we don't
         * derive a "strong" key from an originally weak key.
         */
        err = _BIDSaveKeyAgreementStrength(context, identity, 1, rdata);
        BID_BAIL_ON_ERROR(err);
    } else {
        /* XXX is this even necessary? */
        err = _BIDJsonObjectSet(context, rdata, "exp",
                                json_object_get(identity->Attributes, "exp"), BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    if (replayCache == BID_C_NO_REPLAY_CACHE)
        replayCache = context->ReplayCache;

    err = _BIDSetCacheObject(context, replayCache, szHash, rdata);
    BID_BAIL_ON_ERROR(err);

    if (bStoreReauthCreds) {
        BID_ASSERT(identity->PrivateAttributes != NULL);

        tkt = json_object();
        if (tkt == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = _BIDJsonObjectSet(context, tkt, "jti", json_string(szHash),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, tkt, "exp", json_object_get(rdata, "exp"), 0);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "tkt", tkt, 0);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    BIDFree(szHash);
    json_decref(ark);
    json_decref(rdata);

    return err;
}

BIDError
BIDAcquireReplayCache(
    BIDContext context,
    const char *szCacheName,
    BIDReplayCache *pCache)
{
    return _BIDAcquireCache(context, szCacheName, 0, pCache);
}

BIDError
BIDReleaseReplayCache(
    BIDContext context,
    BIDReplayCache cache)
{
    return _BIDReleaseCache(context, cache);
}

static int
_BIDShouldPurgeReplayCacheEntryP(
    BIDContext context,
    BIDCache cache BID_UNUSED,
    const char *szKey BID_UNUSED,
    json_t *j,
    void *data)
{
    time_t now = *((time_t *)data);
    time_t expiryTime;

    /*
     * If the cache entry is being used for re-authentication (it has a key)
     * then purge only when the ticket expires. Otherwise, purge when the
     * assertion expires.
     */
    if (json_object_get(j, "ark") != NULL)
        _BIDGetJsonTimestampValue(context, j, "exp", &expiryTime);
    else
        _BIDGetJsonTimestampValue(context, j, "a-exp", &expiryTime);

    return (expiryTime == 0 || now >= expiryTime);
}

BIDError
_BIDPurgeReplayCache(
    BIDContext context,
    BIDCache cache,
    time_t currentTime)
{
    return _BIDPurgeCache(context, cache, _BIDShouldPurgeReplayCacheEntryP, &currentTime);
}
