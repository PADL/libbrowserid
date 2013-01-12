/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
_BIDAcquireDefaultReplayCache(BIDContext context)
{
    BIDError err;

    err = BIDAcquireReplayCache(context, ".browserid.replay.json", &context->ReplayCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDCheckReplayCache(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    time_t verificationTime)
{
    BIDError err;
    json_t *rdata;
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
    json_t *rdata;
    unsigned char hash[32];
    char *szHash = NULL;
    size_t cbHash = sizeof(hash), cchHash;
    json_t *ark = NULL;
    json_t *tkt = NULL;
    int bStoreReauthCreds;

    err = _BIDDigestAssertion(context, szAssertion, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64UrlEncode(hash, cbHash, &szHash, &cchHash);
    BID_BAIL_ON_ERROR(err);

    bStoreReauthCreds = (context->ContextOptions & BID_CONTEXT_REAUTH) &&
                        !(ulFlags & BID_VERIFY_FLAG_REAUTH);

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

    if (bStoreReauthCreds) {
        err = _BIDDeriveSessionSubkey(context, identity, "ARK", &ark);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, rdata, "ark", ark, 0);
        BID_BAIL_ON_ERROR(err);
    } else {
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

