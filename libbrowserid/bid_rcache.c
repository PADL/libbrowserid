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

    err = _BIDAcquireCache(context, ".browserid.replay.json", &context->ReplayCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDCheckReplayCache(
    BIDContext context,
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

    err = _BIDGetCacheObject(context, context->ReplayCache, szHash, &rdata);
    if (err == BID_S_CACHE_NOT_FOUND || err == BID_S_CACHE_KEY_NOT_FOUND)
        err = BID_S_OK;
    BID_BAIL_ON_ERROR(err);

    tsHash = json_integer_value(json_object_get(rdata, "ts"));
    expHash = json_integer_value(json_object_get(rdata, "exp"));

    if (expHash < verificationTime)
        err = BID_S_OK;
    else
        err = BID_S_REPLAYED_ASSERTION;

cleanup:
    BIDFree(szHash);
    json_decref(rdata);

    return err;
}

BIDError
_BIDUpdateReplayCache(
    BIDContext context,
    const char *szAssertion,
    time_t verificationTime,
    json_t *expiryTime)
{
    BIDError err;
    json_t *rdata;
    unsigned char hash[32];
    char *szHash = NULL;
    size_t cbHash = sizeof(hash), cchHash;

    err = _BIDDigestAssertion(context, szAssertion, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDBase64UrlEncode(hash, cbHash, &szHash, &cchHash);
    BID_BAIL_ON_ERROR(err);

    verificationTime *= 1000; /* to ms */

    rdata = json_object();
    json_object_set_new(rdata, "ts", json_integer(verificationTime));
    if (expiryTime != NULL)
        json_object_set(rdata, "exp", expiryTime);
    else
        json_object_set(rdata, "exp", json_integer(verificationTime + 300));

    err = _BIDSetCacheObject(context, context->ReplayCache, szHash, rdata);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szHash);
    json_decref(rdata);

    return err;
}
