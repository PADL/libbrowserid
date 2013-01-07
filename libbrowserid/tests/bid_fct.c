/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"
#include "bid_private.h"

/*
 * File cache test
 */

int main(int argc, char *argv[])
{
    BIDError err;
    BIDCache cache = NULL;
    BIDContext context = NULL;
    const char *s;
    json_t *j = NULL;
    json_t *k = NULL;
    json_t *z = NULL;

    err = BIDAcquireContext(0, &context);
    BID_BAIL_ON_ERROR(err);

    j = json_string("bar");

    k = json_object();
    _BIDJsonObjectSet(context, k, "baz", json_string("12345678"), BID_JSON_FLAG_CONSUME_REF);
    _BIDJsonObjectSet(context, k, "bat", json_string("This is a test"), BID_JSON_FLAG_CONSUME_REF);

    err = _BIDAcquireCache(context, "test.json", 0, &cache);
    BID_BAIL_ON_ERROR(err);

    err = _BIDInitializeCache(context, cache);
    if (err == BID_S_CACHE_ALREADY_EXISTS)
        err = BID_S_OK;
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCacheObject(context, cache, "foo", j);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCacheObject(context, cache, "another_cache_object", k);
    BID_BAIL_ON_ERROR(err);

    err = _BIDRemoveCacheObject(context, cache, "foo");
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCacheObject(context, cache, "another_cache_object", &z);
    if (err == BID_S_OK)
        json_dumpf(z, stdout, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDestroyCache(context, cache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    _BIDReleaseCache(context, cache);
    BIDReleaseContext(context);

    if (err != BID_S_OK) {
        BIDErrorToString(err, &s);
        fprintf(stderr, "libbrowserid error %s[%d]\n", s, err);
    }

    json_decref(j);
    json_decref(k);
    json_decref(z);

    exit(err);
}
