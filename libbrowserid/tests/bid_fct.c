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

    err = BIDAcquireContext(NULL, 0, NULL, &context);
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
