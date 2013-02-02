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

struct BIDMemoryCache {
    BID_MUTEX Mutex;
    char *Name;
    json_t *Data;
    uint32_t Flags;
};

/*
 * Concurrency makes the following assumptions:
 *
 * - libjansson is compiled with atomic refcounting ops
 * - returned values are immutable
 * - iteration APIs are not used
 */
#define BIDMemoryCacheLock(mc)      BID_MUTEX_LOCK(&(mc)->Mutex)
#define BIDMemoryCacheUnlock(mc)    BID_MUTEX_UNLOCK(&(mc)->Mutex)

static BIDError
_BIDMemoryCacheAcquire(
    struct BIDCacheOps *ops,
    BIDContext context,
    void **cache,
    const char *name,
    uint32_t ulFlags BID_UNUSED)
{
    BIDError err;
    struct BIDMemoryCache *mc;

    mc = BIDCalloc(1, sizeof(*mc));
    if (mc == NULL)
        return BID_S_NO_MEMORY;

    mc->Data = json_object();
    if (mc == NULL) {
        ops->Release(ops, context, mc);
        return BID_S_NO_MEMORY;
    }

    err = _BIDDuplicateString(context, name, &mc->Name);
    if (err != BID_S_OK) {
        ops->Release(ops, context, mc);
        return err;
    }

    BID_MUTEX_INIT(&mc->Mutex);

    mc->Flags = ulFlags;

    *cache = mc;

    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheRelease(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;

    if (mc == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(mc->Name);
    json_decref(mc->Data);
    BID_MUTEX_DESTROY(&mc->Mutex);
    BIDFree(mc);

    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheInitialize(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache BID_UNUSED)
{
    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheDestroy(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;
    json_t *j;

    if (mc == NULL)
        return BID_S_INVALID_PARAMETER;

    j = json_object();
    if (j == NULL)
        return BID_S_NO_MEMORY;

    BIDMemoryCacheLock(mc);

    json_decref(mc->Data);
    mc->Data = j;

    BIDMemoryCacheUnlock(mc);

    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheGetName(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char **name)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;

    if (mc == NULL)
        return BID_S_INVALID_PARAMETER;

    *name = mc->Name;

    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheGetLastChangedTime(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    time_t *pTime)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;

    *pTime = 0;

    if (mc == NULL)
        return BID_S_INVALID_PARAMETER;

    *pTime = time(NULL); /* XXX */

    return BID_S_OK;
}

static BIDError
_BIDMemoryCacheGetObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char *key,
    json_t **val)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;
    BIDError err;

    *val = NULL;

    if (mc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    BIDMemoryCacheLock(mc);
    *val = json_incref(json_object_get(mc->Data, key));
    BIDMemoryCacheUnlock(mc);

    if (*val == NULL)
        err = BID_S_CACHE_KEY_NOT_FOUND;
    else
        err = BID_S_OK;

cleanup:

    return err;
}

static BIDError
_BIDMemoryCacheSetOrRemoveObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char *key,
    json_t *val,
    int remove)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;
    BIDError err;

    if (mc == NULL || (val == NULL && !remove)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (mc->Flags & BID_CACHE_FLAG_READONLY) {
        err = BID_S_CACHE_PERMISSION_DENIED;
        goto cleanup;
    }

    BIDMemoryCacheLock(mc);
    if (remove)
        err = _BIDJsonObjectDel(context, mc->Data, key, 0);
    else
        err = _BIDJsonObjectSet(context, mc->Data, key, val, 0);
    BIDMemoryCacheUnlock(mc);

    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    return err;
}

static BIDError
_BIDMemoryCacheSetObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key,
    json_t *val)
{
    return _BIDMemoryCacheSetOrRemoveObject(ops, context, cache, key, val, 0);
}

static BIDError
_BIDMemoryCacheRemoveObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key)
{
    return _BIDMemoryCacheSetOrRemoveObject(ops, context, cache, key, NULL, 1);
}

static BIDError
_BIDMemoryCacheFirstObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    void **cookie,
    const char **key,
    json_t **val)
{
    struct BIDMemoryCache *mc = (struct BIDMemoryCache *)cache;
    BIDError err;

    *cookie = NULL;
    *key = NULL;
    *val = NULL;

    if (mc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    BIDMemoryCacheLock(mc);
    err = _BIDCacheIteratorAlloc(json_copy(mc->Data), cookie);
    BIDMemoryCacheUnlock(mc);

    BID_BAIL_ON_ERROR(err);

    err = _BIDCacheIteratorNext(cookie, key, val);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

static BIDError
_BIDMemoryCacheNextObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache BID_UNUSED,
    void **cookie,
    const char **key,
    json_t **val)
{
    BIDError err;

    *key = NULL;
    *val = NULL;

    err = _BIDCacheIteratorNext(cookie, key, val);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

struct BIDCacheOps _BIDMemoryCache = {
    "memory",
    _BIDMemoryCacheAcquire,
    _BIDMemoryCacheRelease,
    _BIDMemoryCacheInitialize,
    _BIDMemoryCacheDestroy,
    _BIDMemoryCacheGetName,
    _BIDMemoryCacheGetLastChangedTime,
    _BIDMemoryCacheGetObject,
    _BIDMemoryCacheSetObject,
    _BIDMemoryCacheRemoveObject,
    _BIDMemoryCacheFirstObject,
    _BIDMemoryCacheNextObject,
};

