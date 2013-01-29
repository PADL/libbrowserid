/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

struct BIDMemoryCache {
    BID_MUTEX Mutex;
    char *Name;
    json_t *Data;
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

