/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

struct BIDCacheDesc {
    struct BIDCacheOps *Ops;
    void *Data;
};

static struct BIDCacheOps *_BIDCacheOps[] = {
#ifndef WIN32
    &_BIDFileCache,
#endif
    &_BIDMemoryCache
};

BIDError
_BIDAcquireCache(
    BIDContext context,
    const char *szCacheName,
    uint32_t ulFlags,
    BIDCache *pCache)
{
    BIDError err;
    BIDCache cache = NULL;
    const char *p;
    struct BIDCacheOps *ops = NULL;

    BID_CONTEXT_VALIDATE(context);

    p = strchr(szCacheName, ':');
    if (p == NULL) {
        ops = _BIDCacheOps[0];
    } else {
        size_t cchScheme = (p - szCacheName), i;

        for (i = 0; i < sizeof(_BIDCacheOps) / sizeof(_BIDCacheOps[0]); i++) {
            if (strncmp(szCacheName, _BIDCacheOps[i]->Scheme, cchScheme) == 0) {
                ops = _BIDCacheOps[i];
                break;
            }
        }

        szCacheName += cchScheme + 1;
    }

    if (ops == NULL) {
        err = BID_S_CACHE_SCHEME_UNKNOWN;
        goto cleanup;
    }

    cache = BIDCalloc(1, sizeof(*cache));
    if (cache == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    cache->Ops = ops;
    cache->Data = NULL;

    err = cache->Ops->Acquire(cache->Ops, context, &cache->Data, szCacheName, ulFlags);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pCache = cache;

cleanup:
    if (err != BID_S_OK)
        BIDFree(cache);

    return err;
}

BIDError
_BIDReleaseCache(
    BIDContext context,
    BIDCache cache)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->Release == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->Release(cache->Ops, context, cache->Data);
    if (err == BID_S_OK)
        BIDFree(cache);

    return err;
}

BIDError
_BIDInitializeCache(
    BIDContext context,
    BIDCache cache)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->Initialize == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->Initialize(cache->Ops, context, cache->Data);

    return err;
}

BIDError
_BIDDestroyCache(
    BIDContext context,
    BIDCache cache)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->Destroy == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->Destroy(cache->Ops, context, cache->Data);

    return err;
}

BIDError
_BIDGetCacheName(
    BIDContext context,
    BIDCache cache,
    const char **pszName)
{
    BIDError err;

    *pszName = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->GetName == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->GetName(cache->Ops, context, cache->Data, pszName);

    return err;
}

BIDError
_BIDGetCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key,
    json_t **pValue)
{
    BIDError err;
    json_t *value = NULL;

    if (pValue != NULL)
        *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (key == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->GetObject == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->GetObject(cache->Ops, context, cache->Data, key, &value);
    if (err == BID_S_OK && pValue != NULL)
        *pValue = value;
    else
        json_decref(value);

    return err;
}

BIDError
_BIDSetCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key,
    json_t *value)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (key == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->SetObject == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->SetObject(cache->Ops, context, cache->Data, key, value);

    return err;
}

BIDError
_BIDRemoveCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (key == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->RemoveObject == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->RemoveObject(cache->Ops, context, cache->Data, key);

    return err;
}

BIDError
_BIDGetCacheLastChangedTime(
    BIDContext context,
    BIDCache cache,
    time_t *ptLastChanged)
{
    BIDError err;

    *ptLastChanged = 0;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->GetLastChangedTime == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->GetLastChangedTime(cache->Ops, context, cache->Data, ptLastChanged);

    return err;
}

BIDError
_BIDGetFirstCacheObject(
    BIDContext context,
    BIDCache cache,
    void **pCookie,
    const char **pKey,
    json_t **pValue)
{
    BIDError err;

    *pCookie = NULL;
    *pKey = NULL;
    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->FirstObject == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->FirstObject(cache->Ops, context, cache->Data, pCookie, pKey, pValue);

    return err;
}

BIDError
_BIDGetNextCacheObject(
    BIDContext context,
    BIDCache cache,
    void **pCookie,
    const char **pKey,
    json_t **pValue)
{
    BIDError err;

    *pKey = NULL;
    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (cache == NULL || *pCookie == NULL)
        return BID_S_INVALID_PARAMETER;

    if (cache->Ops->NextObject == NULL)
        return BID_S_NOT_IMPLEMENTED;

    err = cache->Ops->NextObject(cache->Ops, context, cache->Data, pCookie, pKey, pValue);

    return err;
}

/*
 * Helpers
 */
struct BIDCacheIteratorDesc {
    json_t *Data;
    void *Iterator;
};

static void
_BIDCacheIteratorRelease(struct BIDCacheIteratorDesc *iter)
{
    if (iter != NULL) {
        json_decref(iter->Data);
        BIDFree(iter);
    }
}

BIDError
_BIDCacheIteratorAlloc(
    json_t *json,
    void **pCookie)
{
    struct BIDCacheIteratorDesc *iter;

    BID_ASSERT(pCookie != NULL);

    if (json == NULL)
        return BID_S_INVALID_PARAMETER;

    iter = BIDCalloc(1, sizeof(*iter));
    if (iter == NULL)
        return BID_S_NO_MEMORY;

    iter->Data = json_incref(json);
    if (iter->Data == NULL) {
        _BIDCacheIteratorRelease(iter);
        return BID_S_NO_MEMORY;
    }

    iter->Iterator = json_object_iter(iter->Data);
    if (iter->Iterator == NULL) {
        _BIDCacheIteratorRelease(iter);
        return BID_S_CACHE_KEY_NOT_FOUND;
    }

    *pCookie = iter;
    return BID_S_OK;
}

BIDError
_BIDCacheIteratorNext(
    void **cookie,
    const char **pKey,
    json_t **pValue)
{
    struct BIDCacheIteratorDesc *iter = *cookie;

    if (iter->Iterator == NULL) {
        _BIDCacheIteratorRelease(iter);
        *cookie = NULL;
        return BID_S_NO_MORE_ITEMS;
    }

    *pKey = json_object_iter_key(iter->Iterator);
    *pValue = json_incref(json_object_iter_value(iter->Iterator));

    if (*pKey == NULL || *pValue == NULL) {
        _BIDCacheIteratorRelease(iter);
        *cookie = NULL;
        return BID_S_NO_MORE_ITEMS;
    }
 
    iter->Iterator = json_object_iter_next(iter->Data, iter->Iterator);

    return BID_S_OK;
}
