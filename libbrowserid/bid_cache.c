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

#ifdef __APPLE__
#include <pwd.h>
#include <sys/stat.h>
#endif

struct BIDCacheDesc {
    struct BIDCacheOps *Ops;
    void *Data;
};

static struct BIDCacheOps *_BIDCacheOps[] = {
#ifdef WIN32
    &_BIDRegistryCache,
#else
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

#if 0
BIDError
_BIDGetCacheBinaryValue(
    BIDContext context BID_UNUSED,
    BIDCache cache,
    const char *key,
    unsigned char **pbData,
    size_t *cbData)
{
    BIDError err;
    const char *src;
    json_t *value;

    err = _BIDGetCacheObject(context, cache, key, &value);
    if (err =! BID_S_OK)
        return err;

    src = json_string_value(value);
    if (src == NULL) {
        json_decref(value);
        return BID_S_UNKNOWN_JSON_KEY;
    }

    err = _BIDBase64UrlDecode(src, pbData, cbData);

    json_decref(value);

    return err;
}
#endif

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

BIDError
_BIDPerformCacheObjects(
    BIDContext context,
    BIDCache cache,
    BIDError (*selector)(BIDContext, BIDCache, const char *, json_t *, void *data),
    void *data)
{
    BIDError err, err2 = BID_S_OK;
    void *cookie = NULL;
    const char *k = NULL;
    json_t *j = NULL;

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    for (err = _BIDGetFirstCacheObject(context, cache, &cookie, &k, &j);
         err == BID_S_OK;
         err = _BIDGetNextCacheObject(context, cache, &cookie, &k, &j)) {
        if (err2 == BID_S_OK)
            err2 = selector(context, cache, k, j, data);
        /* can't break as we need to release cookie XXX */
        json_decref(j);
    }

    if (err == BID_S_NO_MORE_ITEMS)
        err = err2;

    return err;
}

struct BIDPurgeCacheArgsDesc {
    int (*Selector)(BIDContext, BIDCache, const char *, json_t *, void *);
    void *Data;
};

static BIDError
_BIDRemoveCacheObjectIfSelectorTrue(
    BIDContext context,
    BIDCache cache,
    const char *szKey,
    json_t *jsonValue,
    void *data)
{
    struct BIDPurgeCacheArgsDesc *args = data;

    if (args->Selector(context, cache, szKey, jsonValue, args->Data))
        _BIDRemoveCacheObject(context, cache, szKey);

    return BID_S_OK;
}

BIDError
_BIDPurgeCache(
    BIDContext context,
    BIDCache cache,
    int (*selector)(BIDContext, BIDCache, const char *, json_t *, void *),
    void *data)
{
    struct BIDPurgeCacheArgsDesc args;

    args.Selector = selector;
    args.Data = data;

    return _BIDPerformCacheObjects(context, cache, _BIDRemoveCacheObjectIfSelectorTrue, &args);
}

BIDError
_BIDAcquireCacheForUser(
    BIDContext context,
    const char *szTemplate,
    BIDCache *pCache)
{
    BIDError err;
#ifdef WIN32
    err = _BIDAcquireCache(context, "memory:", 0, pCache);
#else
    char szFileName[PATH_MAX];

    *pCache = NULL;

#ifdef __APPLE__
    struct passwd *pw, pwd;
    char pwbuf[BUFSIZ];
    struct stat sb;
    const char *szPrefix;

    if (getpwuid_r(geteuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) < 0 ||
        pw == NULL ||
        pw->pw_dir == NULL) {
        err = BID_S_CACHE_OPEN_ERROR;
        goto cleanup;
    }

    szPrefix = (pw->pw_uid == 0) ? "" : pw->pw_dir;

    snprintf(szFileName, sizeof(szFileName),
             "%s/Library/Caches/com.padl.gss.BrowserID", szPrefix);

    if (stat(szFileName, &sb) < 0)
        mkdir(szFileName, 0700);

    snprintf(szFileName, sizeof(szFileName),
             "file:%s/Library/Caches/com.padl.gss.BrowserID/%s.json",
             szPrefix, szTemplate);
#else
    char *szRuntimeDir;

    szRuntimeDir = getenv("XDG_RUNTIME_DIR");
    if (szRuntimeDir != NULL)
        snprintf(szFileName, sizeof(szFileName),
                 "file:%s/%s.json", szRuntimeDir, szTemplate);
    else
        snprintf(szFileName, sizeof(szFileName),
                 "file:/tmp/.%s.%d.json", szTemplate, geteuid());
#endif

    err = _BIDAcquireCache(context, szFileName, 0, pCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
#endif /* WIN32 */

    return err;
}
