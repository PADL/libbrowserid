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

struct BIDRegistryCache {
    HKEY Key;
    REGSAM AccessMask;
};

static BIDError
_BIDRegistryCacheMapError(LONG lResult)
{
    BIDError err;

    switch (lResult) {
    case ERROR_SUCCESS:
        err = BID_S_OK;
        break;
    case ERROR_CANTOPEN:
        err = BID_S_CACHE_OPEN_ERROR;
        break;
    case ERROR_CANTREAD:
        err = BID_S_CACHE_READ_ERROR;
        break;
    case ERROR_CANTWRITE:
        err = BID_S_CACHE_WRITE_ERROR;
        break;
    case ERROR_ACCESS_DENIED:
        err = BID_S_CACHE_PERMISSION_DENIED;
        break;
    case ERROR_BADDB:
        err = BID_S_CACHE_INVALID_VERSION;
        break;
    case ERROR_BADKEY:
    case ERROR_FILE_NOT_FOUND:
        err = BID_S_CACHE_KEY_NOT_FOUND;
        break;
    case ERROR_NO_MORE_ITEMS:
        err = BID_S_NO_MORE_ITEMS;
        break;
    case ERROR_MORE_DATA:
        err = BID_S_BUFFER_TOO_SMALL;
        break;
    default:
        err = BID_S_INVALID_PARAMETER;
        break;
    }

    return err;
}
 
static BIDError
_BIDRegistryCacheAcquire(
    struct BIDCacheOps *ops,
    BIDContext context,
    void **cache,
    const char *name,
    uint32_t ulFlags)
{
    BIDError err;
    LONG lResult;
    HKEY hRootKey;
    PWSTR wszSubKey = NULL;
    struct BIDRegistryCache *rc;

    if (name == NULL)
        return BID_S_INVALID_PARAMETER;

    if (_strnicmp(name, "HKLM\\", 5) == 0) {
        hRootKey = HKEY_LOCAL_MACHINE;
    } else if (_strnicmp(name, "HKCR\\", 5) == 0) {
        hRootKey = HKEY_CLASSES_ROOT;
    } else if (_strnicmp(name, "HKCU\\", 5) == 0) {
        hRootKey = HKEY_CURRENT_USER;
    } else {
        return BID_S_INVALID_PARAMETER;
    }

    rc = BIDCalloc(1, sizeof(*rc));
    if (rc == NULL)
        return BID_S_NO_MEMORY;

    rc->Key = (HKEY)0;

    err = _BIDUtf8ToUcs2(context, &name[5], &wszSubKey);
    if (err != BID_S_OK) {
        ops->Release(ops, context, rc);
        return err;
    }

    if (ulFlags & BID_CACHE_FLAG_READONLY)
        rc->AccessMask = KEY_READ;
    else
        rc->AccessMask = KEY_ALL_ACCESS;

    lResult = RegOpenKeyExW(hRootKey, wszSubKey, 0, rc->AccessMask, &rc->Key);
    if (lResult != STATUS_SUCCESS) {
        ops->Release(ops, context, rc);

        err = _BIDRegistryCacheMapError(lResult);
        if (err == BID_S_CACHE_KEY_NOT_FOUND)
            err = BID_S_CACHE_NOT_FOUND;
    } else
        err = BID_S_OK;

    BIDFree(wszSubKey);

    if (err == BID_S_OK)
        *cache = rc;

    return err;
}

static BIDError
_BIDRegistryCacheRelease(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;

    if (rc == NULL)
        return BID_S_INVALID_PARAMETER;

    if (rc->Key)
        RegCloseKey(rc->Key);
    BIDFree(rc);

    return BID_S_OK;
}

static BIDError
_BIDRegistryCacheInitialize(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache BID_UNUSED)
{
    return BID_S_OK;
}

static BIDError
_BIDRegistryCacheDestroy(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;

    if (rc == NULL)
        return BID_S_INVALID_PARAMETER;

    return BID_S_CACHE_PERMISSION_DENIED;
}

static BIDError
_BIDRegistryCacheGetName(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char **name)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;

    if (rc == NULL)
        return BID_S_INVALID_PARAMETER;

    return BID_S_NOT_IMPLEMENTED;
}

static BIDError
_BIDRegistryCacheGetLastChangedTime(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    time_t *pTime)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;
    FILETIME ftLastWriteTime;

    *pTime = 0;

    if (rc == NULL)
        return BID_S_INVALID_PARAMETER;

    if (RegQueryInfoKey(rc->Key, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL, &ftLastWriteTime) == ERROR_SUCCESS) {
        return _BIDTimeToSecondsSince1970(context, &ftLastWriteTime, pTime);
    }

    return BID_S_OK;
}

static BIDError
_BIDRegistryEnumKey(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context,
    struct BIDRegistryCache *rc,
    HKEY hKey,
    json_t *pJson);

static BIDError
_BIDRegistryMakeValueMultiSz(
    BIDContext context,
    PBYTE pbData,
    DWORD cbData,
    json_t **pJson)
{
    BIDError err;
    json_t *json = NULL;
    PWSTR p = (PWSTR)pbData;

    *pJson = NULL;

    json = json_array();
    if (json == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    /* Make sure the entire array is NUL terminated, caller made room */
    p[cbData / sizeof(WCHAR)] = 0;

    while (*p != 0) {
        char *szUtf8String;
        DWORD cchValue;

        err = _BIDUcs2ToUtf8(context, (PWSTR)p, &szUtf8String);
        BID_BAIL_ON_ERROR(err);

        if (json_array_append_new(json, json_string(szUtf8String)) < 0) {
            BIDFree(szUtf8String);
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        cchValue = wcslen(p);
        p += cchValue + 1;

        BIDFree(szUtf8String);
    }

    err = BID_S_OK;
    *pJson = json;

cleanup:
    if (err != BID_S_OK)
        json_decref(json);

    return err;
}

static BIDError
_BIDRegistryMakeValue(
    BIDContext context,
    DWORD dwType,
    PBYTE pbData,
    DWORD cbData,
    json_t **pJson)
{
    BIDError err = BID_S_OK;
    json_t *json = NULL;

    *pJson = NULL;

    switch (dwType) {
    case REG_BINARY:
        err = _BIDJsonBinaryValue(context, pbData, cbData, &json);
        break;
    case REG_DWORD:
        json = json_integer(*((DWORD *)pbData));
        break;
    case REG_QWORD:
        json = json_integer(*((LONGLONG *)pbData));
        break;
    case REG_SZ: {
        char *szUtf8String;

        ((PWSTR)pbData)[cbData / sizeof(WCHAR)] = 0;

        err = _BIDUcs2ToUtf8(context, (PWSTR)pbData, &szUtf8String);
        if (err == BID_S_OK) {
            json = json_string(szUtf8String);
            BIDFree(szUtf8String);
        }
        break;
    }
    case REG_MULTI_SZ:
        err = _BIDRegistryMakeValueMultiSz(context, pbData, cbData, &json);
        break;
    case REG_NONE:
        json = json_null();
        break;
    default:
        err = BID_S_CACHE_KEY_NOT_FOUND;
        break;
    }

    if (err == BID_S_OK && json == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BID_S_OK;
    *pJson = json;

cleanup:
    if (err != BID_S_OK)
        json_decref(json);

    return err;
}

static BIDError
_BIDRegistryEnumValue(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context,
    struct BIDRegistryCache *rc,
    HKEY hKey,
    DWORD dwIndex,
    json_t *jsonDictionary)
{
    BIDError err;
    LONG lResult;
    WCHAR wszValueName[260];
    DWORD cchValueName = ARRAYSIZE(wszValueName) - 1;
    PBYTE pbData = NULL;
    DWORD dwType;
    DWORD cbData = 0;
    json_t *json = NULL;
    char *szValueName = NULL;

    lResult = RegEnumValueW(hKey, dwIndex, wszValueName, &cchValueName,
                            NULL, &dwType, NULL, &cbData);
    BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

    cchValueName = ARRAYSIZE(wszValueName) - 1;

    pbData = BIDMalloc(cbData + sizeof(WCHAR));
    if (pbData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    lResult = RegEnumValueW(hKey, dwIndex, wszValueName, &cchValueName,
                            NULL, &dwType, pbData, &cbData);
    BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

    err = _BIDRegistryMakeValue(context, dwType, pbData, cbData, &json);
    if (err == BID_S_CACHE_KEY_NOT_FOUND) {
        /* Ignore unknown registry value types */
        err = BID_S_OK;
        goto cleanup;
    }
    BID_BAIL_ON_ERROR(err);

    err = _BIDUcs2ToUtf8(context, wszValueName, &szValueName);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, jsonDictionary, szValueName, json,
                            BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(json);
    BIDFree(pbData);
    BIDFree(szValueName);

    return err;
}

static BIDError
_BIDRegistryEnumKey(
    struct BIDCacheOps *ops,
    BIDContext context,
    struct BIDRegistryCache *rc,
    HKEY hRootKey,
    json_t *json)
{
    BIDError err = BID_S_OK;
    LONG lResult = ERROR_SUCCESS;
    DWORD dwIndex;
    HKEY hSubKey = NULL;
    char *szKeyName = NULL;
    json_t *jsonSubKey = NULL;

    /*
     * Enumerate the values in this key.
     */
    for (dwIndex = 0; err == BID_S_OK; dwIndex++)
        err = _BIDRegistryEnumValue(ops, context, rc, hRootKey, dwIndex, json);
    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;
    BID_BAIL_ON_ERROR(err);

    /*
     * For each subkey, enumerate its values and keys.
     */
    for (dwIndex = 0; lResult == ERROR_SUCCESS; dwIndex++) {
        WCHAR wszKeyName[256];
        DWORD cchKeyName = ARRAYSIZE(wszKeyName) - 1;

        lResult = RegEnumKeyExW(hRootKey, dwIndex, wszKeyName,
                                &cchKeyName, NULL, NULL, NULL, NULL);
        BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

        lResult = RegOpenKeyExW(hRootKey, wszKeyName, 0,    
                                rc->AccessMask, &hSubKey);
        BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

        jsonSubKey = json_object();
        if (jsonSubKey == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = _BIDRegistryEnumKey(ops, context, rc, hSubKey, jsonSubKey);
        BID_BAIL_ON_ERROR(err);

        err = _BIDUcs2ToUtf8(context, wszKeyName, &szKeyName);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, json, szKeyName, jsonSubKey,
                                BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);

        RegCloseKey(hSubKey);
        hSubKey = NULL;

        BIDFree(szKeyName);
        szKeyName = NULL;

        json_decref(jsonSubKey);
        jsonSubKey = NULL;
    }

cleanup:
    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;
    if (hSubKey)
        RegCloseKey(hSubKey);
    BIDFree(szKeyName);
    json_decref(jsonSubKey);

    return err;
}

static BIDError
_BIDRegistryCacheGetObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char *key,
    json_t **val)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;
    BIDError err;
    LONG lResult;
    PWSTR wszKeyName = NULL;
    HKEY hKey = NULL;
    json_t *json = NULL;
    DWORD dwType;
    DWORD cbData;
    PBYTE pbData = NULL;

    *val = NULL;

    if (rc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDUtf8ToUcs2(context, key, &wszKeyName);
    BID_BAIL_ON_ERROR(err);

    lResult = RegOpenKeyExW(rc->Key, wszKeyName, 0, rc->AccessMask, &hKey);
    if (lResult == ERROR_FILE_NOT_FOUND) {
        lResult = RegQueryValueExW(rc->Key, wszKeyName, 0, &dwType,
                                   NULL, &cbData);
        BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

        pbData = BIDMalloc(cbData + sizeof(WCHAR));
        if (pbData == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        lResult = RegQueryValueExW(rc->Key, wszKeyName, 0, &dwType,
                                   pbData, &cbData);
        BID_BAIL_ON_ERROR((err = _BIDRegistryCacheMapError(lResult)));

        err = _BIDRegistryMakeValue(context, dwType, pbData, cbData, &json);
        BID_BAIL_ON_ERROR(err);
    } else if (lResult == ERROR_SUCCESS) {
        json = json_object();
        if (json == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = _BIDRegistryEnumKey(ops, context, rc, hKey, json);
        BID_BAIL_ON_ERROR(err);
    } else {
        err = _BIDRegistryCacheMapError(lResult);
        goto cleanup;
    }

    *val = json;
    json = NULL;

cleanup:
    if (hKey)
        RegCloseKey(hKey);
    BIDFree(wszKeyName);
    json_decref(json);
    BIDFree(pbData);

    return err;
}

static BIDError
_BIDRegistryCacheSetObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key,
    json_t *val)
{
    return BID_S_NOT_IMPLEMENTED;
}

static BIDError
_BIDRegistryCacheRemoveObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key)
{
    return BID_S_NOT_IMPLEMENTED;
}

static BIDError
_BIDRegistryCacheFirstObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    void **cookie,
    const char **key,
    json_t **val)
{
    struct BIDRegistryCache *rc = (struct BIDRegistryCache *)cache;
    BIDError err;
    json_t *jsonKeys = NULL;

    *cookie = NULL;
    *key = NULL;
    *val = NULL;

    if (rc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    jsonKeys = json_object();
    if (jsonKeys == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDRegistryEnumKey(ops, context, rc, rc->Key, jsonKeys);
    BID_BAIL_ON_ERROR(err);

    err = _BIDCacheIteratorAlloc(jsonKeys, cookie);
    BID_BAIL_ON_ERROR(err);

    err = _BIDCacheIteratorNext(cookie, key, val);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(jsonKeys);

    return err;
}

static BIDError
_BIDRegistryCacheNextObject(
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

struct BIDCacheOps _BIDRegistryCache = {
    "registry",
    _BIDRegistryCacheAcquire,
    _BIDRegistryCacheRelease,
    _BIDRegistryCacheInitialize,
    _BIDRegistryCacheDestroy,
    _BIDRegistryCacheGetName,
    _BIDRegistryCacheGetLastChangedTime,
    _BIDRegistryCacheGetObject,
    _BIDRegistryCacheSetObject,
    _BIDRegistryCacheRemoveObject,
    _BIDRegistryCacheFirstObject,
    _BIDRegistryCacheNextObject,
};
