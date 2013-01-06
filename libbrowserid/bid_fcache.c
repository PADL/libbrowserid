/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */
/*
 * Portions Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "bid_private.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <sys/stat.h>

/*
 * Very loosely based on Heimdal's Kerberos credentials cache file backend.
 */

struct BIDFileCache {
    char *Name;
    json_t *Data;
    void *Iterator;
};

static BIDError
_BIDFileCacheAcquire(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context,
    void **cache,
    const char *name)
{
    BIDError err;
    struct BIDFileCache *fc;

    fc = BIDCalloc(1, sizeof(*fc));
    if (fc == NULL)
        return BID_S_NO_MEMORY;

    err = _BIDDuplicateString(context, name, &fc->Name);
    if (err != BID_S_OK) {
        BIDFree(fc);
        return err;
    }

    *cache = fc;

    return BID_S_OK;
}

static BIDError
_BIDFileCacheRelease(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;

    if (fc == NULL)
        return BID_S_INVALID_PARAMETER;

    BIDFree(fc->Name);
    json_decref(fc->Data);
    BIDFree(fc);

    return BID_S_OK;
}

static BIDError
_BIDFileCacheLock(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache BID_UNUSED,
    int fd,
    int exclusive)
{
    int ret;
    BIDError err;
#ifdef HAVE_FCNTL_H
    struct flock l;

    l.l_start = 0;
    l.l_len = 0;
    l.l_type = exclusive ? F_WRLCK : F_RDLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, exclusive ? LOCK_EX : LOCK_SH);
#endif
    if (ret < 0)
        ret = errno;
    if (ret == EACCES) /* fcntl can return EACCES instead of EAGAIN */
        ret = EAGAIN;

    switch (ret) {
    case 0:
        err = BID_S_OK;
        break;
    case EAGAIN:
        err = BID_S_CACHE_LOCK_TIMEOUT;
        break;
    default:
        err = BID_S_CACHE_LOCK_ERROR;
        break;
    }

    return err;
}

static BIDError
_BIDFileCacheUnlock(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache BID_UNUSED,
    int fd)
{
    int ret;

#ifdef HAVE_FCNTL_H
    struct flock l;
    l.l_start = 0;
    l.l_len = 0;
    l.l_type = F_UNLCK;
    l.l_whence = SEEK_SET;
    ret = fcntl(fd, F_SETLKW, &l);
#else
    ret = flock(fd, LOCK_UN);
#endif
    if (ret < 0)
        ret = errno;

    return (ret == 0) ? BID_S_OK : BID_S_CACHE_UNLOCK_ERROR;
}

static BIDError
_BIDFileCacheOpen(
    struct BIDCacheOps *ops,
    BIDContext context,
    struct BIDFileCache *fc,
    int flags,
    mode_t mode,
    int *pFd)
{
    BIDError err;
    int exclusive = 0, fd;

    *pFd = -1;

    fd = open(fc->Name, flags, mode);
    if (fd < 0) {
        switch (errno) {
        case ENOENT:
            err = BID_S_CACHE_NOT_FOUND;
            break;
        case EPERM:
            err = BID_S_CACHE_PERMISSION_DENIED;
            break;
        case EEXIST:
            err = BID_S_CACHE_ALREADY_EXISTS;
            break;
        default:
            err = BID_S_CACHE_OPEN_ERROR;
            break;
        }
        return err;
    }

#ifdef HAVE_FCNTL_H
    if (flags & O_CLOEXEC) {
        int f = fcntl(fd, F_GETFD);
        if (f != -1)
            fcntl(fd, F_SETFD, f | FD_CLOEXEC);
    }
#endif

    if ((flags & O_WRONLY) || (flags & O_RDWR))
        exclusive = 1;

    err = _BIDFileCacheLock(ops, context, fc, fd, exclusive);
    if (err != BID_S_OK) {
        close(fd);
        return err;
    }

    *pFd = fd;

    return BID_S_OK;
}

static BIDError
_BIDFileCacheClose(
    struct BIDCacheOps *ops,
    BIDContext context,
    struct BIDFileCache *fc,
    int fd)
{
    BIDError err = BID_S_OK;

    if (fc != NULL && fd != -1) {
        err = _BIDFileCacheUnlock(ops, context, fc, fd);
        if (close(fd) < 0)
            err = BID_S_CACHE_CLOSE_ERROR;
    }

    return err;
}

static BIDError
_BIDFileCacheScrub(int fd)
{
    off_t pos;
    char buf[128];

    pos = lseek(fd, 0, SEEK_END);
    if (pos < 0)
        return BID_S_CACHE_DESTROY_ERROR;
    if (lseek(fd, 0, SEEK_SET) < 0)
        return BID_S_CACHE_DESTROY_ERROR;
    memset(buf, 0, sizeof(buf));
    while (pos > 0) {
        size_t n = pos > sizeof(buf) ? sizeof(buf) : pos;
        ssize_t tmp = write(fd, buf, n);
        if (tmp < 0)
            return BID_S_CACHE_DESTROY_ERROR;
        pos -= tmp;
    }
#ifdef _MSC_VER
    _commit (fd);
#else
    fsync (fd);
#endif
    return BID_S_OK;
}

static BIDError
_BIDFileCacheErase(
    struct BIDCacheOps *ops,
    BIDContext context,
    struct BIDFileCache *fc)
{
    BIDError err, err2;
    struct stat sb1, sb2;
    int fd = -1;

    if (lstat(fc->Name, &sb1))
        return BID_S_CACHE_DESTROY_ERROR;

    err = _BIDFileCacheOpen(ops, context, fc, O_RDWR, 0, &fd);
    if (err != BID_S_OK)
        return err;

    if (unlink(fc->Name) < 0) {
        err = BID_S_CACHE_DESTROY_ERROR;
        goto cleanup;
    }

    if (fstat(fd, &sb2) < 0) {
        err = BID_S_CACHE_DESTROY_ERROR;
        goto cleanup;
    }

    /* check if someone was playing with symlinks */
    if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino) {
        err = BID_S_CACHE_PERMISSION_DENIED;
        goto cleanup;
    }

    /* only scrub if there are no hardlinks */
    if (sb2.st_nlink == 0) {
        err = _BIDFileCacheScrub(fd);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    err2 = _BIDFileCacheClose(ops, context, fc, fd);
    return (err == BID_S_OK) ? err2 : err;
}

static BIDError
_BIDFileCacheStore(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    struct BIDFileCache *fc BID_UNUSED,
    int fd,
    json_t *data)
{
    char *szJson;
    size_t cchJson;
    ssize_t cbWritten;

    szJson = json_dumps(data, JSON_COMPACT);
    if (szJson == NULL)
        return BID_S_CANNOT_ENCODE_JSON;

    cchJson = strlen(szJson);

    cbWritten = write(fd, szJson, cchJson);
    if (cbWritten == cchJson)
        cbWritten += write(fd, "\n", 1);

    BIDFree(szJson);

    return (cbWritten != cchJson + 1) ? BID_S_CACHE_WRITE_ERROR : BID_S_OK;
}

static BIDError
_BIDFileCacheLoad(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context,
    struct BIDFileCache *fc BID_UNUSED,
    int fd,
    json_t **pData)
{
    FILE *fp;
    json_t *data;
    int fd2; /* lazy */

    fd2 = fcntl(fd, F_DUPFD, 0);
    if (fd2 < 0)
        return BID_S_CACHE_READ_ERROR;
   
    fp = fdopen(fd2, "r");
    if (fp == NULL) {
        close(fd2);
        return BID_S_CACHE_READ_ERROR;
    }

    data = json_loadf(fp, 0, &context->JsonError);

    *pData = data;

    fclose(fp);
    return (data == NULL) ? BID_S_CACHE_READ_ERROR : BID_S_OK;
}

static BIDError
_BIDFileCacheNew(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context,
    struct BIDFileCache *fc BID_UNUSED,
    json_t **pData)
{
    BIDError err;
    json_t *data = NULL;

    data = json_object();
    if (data == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, data, "v", json_string("2013.01.01"), BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, data, "d", json_object(), BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pData = data;

cleanup:
    if (err != BID_S_OK)
        json_decref(data);

    return err;
}

static BIDError
_BIDFileCacheInitialize(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache)
{
    BIDError err, err2;
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    json_t *data = NULL;
    int fd = -1;
    int flags = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC;

    if (fc == NULL)
        return BID_S_INVALID_PARAMETER;

    err = _BIDFileCacheNew(ops, context, fc, &data);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheOpen(ops, context, fc, flags, 0600, &fd);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheStore(ops, context, fc, fd, data);
    BID_BAIL_ON_ERROR(err);

cleanup:
    err2 = _BIDFileCacheClose(ops, context, fc, fd);

    json_decref(data);

    return (err == BID_S_OK) ? err2 : err;
}

static BIDError
_BIDFileCacheRead(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    int fd,
    json_t **pData)
{
    BIDError err;
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    const char *version;

    *pData = NULL;

    err = _BIDFileCacheLoad(ops, context, fc, fd, pData);
    BID_BAIL_ON_ERROR(err);

    version = json_string_value(json_object_get(*pData, "v"));
    if (version == NULL || strcmp(version, "2013.01.01") != 0) {
        err = BID_S_CACHE_INVALID_VERSION;
        goto cleanup;
    }

    if (!json_is_object(json_object_get(*pData, "d"))) {
        err = BID_S_CACHE_READ_ERROR;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK) {
        json_decref(*pData);
        *pData = NULL;
    }

    return err; 
}

static BIDError
_BIDFileCacheWrite(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    json_t *d)
{
    BIDError err;
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    int fd = -1;
    char *szTmpName = NULL;
    size_t cchFileName;

    cchFileName = strlen(fc->Name);
    szTmpName = BIDMalloc(cchFileName + sizeof(".XXXXXX"));
    if (szTmpName == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    memcpy(szTmpName, fc->Name, cchFileName);
    memcpy(&szTmpName[cchFileName], ".XXXXXX", sizeof(".XXXXXX"));

    fd = mkstemp(szTmpName);
    if (fd < 0) {
        err = BID_S_CACHE_WRITE_ERROR;
        goto cleanup;
    }

    err = _BIDFileCacheStore(ops, context, fc, fd, d);
    BID_BAIL_ON_ERROR(err);

    close(fd);
    fd = -1;

    if (rename(szTmpName, fc->Name) < 0) {
        err = BID_S_CACHE_WRITE_ERROR;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    if (fd != -1) {
        if (close(fd) < 0)
            err = BID_S_CACHE_CLOSE_ERROR;
    }
    BIDFree(szTmpName);

    return err; 
}

static BIDError
_BIDFileCacheDestroy(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;

    if (fc == NULL)
        return BID_S_INVALID_PARAMETER;

    return _BIDFileCacheErase(ops, context, fc);
}

static BIDError
_BIDFileCacheGetName(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char **name)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;

    if (fc == NULL)
        return BID_S_INVALID_PARAMETER;

    *name = fc->Name;
    BID_ASSERT(*name != NULL);

    return BID_S_OK;
}

static BIDError
_BIDFileCacheGetLastChangedTime(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    time_t *pTime)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    BIDError err;
    int fd;
    struct stat sb;

    *pTime = 0;

    if (fc == NULL)
        return BID_S_INVALID_PARAMETER;

    err = _BIDFileCacheOpen(ops, context, fc, O_RDONLY | O_CLOEXEC, 0, &fd);
    if (err != BID_S_OK)
        return err;

    if (fstat(fd, &sb) == 0)
        *pTime = sb.st_mtime;
    else
        return BID_S_CACHE_OPEN_ERROR;

    _BIDFileCacheClose(ops, context, fc, fd);

    return BID_S_OK;
}

static BIDError
_BIDFileCacheGetObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key,
    json_t **val)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    BIDError err;
    json_t *data = NULL;
    json_t *d;
    int fd = -1;

    *val = NULL;

    if (fc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDFileCacheOpen(ops, context, fc, O_RDONLY | O_CLOEXEC, 0600, &fd);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheRead(ops, context, cache, fd, &data);
    BID_BAIL_ON_ERROR(err);

    d = json_object_get(data, "d");

    *val = json_incref(json_object_get(d, key));

    if (*val == NULL)
        err = BID_S_CACHE_KEY_NOT_FOUND;
    else
        err = BID_S_OK;

cleanup:
    _BIDFileCacheClose(ops, context, fc, fd);
    json_decref(data);

    return err;
}

static BIDError
_BIDFileCacheSetOrRemoveObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key,
    json_t *val,
    int remove)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    BIDError err;
    json_t *data = NULL, *d;
    int fd = -1;

    if (fc == NULL || (val == NULL && !remove)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDFileCacheOpen(ops, context, fc, O_RDWR | O_CREAT | O_CLOEXEC, 0600, &fd);
    if (err == BID_S_OK)
        err = _BIDFileCacheRead(ops, context, cache, fd, &data);
    if (err == BID_S_CACHE_NOT_FOUND || err == BID_S_CACHE_READ_ERROR)
        err = _BIDFileCacheNew(ops, context, fc, &data);
    BID_BAIL_ON_ERROR(err);

    d = json_object_get(data, "d");
    BID_ASSERT(d != NULL);

    if (remove)
        err = _BIDJsonObjectDel(context, d, key, 0);
    else
        err = _BIDJsonObjectSet(context, d, key, val, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheWrite(ops, context, cache, data);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    _BIDFileCacheClose(ops, context, fc, fd);
    json_decref(data);

    return err;
}

static BIDError
_BIDFileCacheSetObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key,
    json_t *val)
{
    return _BIDFileCacheSetOrRemoveObject(ops, context, cache, key, val, 0);
}

static BIDError
_BIDFileCacheRemoveObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char *key)
{
    return _BIDFileCacheSetOrRemoveObject(ops, context, cache, key, NULL, 1);
}

static BIDError
_BIDFileCacheFirstObject(
    struct BIDCacheOps *ops,
    BIDContext context,
    void *cache,
    const char **key,
    json_t **val)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    BIDError err;
    json_t *data = NULL, *d = NULL;
    int fd = -1;

    *key = NULL;
    *val = NULL;

    if (fc == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDFileCacheOpen(ops, context, fc, O_RDWR | O_CLOEXEC, 0600, &fd);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheRead(ops, context, cache, fd, &data);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFileCacheClose(ops, context, fc, fd);
    BID_BAIL_ON_ERROR(err);

    fd = -1;

    d = json_object_get(data, "d");

    fc->Iterator = json_object_iter(d);
    if (fc->Iterator == NULL) {
        err = BID_S_CACHE_KEY_NOT_FOUND;
        goto cleanup;
    }

    *key = json_object_iter_key(fc->Iterator);
    *val = json_incref(json_object_iter_value(fc->Iterator));
    if (*key == NULL || *val == NULL) {
        err = BID_S_NO_MORE_ITEMS;
        goto cleanup;
    }

    json_decref(fc->Data);
    fc->Data = json_incref(d);

    err = BID_S_OK;

cleanup:
    if (fd != -1)
        _BIDFileCacheClose(ops, context, fc, fd);

    json_decref(data);

    return err;
}

static BIDError
_BIDFileCacheNextObject(
    struct BIDCacheOps *ops BID_UNUSED,
    BIDContext context BID_UNUSED,
    void *cache,
    const char **key,
    json_t **val)
{
    struct BIDFileCache *fc = (struct BIDFileCache *)cache;
    BIDError err;

    *key = NULL;
    *val = NULL;

    if (fc == NULL || fc->Data == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    fc->Iterator = json_object_iter_next(fc->Data, fc->Iterator);
    if (fc->Iterator == NULL) {
        err = BID_S_NO_MORE_ITEMS;
        goto cleanup;
    }

    *key = json_object_iter_key(fc->Iterator);
    *val = json_incref(json_object_iter_value(fc->Iterator));
    if (*key == NULL || *val == NULL) {
        err = BID_S_NO_MORE_ITEMS;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK) {
        json_decref(fc->Data);
        fc->Data = NULL;
    }

    return err;
}

struct BIDCacheOps _BIDFileCache = {
    "file",
    _BIDFileCacheAcquire,
    _BIDFileCacheRelease,
    _BIDFileCacheInitialize,
    _BIDFileCacheDestroy,
    _BIDFileCacheGetName,
    _BIDFileCacheGetLastChangedTime,
    _BIDFileCacheGetObject,
    _BIDFileCacheSetObject,
    _BIDFileCacheRemoveObject,
    _BIDFileCacheFirstObject,
    _BIDFileCacheNextObject,
};

