/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#ifdef __APPLE__
#include <pwd.h>
#include <sys/stat.h>
#endif

BIDError
_BIDAcquireDefaultAssertionCache(BIDContext context)
{
    BIDError err;
    char szFileName[PATH_MAX];

#ifdef __APPLE__
    struct passwd *pw, pwd;
    char pwbuf[BUFSIZ];
    struct stat sb;

    if (getpwuid_r(geteuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) < 0 ||
        pw == NULL ||
        pw->pw_dir == NULL) {
        err = BID_S_CACHE_OPEN_ERROR;
        goto cleanup;
    }

    snprintf(szFileName, sizeof(szFileName), "%s/Library/Caches/com.padl.gss.BrowserID", pw->pw_dir);

    if (stat(szFileName, &sb) < 0)
        mkdir(szFileName, 0700);

    snprintf(szFileName, sizeof(szFileName), "%s/Library/Caches/com.padl.gss.BrowserID/browserid.assertion.json", pw->pw_dir);
#else
    snprintf(szFileName, sizeof(szFileName), "/tmp/.browserid.assertion.%d.json", geteuid());
#endif

    err = _BIDAcquireCache(context, szFileName, &context->AssertionCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDGetCachedAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    char **pAssertion)
{
    BIDError err;
    char *szPackedAudience = NULL;
    json_t *assertion = NULL;
    time_t expires;

    *pAssertion = NULL;

    err = _BIDPackAudience(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCacheObject(context, context->AssertionCache, szPackedAudience, &assertion);
    BID_BAIL_ON_ERROR(err);

    err = BIDAcquireAssertionFromString(context, json_string_value(assertion), NULL, &expires);
    if (err == BID_S_OK && expires < time(NULL))
        err = BID_S_EXPIRED_ASSERTION;
    BID_BAIL_ON_ERROR(err);

    err = _BIDDuplicateString(context, json_string_value(assertion), pAssertion);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szPackedAudience);
    json_decref(assertion);

    return err;
}

BIDError
_BIDCacheAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szAssertion)
{
    BIDError err;
    char *szPackedAudience = NULL;
    json_t *assertion = NULL;

    err = _BIDPackAudience(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, &szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    assertion = json_string(szAssertion);
    if (assertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDSetCacheObject(context, context->AssertionCache, szPackedAudience, assertion);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szPackedAudience);
    json_decref(assertion);

    return err;
}
