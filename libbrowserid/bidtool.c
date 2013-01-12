/*
 * Copyright (C) 1813 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include "browserid.h"
#include "bid_private.h"

static BIDContext gContext = NULL;
static time_t gNow = 0;
static int gVerbose = 0;

static void
BIDToolUsage(void);
static void
BIDAbortError(const char *szMessage, BIDError err);
static BIDError
BIDPurgeCache(int argc, char *argv[], BIDCache cache, int (*shouldPurgeP)(json_t *));

static BIDError
BIDPrintVerboseTicketCacheEntry(const char *k, json_t *j)
{
    unsigned char *pbArk = NULL;
    size_t cbArk = 0;
    time_t issueTime, expiryTime;
    uint32_t ulTicketFlags = json_integer_value(json_object_get(j, "flags"));

    _BIDGetJsonTimestampValue(gContext, j, "iat", &issueTime);
    _BIDGetJsonTimestampValue(gContext, j, "exp", &expiryTime);
    _BIDGetJsonBinaryValue(gContext, json_object_get(j, "ark"), "secret-key", &pbArk, &cbArk);

    printf("Audience:         %s\n", k);
    printf("Subject:          %s\n", json_string_value(json_object_get(j, "sub")));
    printf("Issuer:           %s\n", json_string_value(json_object_get(j, "iss")));
    printf("Key length:       %zd bits\n", cbArk * 8);
    printf("Cert issue time:  %s", ctime(&issueTime));
    printf("Ticket expiry:    %s", ctime(&expiryTime));
    printf("Ticket flags:     ");
    if (ulTicketFlags & BID_TICKET_FLAG_MUTUAL_AUTH)
        printf("MUTUAL");
    if (ulTicketFlags == 0)
        printf("NONE");
    printf("\n\n");

    if (pbArk != NULL) {
        memset(pbArk, 0, cbArk);
        BIDFree(pbArk);
    }

    return BID_S_OK;
}

static BIDError
BIDPrintTicketCacheEntry(const char *k, json_t *j)
{
    const char *szExpiry;
    time_t expiryTime;
    json_t *tkt = json_object_get(j, "tkt");
    const char *aud = json_string_value(json_object_get(j, "aud"));

    if (aud != NULL &&
        strncmp(aud, BID_GSS_AUDIENCE_PREFIX, BID_GSS_AUDIENCE_PREFIX_LEN) == 0)
        aud += BID_GSS_AUDIENCE_PREFIX_LEN;

    _BIDGetJsonTimestampValue(gContext, tkt, "exp", &expiryTime);

    szExpiry = gNow < expiryTime ? ctime(&expiryTime) : ">>> Expired <<<";

    printf("%-15.15s %-25.25s %-13.13s %-24.24s\n",
           json_string_value(json_object_get(j, "sub")),
           aud,
           json_string_value(json_object_get(j, "iss")),
           szExpiry);

    return BID_S_OK;
}

static int
BIDShouldPurgeTicketCacheEntryP(json_t *j)
{
    time_t expiryTime;
    json_t *tkt = json_object_get(j, "tkt");

    _BIDGetJsonTimestampValue(gContext, tkt, "exp", &expiryTime);

    return expiryTime == 0 || gNow >= expiryTime;
}

static BIDError
BIDPurgeTicketCache(int argc, char *argv[])
{
    return BIDPurgeCache(argc, argv, gContext->TicketCache, BIDShouldPurgeTicketCacheEntryP);
}

static BIDError
BIDListTicketCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    BIDError err;
    const char *k = NULL;
    const char *szCacheName = NULL;
    json_t *j = NULL;
    int i;

    if (argc)
        BIDToolUsage();

    if (gContext->TicketCache == NULL)
        return BID_S_INVALID_PARAMETER;

    err = _BIDGetCacheName(gContext, gContext->TicketCache, &szCacheName);
    if (err != BID_S_OK)
        return err;

    printf("Ticket cache: %s\n\n", szCacheName);

    if (!gVerbose) {
        printf("%-15.15s %-25.25s %-13.13s %-24.24s\n",
               "Identity", "Audience", "Issuer", "Expires");
        for (i = 0; i < 80; i++)
            printf("-");
        printf("\n");
    };

    for (err = _BIDGetFirstCacheObject(gContext, gContext->TicketCache, &k, &j);
         err == BID_S_OK;
         err = _BIDGetNextCacheObject(gContext, gContext->TicketCache, &k, &j)) {
        gVerbose ? BIDPrintVerboseTicketCacheEntry(k, j) : BIDPrintTicketCacheEntry(k, j);
        json_decref(j);
        j = NULL;
    }

    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;

    json_decref(j);
    return err;
}

static BIDError
BIDDestroyTicketCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    if (argc)
        BIDToolUsage();

    if (gContext->TicketCache == NULL)
        return BID_S_INVALID_PARAMETER;

    return _BIDDestroyCache(gContext, gContext->TicketCache);
}

static BIDError
BIDPrintVerboseReplayCacheEntry(const char *k, json_t *j)
{
    unsigned char *pbHash = NULL;
    size_t cbHash = 0, i;
    unsigned char *pbArk = NULL;
    size_t cbArk = 0;
    time_t issueTime, expiryTime, assertionExpiryTime;

    _BIDBase64UrlDecode(k, &pbHash, &cbHash);
    _BIDGetJsonBinaryValue(gContext, json_object_get(j, "ark"), "secret-key", &pbArk, &cbArk);
    _BIDGetJsonTimestampValue(gContext, j, "iat", &issueTime);
    _BIDGetJsonTimestampValue(gContext, j, "exp", &expiryTime);
    _BIDGetJsonTimestampValue(gContext, j, "a-exp", &assertionExpiryTime);

    printf("Ticket ID:        ");
    for (i = 0; i < cbHash; i++)
        printf("%02X", pbHash[i] & 0xff);
    printf("\n");

    if (pbArk != NULL) {
        printf("Audience:         %s\n", json_string_value(json_object_get(j, "aud")));
        printf("Subject:          %s\n", json_string_value(json_object_get(j, "sub")));
        printf("Issuer:           %s\n", json_string_value(json_object_get(j, "iss")));
        printf("Key length:       %zd bits\n", cbArk * 8);
    }

    printf("Cert issue time:  %s", ctime(&issueTime));
    printf("Assertion expiry: %s", ctime(&assertionExpiryTime));
    printf("Ticket expiry:    %s", ctime(&expiryTime));
    printf("\n");

    if (pbArk != NULL) {
        memset(pbArk, 0, cbArk);
        BIDFree(pbArk);
    }
    BIDFree(pbHash);

    return BID_S_OK;
}

static BIDError
BIDPrintReplayCacheEntry(const char *k, json_t *j)
{
    BIDError err;
    unsigned char *hash = NULL;
    size_t cbHash, i;
    time_t exp, ts;

    err = _BIDBase64UrlDecode(k, &hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    _BIDGetJsonTimestampValue(gContext, j, "iat", &ts);
    _BIDGetJsonTimestampValue(gContext, j, "exp", &exp);

    printf("%-24.24s  ", ctime(&ts));

    for (i = 0; i < cbHash; i++)
        printf("%02X", hash[i] & 0xff);

    printf("\n");

cleanup:
    BIDFree(hash);

    return err;
}

static int
BIDShouldPurgeReplayCacheEntryP(json_t *j)
{
    time_t expiryTime;

    /*
     * If the cache entry is being used for re-authentication (it has a key)
     * then purge only when the ticket expires. Otherwise, purge when the
     * assertion expires.
     */
    if (json_object_get(j, "ark") != NULL)
        _BIDGetJsonTimestampValue(gContext, j, "exp", &expiryTime);
    else
        _BIDGetJsonTimestampValue(gContext, j, "a-exp", &expiryTime);

    return expiryTime == 0 || gNow >= expiryTime;
}

static BIDError
BIDListReplayCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    BIDError err;
    const char *k = NULL;
    const char *szCacheName = NULL;
    json_t *j = NULL;
    int i;

    if (argc)
        BIDToolUsage();

    if (gContext->ReplayCache == NULL)
        return BID_S_INVALID_PARAMETER;

    err = _BIDGetCacheName(gContext, gContext->ReplayCache, &szCacheName);
    if (err != BID_S_OK)
        return err;

    printf("Replay cache:     %s\n\n", szCacheName);

    if (!gVerbose) {
        printf("%-24.24s  %s\n", "Timestamp", "Ticket ID");
        for (i = 0; i < 90; i++)
            printf("-");
        printf("\n");
    }

    for (err = _BIDGetFirstCacheObject(gContext, gContext->ReplayCache, &k, &j);
         err == BID_S_OK;
         err = _BIDGetNextCacheObject(gContext, gContext->ReplayCache, &k, &j)) {
        gVerbose ? BIDPrintVerboseReplayCacheEntry(k, j) : BIDPrintReplayCacheEntry(k, j);
        json_decref(j);
        j = NULL;
    }

    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;

    json_decref(j);
    return err;
}

static BIDError
BIDPurgeCache(
    int argc BID_UNUSED,
    char *argv[] BID_UNUSED,
    BIDCache cache,
    int (*shouldPurgeP)(json_t *))
{
    BIDError err;
    const char *k = NULL;
    json_t *j = NULL;

    if (argc)
        BIDToolUsage();

    if (cache == NULL)
        return BID_S_INVALID_PARAMETER;

    for (err = _BIDGetFirstCacheObject(gContext, cache, &k, &j);
         err == BID_S_OK;
         err = _BIDGetNextCacheObject(gContext, cache, &k, &j)) {
        if (shouldPurgeP(j))
            _BIDRemoveCacheObject(gContext, cache, k);
    }

    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;

    json_decref(j);
    return err;
}

static BIDError
BIDPurgeReplayCache(int argc, char *argv[])
{
    return BIDPurgeCache(argc, argv, gContext->ReplayCache, BIDShouldPurgeReplayCacheEntryP);
}

static BIDError
BIDDestroyReplayCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    if (argc)
        BIDToolUsage();

    if (gContext->ReplayCache == NULL)
        return BID_S_INVALID_PARAMETER;

    return _BIDDestroyCache(gContext, gContext->ReplayCache);
}

static int
BIDShouldPurgeAuthorityP(json_t *j)
{
    time_t expiryTime;

    _BIDGetJsonTimestampValue(gContext, j, "exp", &expiryTime);

    return expiryTime == 0 || gNow >= expiryTime;
}

static BIDError
BIDPrintAuthorityCacheEntry(const char *k, json_t *j)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    BIDIdentity identity = NULL;
    BIDJWK publicKey = NULL;
    const char *szAlgorithm;
    time_t expiryTime;
    const char *szExpiry;

    _BIDGetJsonTimestampValue(gContext, j, "exp", &expiryTime);

    err = _BIDGetAuthorityPublicKey(gContext, j, &publicKey);
    if (err == BID_S_OK) {
        json_t *p = json_object_get(publicKey, "public-key");

        szAlgorithm = json_string_value(json_object_get(p, "algorithm"));
        if (szAlgorithm == NULL)
            szAlgorithm = json_string_value(json_object_get(p, "alg"));

        if (strcmp(szAlgorithm, "RS") == 0)
            szAlgorithm = "RSA";
        else if (strcmp(szAlgorithm, "DS") == 0)
            szAlgorithm = "DSA";

        json_decref(publicKey);
    }

    if (szAlgorithm == NULL)
        szAlgorithm = "UNK";

    szExpiry = gNow < expiryTime ? ctime(&expiryTime) : ">>> Expired <<<";

    printf("%-30.30s %-4.4s %-20.20s\n",
           k, szAlgorithm, szExpiry);

    _BIDReleaseBackedAssertion(gContext, backedAssertion);
    BIDReleaseIdentity(gContext, identity);

    return err;
}

static BIDError
BIDListAuthorityCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    BIDError err;
    const char *k = NULL;
    json_t *j = NULL;
    int i;

    if (argc)
        BIDToolUsage();

    if (gContext->AuthorityCache == NULL)
        return BID_S_INVALID_PARAMETER;

    printf("%-30.30s %-4.4s %-20.20s\n", "Issuer", "ALG", "Expires");
    for (i = 0; i < 60; i++)
        printf("-");
    printf("\n");

    for (err = _BIDGetFirstCacheObject(gContext, gContext->AuthorityCache, &k, &j);
         err == BID_S_OK;
         err = _BIDGetNextCacheObject(gContext, gContext->AuthorityCache, &k, &j)) {
        BIDPrintAuthorityCacheEntry(k, j);
        json_decref(j);
        j = NULL;
    }

    if (err == BID_S_NO_MORE_ITEMS)
        err = BID_S_OK;

    json_decref(j);
    return err;
}

static BIDError
BIDPurgeAuthorityCache(int argc, char *argv[])
{
    return BIDPurgeCache(argc, argv, gContext->AuthorityCache, BIDShouldPurgeAuthorityP);
}

static BIDError
BIDDestroyAuthorityCache(int argc BID_UNUSED, char *argv[] BID_UNUSED)
{
    if (argc)
        BIDToolUsage();

    if (gContext->AuthorityCache == NULL)
        return BID_S_INVALID_PARAMETER;

    return _BIDDestroyCache(gContext, gContext->AuthorityCache);
}

static BIDError
BIDVerifyAssertionFromString(int argc, char *argv[])
{
    BIDError err;
    BIDIdentity identity = NULL;
    time_t expiryTime;
    const char *szExpiryTime;
    uint32_t ulFlags = 0;

    if (argc != 2)
        BIDToolUsage();

    err = BIDVerifyAssertion(gContext, BID_C_NO_REPLAY_CACHE,
                             argv[0], argv[1], NULL, 0, 0,
                             gNow, &identity, &expiryTime, &ulFlags);
    if (err != BID_S_OK) {
        BIDAbortError("Failed to verify assertion", err);
        goto cleanup;
    }

    szExpiryTime = expiryTime < gNow ? ctime(&expiryTime) : ">>> Expired <<<";

    printf("Verified assertion for %s issued by %s (expiry %s)\n",
           json_string_value(json_object_get(identity->Attributes, "sub")),
           json_string_value(json_object_get(identity->Attributes, "iss")),
           szExpiryTime);

cleanup:
    BIDReleaseIdentity(gContext, identity);

    return err;
}

static struct {
    const char *Argument;
    const char *Usage;
    BIDError (*Handler)(int argc, char *argv[]);
    enum { NO_CACHE, TICKET_CACHE, REPLAY_CACHE, AUTHORITY_CACHE } CacheUsage;
} _BIDToolHandlers[] = {
    { "tlist",        "", BIDListTicketCache,             TICKET_CACHE         },
    { "tpurge",       "", BIDPurgeTicketCache,            TICKET_CACHE         },
    { "tdestroy",     "", BIDDestroyTicketCache,          TICKET_CACHE         },

    { "rlist",        "", BIDListReplayCache,             REPLAY_CACHE         },
    { "rpurge",       "", BIDPurgeReplayCache,            REPLAY_CACHE         },
    { "rdestroy",     "", BIDDestroyReplayCache,          REPLAY_CACHE         },

    { "certlist",     "", BIDListAuthorityCache,          AUTHORITY_CACHE      },
    { "certpurge",    "", BIDPurgeAuthorityCache,         AUTHORITY_CACHE      },
    { "certdestroy",  "", BIDDestroyAuthorityCache,       AUTHORITY_CACHE      },

    { "verify",       "assertion audience", BIDVerifyAssertionFromString, REPLAY_CACHE },

};

static void
BIDAbortError(const char *szMessage, BIDError err)
{
    const char *szErrString = NULL;

    if (BIDErrorToString(err, &szErrString) != BID_S_OK)
        szErrString = "Unknown error";

    fprintf(stderr, "bidtool: %s: %s\n", szMessage, szErrString);
    BIDReleaseContext(gContext);
    exit(err);
}

static void
BIDToolUsage(void)
{
    int first = 1;
    int i;

    fprintf(stderr, "Usage: bidtool ");

    for (i = 0; i < sizeof(_BIDToolHandlers) / sizeof(_BIDToolHandlers[0]); i++) {
        if (first) {
            first = 0;
        } else {
            fprintf(stderr, "               ");
        }
        fprintf(stderr, "%-20.20s ", _BIDToolHandlers[i].Argument);
        if (_BIDToolHandlers[i].CacheUsage)
            fprintf(stderr, "[-cache name] ");
        fprintf(stderr, "[-verbose] %s\n", _BIDToolHandlers[i].Usage);
    }
    exit(BID_S_INVALID_PARAMETER);
}

int main(int argc, char *argv[])
{
    BIDError err;
    uint32_t ulOptions;
    int i;
    uint32_t ulCacheOpt;
    char *szCacheName = NULL;

    ulOptions = BID_CONTEXT_RP              |
                BID_CONTEXT_USER_AGENT      |
                BID_CONTEXT_GSS             |
                BID_CONTEXT_REPLAY_CACHE    |
                BID_CONTEXT_REAUTH          |
                BID_CONTEXT_AUTHORITY_CACHE;

    err = BIDAcquireContext(ulOptions, &gContext);
    if (err != BID_S_OK)
        BIDAbortError("Failed to acquire context", err);

    if (argc < 2)
        BIDToolUsage();

    argc--;
    argv++;

    gNow = time(NULL);

    err = BID_S_INVALID_PARAMETER;

    for (i = 0; i < sizeof(_BIDToolHandlers) / sizeof(_BIDToolHandlers[0]); i++) {
        if (strcmp(argv[0], _BIDToolHandlers[i].Argument) == 0) {
            switch (_BIDToolHandlers[i].CacheUsage) {
            case TICKET_CACHE:
                ulCacheOpt = BID_PARAM_TICKET_CACHE_NAME;
                break;
            case REPLAY_CACHE:
                ulCacheOpt = BID_PARAM_REPLAY_CACHE_NAME;
                break;
            case AUTHORITY_CACHE:
                ulCacheOpt = BID_PARAM_AUTHORITY_CACHE_NAME;
                break;
            default:
                ulCacheOpt = 0;
                break;
            }
            err = BID_S_OK;
            argc--;
            argv++;
            break;
        }
    }

    if (err == BID_S_INVALID_PARAMETER)
        BIDToolUsage();

    if (argc > 1 && strcmp(argv[0], "-cache") == 0) {
        szCacheName = argv[1];
        argc -= 2;
        argv += 2;
    }

    if (argc > 0 &&
        (strcmp(argv[0], "-verbose") == 0 || strcmp(argv[0], "-v") == 0)) {
        gVerbose = 1;
        argc--;
        argv++;
    }

    if (szCacheName != NULL && ulCacheOpt != 0) {
        err = BIDSetContextParam(gContext, ulCacheOpt, szCacheName);
        if (err != BID_S_OK)
            BIDAbortError("Failed to acquire cache", err);
    }

    err = _BIDToolHandlers[i].Handler(argc, argv);

    BIDReleaseContext(gContext);

    exit(0);
}
