/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#ifndef _BID_PRIVATE_H_
#define _BID_PRIVATE_H_ 1

#include "config.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <jansson.h>
#include <curl/curl.h>
#include <curl/easy.h>

#include "browserid.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BIDContextDesc {
    uint32_t ContextOptions;
    json_error_t JsonError;
    char *VerifierUrl;
    json_t *AuthorityCache;
    uint32_t MaxDelegations;
    uint32_t Skew;
};

#define BIDCalloc                   calloc
#define BIDMalloc                   malloc
#define BIDFree                     free
#define BIDRealloc                  realloc

#define BID_ASSERT                  assert

#if !defined(WIN32) && !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#define BID_UNUSED __attribute__ ((__unused__))
#else
#define BID_UNUSED
#endif

#define BID_CONTEXT_VALIDATE(context)   do {        \
        BID_ASSERT((context) != BID_C_NO_CONTEXT);  \
        if ((context) == BID_C_NO_CONTEXT)          \
            return BID_S_NO_CONTEXT;                \
    } while (0)

#define BID_BAIL_ON_ERROR(status)       do {        \
        if ((status) != BID_S_OK)                   \
            goto cleanup;                           \
    } while (0)

/*
 * bid_authority.c
 */
#define BID_WELL_KNOWN_URL          "/.well-known/browserid"
#define BID_WELL_KNOWN_URL_LEN      (sizeof(BID_WELL_KNOWN_URL) - 1)

#define BROKEN_URL_PARSER 1

/* XXX better would be urn:x-gss-browserid: but it causes problems with WebKit/BrowserID */
#ifdef BROKEN_URL_PARSER
#define BID_GSS_AUDIENCE_PREFIX     "gss://"
#else
#define BID_GSS_AUDIENCE_PREFIX     "gss:"
#endif
#define BID_GSS_AUDIENCE_PREFIX_LEN (sizeof(BID_GSS_AUDIENCE_PREFIX) - 1)

typedef json_t *BIDAuthority;
typedef json_t *BIDJWK;
typedef json_t *BIDJWKSet;

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *hostname,
    BIDAuthority *pAuthority);

BIDError
_BIDReleaseAuthority(
    BIDContext context,
    BIDAuthority authority);

BIDError
_BIDGetAuthorityPublicKey(
    BIDContext context,
    BIDAuthority authority,
    BIDJWKSet *pKey);

BIDError
_BIDIssuerIsAuthoritative(
    BIDContext context,
    const char *szHostname,
    const char *szIssuer);
//    BIDAuthority authority);

/*
 * bid_base64.c
 */
BIDError
_BIDBase64UrlEncode(const unsigned char *data, size_t size, char **str, size_t *cchStr);

BIDError
_BIDBase64UrlDecode(const char *str, unsigned char **pData, size_t *cbData);

/*
 * bid_cache.c
 */
struct BIDCacheDesc;
typedef struct BIDCacheDesc *BIDCache;

struct BIDCacheOps {
    const char *Scheme;

    BIDError (*Acquire)(struct BIDCacheOps *, BIDContext, void **, const char *);
    BIDError (*Release)(struct BIDCacheOps *, BIDContext, void *);

    BIDError (*Initialize)(struct BIDCacheOps *, BIDContext, void *, const char *version);
    BIDError (*Destroy)(struct BIDCacheOps *, BIDContext, void *);

    BIDError (*GetName)(struct BIDCacheOps *, BIDContext, void *, const char **);
    BIDError (*GetLastChangedTime)(struct BIDCacheOps *, BIDContext, void *, time_t *time);

    BIDError (*GetObject)(struct BIDCacheOps *, BIDContext, void *, const char *key, json_t **val);
    BIDError (*SetObject)(struct BIDCacheOps *, BIDContext, void *, const char *key, json_t *val);
    BIDError (*RemoveObject)(struct BIDCacheOps *, BIDContext, void *, const char *key);

    BIDError (*FirstObject)(struct BIDCacheOps *, BIDContext, void *, json_t **val);
    BIDError (*NextObject)(struct BIDCacheOps *, BIDContext, void *, json_t **val);
};

BIDError
_BIDAcquireCache(
    BIDContext context,
    const char *szCacheName,
    BIDCache *pCache);

BIDError
_BIDReleaseCache(
    BIDContext context,
    BIDCache cache);

BIDError
_BIDInitializeCache(
    BIDContext context,
    BIDCache cache);

BIDError
_BIDDestroyCache(
    BIDContext context,
    BIDCache cache);

BIDError
_BIDGetCacheName(
    BIDContext context,
    BIDCache cache,
    const char **pszName);

BIDError
_BIDGetCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key,
    json_t **pValue);

BIDError
_BIDSetCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key,
    json_t *value);

BIDError
_BIDRemoveCacheObject(
    BIDContext context,
    BIDCache cache,
    const char *key);

BIDError
_BIDGetCacheLastChangedTime(
    BIDContext context,
    BIDCache cache,
    time_t *ptLastChanged);

BIDError
_BIDCacheLock(
    BIDContext context,
    BIDCache cache);

BIDError
_BIDCacheUnlock(
    BIDContext context,
    BIDCache cache);

/*
 * bid_context.c
 */

/*
 * bid_fcache.c
 */

extern struct BIDCacheOps _BIDFileCache;

/*
 * bid_jwt.c
 */
typedef struct BIDJWTDesc {
    char *EncData;
    size_t EncDataLength;
    json_t *Header;
    json_t *Payload;
    unsigned char *Signature;
    size_t SignatureLength;
} *BIDJWT;

int
_BIDIsLegacyJWK(BIDContext context, BIDJWK jwt);

BIDError
_BIDMakeSignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset,
    char **pszJwt,
    size_t *pcchJwt);

BIDError
_BIDVerifySignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset);

BIDError
_BIDReleaseJWT(
    BIDContext context,
    BIDJWT jwt);

BIDError
_BIDParseJWT(
    BIDContext context,
    const char *szJwt,
    BIDJWT *pJwt);

/*
 * bid_local.c
 */

#define BID_MAX_CERTS               10

typedef struct BIDBackedAssertionDesc {
    BIDJWT Assertion;
    size_t cCertificates;
    BIDJWT rCertificates[BID_MAX_CERTS];
} *BIDBackedAssertion;

struct BIDIdentityDesc {
    json_t *Attributes;
};

BIDError
_BIDVerifyLocal(
    BIDContext context,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime);

/*
 * bid_remote.c
 */
BIDError
_BIDVerifyRemote(
    BIDContext context,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime);

/*
 * bid_util.c
 */
BIDError
_BIDGetJsonStringValue(
    BIDContext context,
    json_t *json,
    const char *key,
    char **pDst);

BIDError
_BIDGetJsonBinaryValue(
    BIDContext context,
    json_t *json,
    const char *key,
    unsigned char **pbData,
    size_t *cbData);

BIDError
_BIDDuplicateString(
    BIDContext context,
    const char *szSrc,
    char **szDst);

BIDError
_BIDEncodeJson(
    BIDContext context,
    json_t *jData,
    char **pEncodedJson,
    size_t *pEncodedJsonLen);

BIDError
_BIDDecodeJson(
    BIDContext context,
    const char *encodedJson,
    json_t **pjData);

BIDError
_BIDPackBackedAssertion(
    BIDContext context,
    BIDBackedAssertion assertion,
    BIDJWKSet keyset,
    char **pEncodedJson);

BIDError
_BIDUnpackBackedAssertion(
    BIDContext context,
    const char *encodedJson,
    BIDBackedAssertion *pAssertion);

BIDError
_BIDReleaseBackedAssertion(
    BIDContext context,
    BIDBackedAssertion assertion);

BIDError
_BIDRetrieveDocument(
    BIDContext context,
    const char *szHostname,
    const char *szRelativeUrl,
    time_t tIfModifiedSince,
    json_t **pJsonDoc);

BIDError
_BIDPostDocument(
    BIDContext context,
    const char *szUrl,
    const char *szPostFields,
    json_t **pJsonDoc);

json_t *
_BIDLeafCert(
    BIDContext context,
    BIDBackedAssertion backedAssertion);

json_t *
_BIDRootCert(
    BIDContext context,
    BIDBackedAssertion backedAssertion);

BIDError
_BIDPopulateIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity *pIdentity);

BIDError
_BIDUnpackAudience(
    BIDContext context,
    const char *szPackedAudience,
    char **pszAudienceOrSpn,
    unsigned char **ppbChannelBindings,
    size_t *pcbChannelBindings);

BIDError
_BIDPackAudience(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    char **pszPackedAudience);

#if 0
typedef enum {
    BID_ENCODING_UNKNOWN,
    BID_ENCODING_DECIMAL,
    BID_ENCODING_HEX,
    BID_ENCODING_BASE64,
} BIDEncoding;

BIDError
_BIDGuessEncoding(
    BIDContext context,
    const char *value,
    BIDEncoding *pEncoding);
#endif

/*
 * bid_verifier.c
 */
#define BID_VERIFIER_URL            "https://verifier.login.persona.org/verify"

BIDError
_BIDValidateAudience(
    BIDContext context,
    BIDBackedAssertion assertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings);

/*
 * bid_webkit.c
 */
BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szPackedAudience,
    char **pAssertion);

/*
 * vers.c
 */
extern const char SGS_VERS[];
extern const char VERS_NUM[];

#ifdef __cplusplus
}
#endif

#endif /* _BID_PRIVATE_H_ */
