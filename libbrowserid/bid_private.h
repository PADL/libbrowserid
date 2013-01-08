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

#define BID_GSS_AUDIENCE_PREFIX     "urn:x-gss:"
#define BID_GSS_AUDIENCE_PREFIX_LEN (sizeof(BID_GSS_AUDIENCE_PREFIX) - 1)

typedef json_t *BIDAuthority;
typedef json_t *BIDJWK;
typedef json_t *BIDJWKSet;

struct BIDBackedAssertionDesc;
typedef struct BIDBackedAssertionDesc *BIDBackedAssertion;

BIDError
_BIDAcquireDefaultAuthorityCache(
    BIDContext context);

BIDError
_BIDAcquireAuthority(
    BIDContext context,
    const char *hostname,
    time_t verificationTime,
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
    const char *szIssuer,
    time_t verificationTime);

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
struct BIDCacheOps {
    const char *Scheme;

    BIDError (*Acquire)(struct BIDCacheOps *, BIDContext, void **, const char *, uint32_t flags);
    BIDError (*Release)(struct BIDCacheOps *, BIDContext, void *);

    BIDError (*Initialize)(struct BIDCacheOps *, BIDContext, void *);
    BIDError (*Destroy)(struct BIDCacheOps *, BIDContext, void *);

    BIDError (*GetName)(struct BIDCacheOps *, BIDContext, void *, const char **);
    BIDError (*GetLastChangedTime)(struct BIDCacheOps *, BIDContext, void *, time_t *time);

    BIDError (*GetObject)(struct BIDCacheOps *, BIDContext, void *, const char *key, json_t **val);
    BIDError (*SetObject)(struct BIDCacheOps *, BIDContext, void *, const char *key, json_t *val);
    BIDError (*RemoveObject)(struct BIDCacheOps *, BIDContext, void *, const char *key);

    BIDError (*FirstObject)(struct BIDCacheOps *, BIDContext, void *, const char **, json_t **val);
    BIDError (*NextObject)(struct BIDCacheOps *, BIDContext, void *, const char **, json_t **val);
};

BIDError
_BIDAcquireCache(
    BIDContext context,
    const char *szCacheName,
    uint32_t ulFlags,
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
_BIDGetFirstCacheObject(
    BIDContext context,
    BIDCache cache,
    const char **pKey,
    json_t **pValue);

BIDError
_BIDGetNextCacheObject(
    BIDContext context,
    BIDCache cache,
    const char **pKey,
    json_t **pValue);

/*
 * bid_context.c
 */
struct BIDContextDesc {
    uint32_t ContextOptions;
    char **SecondaryAuthorities;
    json_error_t JsonError;
    char *VerifierUrl;
    uint32_t MaxDelegations;
    uint32_t Skew;
    BIDAuthorityCache AuthorityCache;
    BIDReplayCache ReplayCache;
    BIDTicketCache TicketCache;
    uint32_t DhKeySize; 
    uint32_t TicketLifetime;
};

/*
 * bid_fcache.c
 */

extern struct BIDCacheOps _BIDFileCache;

/*
 * bid_identity.c
 */
BIDError
_BIDAllocIdentity(
    BIDContext context,
    json_t *attributes,
    BIDIdentity *pIdentity);

BIDError
_BIDPopulateIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity *pIdentity);

BIDError
_BIDSetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t *y);

BIDError
_BIDGetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t **y);

BIDError
_BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    json_t **pValue);

/*
 * bid_jwt.c
 */
struct BIDJWTDesc {
    char *EncData;
    size_t EncDataLength;
    json_t *Header;
    json_t *Payload;
    unsigned char *Signature;
    size_t SignatureLength;
};

typedef struct BIDJWTAlgorithmDesc {
    const char *szAlgID;
    const char *szKeyAlgID;
    size_t cbKey;
    const unsigned char *pbOid;
    size_t cbOid;
    BIDError (*MakeSignature)(struct BIDJWTAlgorithmDesc *, BIDContext, BIDJWT, BIDJWK);
    BIDError (*VerifySignature)(struct BIDJWTAlgorithmDesc *, BIDContext, BIDJWT, BIDJWK, int *);
    BIDError (*KeySize)(struct BIDJWTAlgorithmDesc *desc, BIDContext, BIDJWK, size_t *);
} *BIDJWTAlgorithm;

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
 * bid_fcache.c
 */

extern struct BIDCacheOps _BIDMemoryCache;

/*
 * bid_openssl.c
 */

/*
 * To implement a new crypto provider, you need to replace the following
 * dispatch table and functions.
 */
extern struct BIDJWTAlgorithmDesc _BIDJWTAlgorithms[];

/*
 * Hash the assertion in an implementation-defined manner that may be used
 * as a key into the replay cache as well as a ticket identifier.
 */
BIDError
_BIDDigestAssertion(
    BIDContext context,
    const char *szAssertion,
    unsigned char *digest,
    size_t *digestLength);

/*
 * Generate a Diffie-Hellman key with the specified parameters.
 */
BIDError
_BIDGenerateDHKey(
    BIDContext context,
    json_t *dhParams,
    BIDJWK *pDhKey);

/*
 * Generate Diffie-Hellman parameters.
 */
BIDError
_BIDGenerateDHParams(
    BIDContext context,
    json_t **pDhParams);

/*
 * Compute a Diffie-Hellman shared secret.
 */
BIDError
_BIDComputeDHKey(
    BIDContext context,
    BIDJWK dhKey,
    json_t *pubValue,
    unsigned char **ppbKey,
    size_t *pcbKey);

/*
 * Generate a random base64 URL encoded nonce of at least 64 bits.
 */
BIDError
_BIDGenerateNonce(
    BIDContext context,
    json_t **pNonce);

/*
 * Derive a key using HMAC(K, "BrowserID" || pbSalt || 0x01)
 */
BIDError
_BIDDeriveKey(
    BIDContext context,
    const unsigned char *pbBaseKey,
    size_t cbBaseKey,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey);

/*
 * bid_reauth.c
 */
BIDError
_BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    json_t *ticket);

BIDError
_BIDGetReauthAssertion(
    BIDContext context,
    BIDTicketCache ticketCache,
    const char *szPackedAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName, /* optional */
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime);

BIDError
_BIDVerifyReauthAssertion(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion assertion,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    BIDJWK *pVerifierCred);

BIDError
_BIDAcquireDefaultTicketCache(
    BIDContext context);

BIDError
_BIDDeriveAuthenticatorRootKey(
    BIDContext context,
    BIDIdentity identity,
    BIDJWK *pArk);

BIDError
_BIDDeriveAuthenticatorSessionKey(
    BIDContext context,
    BIDJWK ark,
    BIDJWT ap,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey);

/*
 * bid_rverify.c
 */
#define BID_VERIFIER_URL            "https://verifier.login.persona.org/verify"

BIDError
_BIDVerifyRemote(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulRetFlags);

/*
 * bid_util.c
 */
BIDError
_BIDMakeAudience(
    BIDContext context,
    const char *szAudienceOrSpn,
    char **pszPackedAudience);

BIDError
_BIDJsonBinaryValue(
    BIDContext context,
    const unsigned char *pbData,
    size_t cbData,
    json_t **pJson);

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
_BIDGetJsonTimestampValue(
    BIDContext context,
    json_t *json,
    const char *key,
    time_t *ts);

BIDError
_BIDSetJsonTimestampValue(
    BIDContext context,
    json_t *json,
    const char *key,
    time_t ts);

BIDError
_BIDGetCurrentJsonTimestamp(
    BIDContext context,
    json_t **pTs);

BIDError
_BIDDuplicateString(
    BIDContext context,
    const char *szSrc,
    char **szDst);

#define BID_JSON_FLAG_REQUIRED      1
#define BID_JSON_FLAG_CONSUME_REF   2

BIDError
_BIDJsonObjectSet(
    BIDContext context BID_UNUSED,
    json_t *dst,
    const char *key,
    json_t *src,
    uint32_t ulFlags);

BIDError
_BIDJsonObjectDel(
    BIDContext context BID_UNUSED,
    json_t *dst,
    const char *key,
    uint32_t ulFlags);

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
    json_t **pJsonDoc,
    time_t *pExpiryTime);

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

int
_BIDCanInteractP(
    BIDContext context,
    uint32_t ulReqFlags);

/*
 * bid_rcache.c
 */
BIDError
_BIDAcquireDefaultReplayCache(
    BIDContext context);

BIDError
_BIDCheckReplayCache(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    time_t verificationTime);

BIDError
_BIDUpdateReplayCache(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDIdentity identity,
    const char *pAssertion,
    time_t verificationTime,
    uint32_t ulFlags);

/*
 * bid_user.c
 */

/*
 * bid_verify.c
 */

#define BID_MAX_CERTS               10

BIDError
_BIDValidateAudience(
    BIDContext context,
    BIDBackedAssertion assertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings);

struct BIDBackedAssertionDesc {
    BIDJWT Assertion;
    size_t cCertificates;
    BIDJWT rCertificates[BID_MAX_CERTS];
};

struct BIDIdentityDesc {
    json_t *Attributes;
    json_t *PrivateAttributes;
    unsigned char *SessionKey;
    size_t SessionKeyLength;
};

BIDError
_BIDVerifyLocal(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulRetFlags);

BIDError
_BIDValidateExpiry(
    BIDContext context,
    time_t verificationTime,
    json_t *assertion);

/*
 * bid_webkit.c
 */
#define BID_SIGN_IN_URL              "https://login.persona.org/sign_in#NATIVE"

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName, /* optional */
    uint32_t ulReqFlags,
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
