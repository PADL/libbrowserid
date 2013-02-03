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

#ifdef WIN32
#include "bid_wpal.h"
#endif
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
 * Generate safe DH primes. Should never be necessary as we
 * always generate a new key.
 */
#define BID_CONTEXT_DH_SAFE_PRIMES          0x00010000

/*
 * bid_authority.c
 */
#define BID_WELL_KNOWN_URL          "/.well-known/browserid"
#define BID_WELL_KNOWN_URL_LEN      (sizeof(BID_WELL_KNOWN_URL) - 1)

#define BID_GSS_AUDIENCE_PREFIX     "urn:x-gss:"
#define BID_GSS_AUDIENCE_PREFIX_LEN (sizeof(BID_GSS_AUDIENCE_PREFIX) - 1)

typedef json_t *BIDAuthority;
typedef json_t *BIDJWK;
typedef json_t *BIDJWKSet;

struct BIDBackedAssertionDesc;
typedef struct BIDBackedAssertionDesc *BIDBackedAssertion;

struct BIDSecretHandleDesc;
typedef struct BIDSecretHandleDesc *BIDSecretHandle;

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

#define BID_ENCODING_UNKNOWN       0
#define BID_ENCODING_BASE64_URL    1
#define BID_ENCODING_BASE64        2

BIDError
_BIDBase64Encode(const unsigned char *data, size_t size, uint32_t encoding, char **str, size_t *cchStr);

BIDError
_BIDBase64UrlDecode(const char *str, unsigned char **pData, size_t *cbData);

/*
 * bid_cache.c
 */
#define BID_CACHE_FLAG_UNVERSIONED              0x00000001
#define BID_CACHE_FLAG_READONLY                 0x00000002

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

    BIDError (*FirstObject)(struct BIDCacheOps *, BIDContext, void *, void **, const char **, json_t **val);
    BIDError (*NextObject)(struct BIDCacheOps *, BIDContext, void *, void **, const char **, json_t **val);
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

#if 0
BIDError
_BIDGetCacheBinaryValue(
    BIDContext context BID_UNUSED,
    BIDCache cache,
    const char *key,
    unsigned char **pbData,
    size_t *cbData);
#endif

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
    void **cookie,
    const char **pKey,
    json_t **pValue);

BIDError
_BIDGetNextCacheObject(
    BIDContext context,
    BIDCache cache,
    void **cookie,
    const char **pKey,
    json_t **pValue);

BIDError
_BIDCacheIteratorAlloc(
    json_t *json,
    void **pCookie);

BIDError
_BIDCacheIteratorNext(
    void **cookie,
    const char **pKey,
    json_t **pValue);

BIDError
_BIDPurgeCache(
    BIDContext context,
    BIDCache cache,
    int (*selector)(BIDContext, BIDCache, const char *, json_t *, void *),
    void *data);

BIDError
_BIDPerformCacheObjects(
    BIDContext context,
    BIDCache cache,
    BIDError (*selector)(BIDContext, BIDCache, const char *, json_t *, void *data),
    void *data);

BIDError
_BIDAcquireCacheForUser(
    BIDContext context,
    const char *szTemplate,
    BIDCache *pCache);

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
    BIDDHParamsCache DHParamsCache;
    uint32_t DHKeySize;
    uint32_t TicketLifetime;
    BIDCache RPCertConfig;
    void *ParentWindow;
};

/*
 * bid_crypto.c
 */
struct BIDJWTDesc;
typedef struct BIDJWTDesc *BIDJWT;

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

BIDError
_BIDIdentityComputeKey(
    BIDContext context,
    BIDIdentity identity);

BIDError
_BIDDeriveSessionSubkey(
    BIDContext context,
    BIDIdentity identity,
    const char *szSalt,
    BIDJWK *pDerivedKey);

BIDError
_BIDImportSecretKey(
    BIDContext context, 
    BIDJWK jwk,
    BIDSecretHandle *pSecretHandle);

int
_BIDIsLegacyJWK(BIDContext context, BIDJWK jwt);

BIDError
_BIDFindKeyInKeyset(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWKSet keyset,
    BIDJWK *pKey);

BIDError
_BIDVerifierDHKeyEx(
    BIDContext context,
    BIDIdentity identity);

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
_BIDAcquireDefaultDHParamsCache(
    BIDContext context);

BIDError
_BIDGetDHParams(
    BIDContext context,
    json_t **pDhParams);

BIDError
_BIDSaveDHKeySize(
    BIDContext context,
    BIDIdentity identity,
    int publicKey,
    json_t *cred);

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
    uint32_t ulFlags,
    BIDIdentity *pIdentity);

BIDError
_BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    json_t **pValue);

BIDError
_BIDValidateSubject(
    BIDContext context,
    BIDIdentity identity,
    const char *szSubjectName,
    uint32_t ulFlags);

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

BIDError
_BIDMakeSignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset,
    json_t *x509CertChain,
    char **pszJwt,
    size_t *pcchJwt);

BIDError
_BIDVerifySignature(
    BIDContext context,
    BIDJWT jwt,
    BIDJWKSet keyset);

BIDError
_BIDReleaseJWTInternal(
    BIDContext context BID_UNUSED,
    BIDJWT jwt,
    int freeit);

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
BIDError
_BIDDestroySecret(
    BIDContext context,
    BIDSecretHandle secretHandle);

BIDError
_BIDImportSecretKeyData(
    BIDContext context, 
    unsigned char *pbSecret,
    size_t cbSecret,
    BIDSecretHandle *pSecretHandle);

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
    BIDSecretHandle *pSecretHandle);

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
    BIDSecretHandle secretHandle,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbDerivedKey,
    size_t *pcbDerivedKey);

BIDError
_BIDLoadX509PrivateKey(
    BIDContext context,
    const char *path,
    const char *certPath,
    BIDJWK *pPrivateKey);

BIDError
_BIDLoadX509Certificate(
    BIDContext context BID_UNUSED,
    const char *path,
    json_t **pCert);

BIDError
_BIDPopulateX509Identity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity identity,
    uint32_t ulReqFlags);

BIDError
_BIDValidateX509CertChain(
    BIDContext context,
    json_t *certChain,
    json_t *certParams,
    time_t verificationTime);

/*
 * bid_ppal.c
 */
#ifndef WIN32
#include <pthread.h>

#define BID_MUTEX                    pthread_mutex_t
#define BID_MUTEX_INIT(m)            pthread_mutex_init((m), NULL)
#define BID_MUTEX_DESTROY(m)         pthread_mutex_destroy((m))
#define BID_MUTEX_LOCK(m)            pthread_mutex_lock((m))
#define BID_MUTEX_UNLOCK(m)          pthread_mutex_unlock((m))
#endif /* !WIN32 */

BIDError
_BIDGetCurrentJsonTimestamp(
    BIDContext context,
    json_t **pTs);

#ifdef GSSBID_DEBUG
void
_BIDOutputDebugJson(json_t *j);
#else
#define _BIDOutputDebugJson(j)
#endif

/*
 * bid_reauth.c
 */
#define BID_TICKET_FLAG_MUTUAL_AUTH             0x2

BIDError
_BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    json_t *ticket,
    uint32_t ulFlags);

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
    time_t *ptExpiryTime,
    uint32_t *pulTicketFlags);

BIDError
_BIDVerifyReauthAssertion(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion assertion,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    BIDJWK *pVerifierCred,
    uint32_t *pulRetFlags);

BIDError
_BIDAcquireDefaultTicketCache(
    BIDContext context);

BIDError
_BIDDeriveAuthenticatorRootKey(
    BIDContext context,
    BIDIdentity identity,
    BIDJWK *pArk);

#ifdef WIN32
/*
 * bid_rgycache.c
 */

extern struct BIDCacheOps _BIDRegistryCache;
#endif

/*
 * bid_rverify.c
 */
#define BID_VERIFIER_URL            "https://verifier.login.persona.org/verify"

BIDError
_BIDVerifyRemote(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion pBackedAssertion,
    const char *szAudience,
    const char *szSubjectName,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
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
_BIDJsonObjectSetBinaryValue(
    BIDContext context,
    json_t *dst,
    const char *key,
    const unsigned char *pbData,
    size_t cbData);

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
    json_t *certChain,
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

BIDError
_BIDPurgeReplayCache(
    BIDContext context,
    BIDCache cache,
    time_t currentTime);

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
    char *EncData;
    size_t EncDataLength;
    BIDJWT Assertion;
    size_t cCertificates;
    BIDJWT rCertificates[BID_MAX_CERTS];
};

struct BIDIdentityDesc {
    json_t *Attributes;
    json_t *PrivateAttributes;
    BIDSecretHandle SecretHandle;
};

BIDError
_BIDVerifyLocal(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion backedAssertion,
    const char *szAudience,
    const char *szSubjectName,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDJWK optionalVerifyCred,
    BIDIdentity *pVerifiedIdentity,
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
 * bid_wpal.c
 */

#ifdef WIN32
#define BID_MUTEX                    CRITICAL_SECTION
#define BID_MUTEX_INIT(m)            (InitializeCriticalSection((m)), 0)
#define BID_MUTEX_DESTROY(m)         DeleteCriticalSection((m))
#define BID_MUTEX_LOCK(m)            EnterCriticalSection((m))
#define BID_MUTEX_UNLOCK(m)          LeaveCriticalSection((m))
#endif

BIDError
_BIDTimeToSecondsSince1970(
    BIDContext context BID_UNUSED,
    PFILETIME pft,
    time_t *pt);

BIDError
_BIDSecondsSince1970ToTime(
    BIDContext context BID_UNUSED,
    time_t t,
    PFILETIME pft);

BIDError
_BIDUcs2ToUtf8(
    BIDContext context BID_UNUSED,
    PCWSTR ucs2String,
    char **pUtf8String);

BIDError
_BIDUtf8ToUcs2(
    BIDContext context BID_UNUSED,
    const char *utf8String,
    PWSTR *pUcs2String);

BIDError
_BIDGetJsonUcs2Value(
    BIDContext context,
    json_t *json,
    const char *key,
    PWSTR *pDst);

BIDError
_BIDSetJsonUcs2Value(
    BIDContext context,
    json_t *json,
    const char *key,
    PWSTR wsz);

BIDError
_BIDSetJsonFileTimeValue(
    BIDContext context,
    json_t *json,
    const char *key,
    PFILETIME pft);

/*
 * bid_x509.c
 */
BIDError
_BIDGetRPPrivateKey(
    BIDContext context,
    BIDJWK *pKey,
    json_t **pCertChain);

int
_BIDCanMutualAuthP(BIDContext context);

BIDError
_BIDValidateX509(
    BIDContext context,
    json_t *certChain,
    time_t verificationTime);

/*
 * vers.c
 */
extern const char SGS_VERS[];
extern const char VERS_NUM[];

#ifdef __cplusplus
}
#endif

#endif /* _BID_PRIVATE_H_ */
