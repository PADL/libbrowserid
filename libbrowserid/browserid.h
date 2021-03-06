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

#ifndef _BROWSERID_H_
#define _BROWSERID_H_ 1

#ifdef WIN32
#include <bid_wpal.h>
#else
#include <inttypes.h>
#endif
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BID_S_OK,
    BID_S_NO_CONTEXT,
    BID_S_NO_MEMORY,
    BID_S_NOT_IMPLEMENTED,
    BID_S_INVALID_PARAMETER,
    BID_S_INVALID_USAGE,
    BID_S_UNAVAILABLE,
    BID_S_UNKNOWN_JSON_KEY,
    BID_S_INVALID_JSON,
    BID_S_INVALID_BASE64,
    BID_S_INVALID_ASSERTION,
    BID_S_CANNOT_ENCODE_JSON,
    BID_S_CANNOT_ENCODE_BASE64,
    BID_S_TOO_MANY_CERTS,
    BID_S_UNTRUSTED_ISSUER,
    BID_S_INVALID_ISSUER,
    BID_S_MISSING_ISSUER,
    BID_S_MISSING_AUDIENCE,
    BID_S_BAD_AUDIENCE,
    BID_S_EXPIRED_ASSERTION,
    BID_S_ASSERTION_NOT_YET_VALID,
    BID_S_EXPIRED_CERT,
    BID_S_CERT_NOT_YET_VALID,
    BID_S_INVALID_SIGNATURE,
    BID_S_MISSING_ALGORITHM,
    BID_S_UNKNOWN_ALGORITHM,
    BID_S_INVALID_KEY,
    BID_S_INVALID_KEYSET,
    BID_S_NO_KEY,
    BID_S_CRYPTO_ERROR,
    BID_S_HTTP_ERROR,
    BID_S_BUFFER_TOO_SMALL,
    BID_S_BUFFER_TOO_LONG,
    BID_S_REMOTE_VERIFY_FAILURE,
    BID_S_MISSING_PRINCIPAL,
    BID_S_UNKNOWN_PRINCIPAL_TYPE,
    BID_S_MISSING_CERT,
    BID_S_UNKNOWN_ATTRIBUTE,
    BID_S_MISSING_CHANNEL_BINDINGS,
    BID_S_CHANNEL_BINDINGS_MISMATCH,
    BID_S_NO_SESSION_KEY,
    BID_S_DOCUMENT_NOT_MODIFIED,
    BID_S_INTERACT_UNAVAILABLE,
    BID_S_INTERACT_FAILURE,
    BID_S_INTERACT_REQUIRED,
    BID_S_INVALID_AUDIENCE_URN,
    BID_S_INVALID_JSON_WEB_TOKEN,
    BID_S_NO_MORE_ITEMS,
    BID_S_CACHE_OPEN_ERROR,
    BID_S_CACHE_READ_ERROR,
    BID_S_CACHE_WRITE_ERROR,
    BID_S_CACHE_CLOSE_ERROR,
    BID_S_CACHE_LOCK_ERROR,
    BID_S_CACHE_LOCK_TIMEOUT,
    BID_S_CACHE_UNLOCK_ERROR,
    BID_S_CACHE_DESTROY_ERROR,
    BID_S_CACHE_PERMISSION_DENIED,
    BID_S_CACHE_INVALID_VERSION,
    BID_S_CACHE_SCHEME_UNKNOWN,
    BID_S_CACHE_ALREADY_EXISTS,
    BID_S_CACHE_NOT_FOUND,
    BID_S_CACHE_KEY_NOT_FOUND,
    BID_S_REPLAYED_ASSERTION,
    BID_S_DH_PARAM_GENERATION_FAILURE,
    BID_S_DH_KEY_GENERATION_FAILURE,
    BID_S_NO_TICKET_CACHE,
    BID_S_BAD_TICKET_CACHE,
    BID_S_CERT_FILE_UNREADABLE,
    BID_S_KEY_FILE_UNREADABLE,
    BID_S_UNTRUSTED_X509_CERT,
    BID_S_NOT_REAUTH_ASSERTION,
    BID_S_BAD_SUBJECT,
    BID_S_MISMATCHED_RP_RESPONSE,
    BID_S_REFLECTED_RP_RESPONSE,
    BID_S_MISSING_SIGNATURE,
    BID_S_INVALID_SECRET,
    BID_S_KEY_TOO_SHORT,
    BID_S_UNKNOWN_EC_CURVE,
    BID_S_INVALID_EC_CURVE,
    BID_S_MISSING_NONCE,
    BID_S_UNKNOWN_ERROR_CODE,
} BIDError;

BIDError
BIDErrorToString(
    BIDError error,
    const char **pString);

struct BIDContextDesc;
typedef struct BIDContextDesc *BIDContext;

#define BID_C_NO_CONTEXT                    ((BIDContext)0)
#define BID_C_NO_IDENTITY                   ((BIDIdentity)0)
#define BID_C_NO_AUTHORITY_CACHE            ((BIDAuthorityCache)0)
#define BID_C_NO_REPLAY_CACHE               ((BIDReplayCache)0)
#define BID_C_NO_TICKET_CACHE               ((BIDTicketCache)0)

/*
 * Context is used by user-agent.
 */
#define BID_CONTEXT_USER_AGENT              0x00000001

/*
 * Context is used by relying party.
 */
#define BID_CONTEXT_RP                      0x00000002

/*
 * Context uses remote verification service.
 */
#define BID_CONTEXT_VERIFY_REMOTE           0x00000004

/*
 * Context uses persistent authority cache.
 */
#define BID_CONTEXT_AUTHORITY_CACHE         0x00000008

/*
 * Context is for GSS client.
 */
#define BID_CONTEXT_GSS                     0x00000010

/*
 * Use replay cache.
 */
#define BID_CONTEXT_REPLAY_CACHE            0x00000020

/*
 * Disable interaction with user completely.
 */
#define BID_CONTEXT_INTERACTION_DISABLED    0x00000040

#if 0
/*
 * Do not prompt user if the browser already has a key
 * for the user. Note that this is independent of reauth
 * credentials.
 */
#define BID_CONTEXT_BROWSER_SILENT          0x00000080

/*
 * DH key exchange
 */
#define BID_CONTEXT_DH_KEYEX                0x00000100
#endif

/*
 * Fast reauthentication support (requires replay cache on RP).
 */
#define BID_CONTEXT_REAUTH                  0x00000200

/*
 * Use ticket cache
 */
#define BID_CONTEXT_TICKET_CACHE            0x00000400

/*
 * ECDH key exchange
 */
#define BID_CONTEXT_ECDH_KEYEX              0x00000800

/*
 * Allow host SPN when validating audiences
 */
#define BID_CONTEXT_HOST_SPN_ALIAS          0x00001000

/*
 * Context management.
 */
struct BIDAcquireContextArgsDesc;
typedef struct BIDAcquireContextArgsDesc *BIDAcquireContextArgs;

BIDError
BIDAcquireContext(
    const char *szConfig,
    uint32_t ulContextOptions,
    BIDAcquireContextArgs contextArgs,
    BIDContext *pContext);

BIDError
BIDReleaseContext(BIDContext context);

#define BID_ECDH_CURVE_P256                 "P-256"
#define BID_ECDH_CURVE_P384                 "P-384"
#define BID_ECDH_CURVE_P521                 "P-521"

typedef enum {
    BID_PARAM_AUDIENCES = 1,
    BID_PARAM_SECONDARY_AUTHORITIES,
    BID_PARAM_VERIFIER_URL,
    BID_PARAM_JSON_ERROR_INFO,
    BID_PARAM_MAX_DELEGATIONS,
    BID_PARAM_SKEW,
    BID_PARAM_CONTEXT_OPTIONS,
    BID_PARAM_DH_MODULUS_SIZE,
    BID_PARAM_REPLAY_CACHE_NAME,
    BID_PARAM_AUTHORITY_CACHE_NAME,
    BID_PARAM_TICKET_CACHE_NAME,
    BID_PARAM_CONFIG_NAME,
    BID_PARAM_REPLAY_CACHE,
    BID_PARAM_AUTHORITY_CACHE,
    BID_PARAM_TICKET_CACHE,
    BID_PARAM_CONFIG_CACHE,
    BID_PARAM_PARENT_WINDOW,
    BID_PARAM_TICKET_LIFETIME, /* seconds */
    BID_PARAM_ECDH_CURVE,
    BID_PARAM_RENEW_LIFETIME, /* seconds */
} BIDContextParameter;

BIDError
BIDSetContextParam(BIDContext context, BIDContextParameter ulParam, void *value);

BIDError
BIDGetContextParam(BIDContext context, BIDContextParameter ulParam, void **pValue);

struct BIDIdentityDesc;
typedef struct BIDIdentityDesc *BIDIdentity;

struct BIDCacheDesc;
typedef struct BIDCacheDesc *BIDCache;

typedef BIDCache BIDReplayCache;
typedef BIDCache BIDAuthorityCache;
typedef BIDCache BIDTicketCache;

BIDError
BIDAcquireTicketCache(
    BIDContext context,
    const char *szCacheName,
    BIDTicketCache *pCache);

BIDError
BIDReleaseTicketCache(
    BIDContext context,
    BIDTicketCache cache);

BIDError
BIDAcquireReplayCache(
    BIDContext context,
    const char *szCacheName,
    BIDReplayCache *pCache);

BIDError
BIDReleaseReplayCache(
    BIDContext context,
    BIDReplayCache cache);

/*
 * User agent.
 */

/* Input flags (ulReqFlags) */
#define BID_ACQUIRE_FLAG_NO_INTERACT        0x00000001
#define BID_ACQUIRE_FLAG_NO_CACHED          0x00000002
#define BID_ACQUIRE_FLAG_MUTUAL_AUTH        0x00000004
#define BID_ACQUIRE_FLAG_EXTRA_ROUND_TRIP   0x00000008 /* request XRT option */
#define BID_ACQUIRE_FLAG_DCE                0x00000010 /* request DCE option */
#define BID_ACQUIRE_FLAG_IDENTIFY           0x00000020 /* request identify option */
#define BID_ACQUIRE_FLAG_FORCE_AUTH         0x00000040 /* forceAuthentication: true */

/* Output flags (ulRetFlags) */
#define BID_ACQUIRE_FLAG_REAUTH             0x00010000
#define BID_ACQUIRE_FLAG_REAUTH_MUTUAL      0x00020000

BIDError
BIDAcquireAssertionFromString(
    BIDContext context,
    const char *szAssertion,
    uint32_t ulFlags,
    BIDIdentity *pAssertedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulFlags);

BIDError
BIDAcquireAssertion(
    BIDContext context,
    BIDTicketCache ticketCache, /* optional, uses context cache if absent */
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName, /* optional */
    uint32_t ulFlags,
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulFlags);

BIDError
BIDFreeAssertion(
    BIDContext context,
    char *assertion);

/*
 * Verifier.
 */

/* Input flags (ulReqFlags) */
#define BID_VERIFY_FLAG_REAUTH                  0x00000001

/* Output flags (ulRetFlags) */
#define BID_VERIFY_FLAG_REMOTE                  0x00010000
#define BID_VERIFY_FLAG_VALIDATED_CERTS         0x00020000
#define BID_VERIFY_FLAG_X509                    0x00040000
#define BID_VERIFY_FLAG_REAUTH_MUTUAL           0x00080000
#define BID_VERIFY_FLAG_EXTRA_ROUND_TRIP        0x00100000 /* requested XRT option */
#define BID_VERIFY_FLAG_DCE                     0x00200000 /* requested DCE option */
#define BID_VERIFY_FLAG_IDENTIFY                0x00400000 /* requested identify option */
#define BID_VERIFY_FLAG_MUTUAL_AUTH             0x00800000 /* requested MA option */

BIDError
BIDVerifyAssertion(
    BIDContext context,
    BIDReplayCache replayReauthCache, /* optional, uses context replay cache if absent */
    const char *szAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t tVerificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulVerifyFlags);

BIDError
BIDGetIdentityAudience(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue);

BIDError
BIDGetIdentitySubject(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue);

BIDError
BIDGetIdentityIssuer(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue);

BIDError
BIDGetIdentityAttribute(
    BIDContext context,
    BIDIdentity identity,
    const char *attribute,
    const char **pValue);

BIDError
BIDGetIdentityExpiryTime(
    BIDContext context,
    BIDIdentity identity,
    time_t *value);

#ifdef JANSSON_H
/* Caller frees reference; pass NULL to get root object. */
BIDError
BIDGetIdentityJsonObject(
    BIDContext context,
    BIDIdentity identity,
    const char *attribute,
    json_t **pJsonValue);
#endif

BIDError
BIDGetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    unsigned char **pY,
    size_t *pcbY);

BIDError
BIDSetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    const unsigned char *Y,
    size_t cbY);

BIDError
BIDIdentityDeriveKey(
    BIDContext context,
    BIDIdentity identity,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey);

BIDError
BIDFreeIdentityDerivedKey(
    BIDContext context,
    BIDIdentity identity,
    unsigned char *pbSessionKey,
    size_t cbSessionKey);

BIDError
BIDReleaseIdentity(
    BIDContext context,
    BIDIdentity identity);

BIDError
BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue);

BIDError
BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    const char *szTicket);

/* Input flags (ulReqFlags) */
#define BID_RP_FLAG_HAVE_SESSION_KEY            0x00000001 /* have a session key */
#define BID_RP_FLAG_INITIAL                     0x00000002 /* not reauth-based auth */
#define BID_RP_FLAG_X509_THUMBPRINT             0x00000008 /* send thumbprint not cert */
#define BID_RP_FLAG_FORCE_EXTRA_ROUND_TRIP      0x00000010 /* force XRT even if initiator didn't request it */

/* Output flags (ulRetFlags) */
#define BID_RP_FLAG_VALIDATED_CERTS             0x00020000 /* validated certificate chain */
#define BID_RP_FLAG_X509                        0x00040000 /* certs were X.509 */
#define BID_RP_FLAG_EXTRA_ROUND_TRIP            0x00080000 /* server supports XRT extension */

#ifdef JANSSON_H
BIDError
BIDAcquireAssertionEx(
    BIDContext context,
    BIDTicketCache ticketCache, /* optional, uses context cache if absent */
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    const char *szIdentityName, /* optional */
    uint32_t ulFlags,
    json_t *userClaims, /* optional */
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulFlags);

BIDError
BIDMakeRPResponseToken(
    BIDContext context,
    BIDIdentity identity,
    json_t *Payload,
    uint32_t ulReqFlags,
    char **pszResponseToken,
    size_t *pchResponseToken,
    uint32_t *pulRetFlags);

BIDError
BIDVerifyRPResponseToken(
    BIDContext context,
    BIDIdentity identity,
    const char *szAssertion,
    const char *szAudienceName,
    uint32_t ulReqFlags,
    json_t **pPayload,
    uint32_t *pulRetFlags);

BIDError
BIDMakeXRTToken(
    BIDContext context,
    BIDIdentity identity,
    json_t *additionalClaims,
    uint32_t ulReqFlags,
    char **pszResponseToken,
    size_t *pchResponseToken,
    uint32_t *pulRetFlags);

BIDError
BIDVerifyXRTToken(
    BIDContext context,
    BIDIdentity identity,
    const char *szAssertion,
    uint32_t ulReqFlags,
    json_t **pPayload,
    uint32_t *pulRetFlags);
#endif /* JANSSON_H */

BIDError
BIDFreeData(
    BIDContext context,
    char *s);

#ifdef __cplusplus
}
#endif

#endif /* _BROWSERID_H_ */
