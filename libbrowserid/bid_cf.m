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

#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H

#include <Foundation/Foundation.h>

CF_EXPORT void _CFRuntimeBridgeClasses(CFTypeID cf_typeID, const char *objc_classname);
CF_EXPORT CFTypeRef _CFTryRetain(CFTypeRef cf);
CF_EXPORT Boolean _CFIsDeallocating(CFTypeRef cf);

/*
 * This is a CoreFoundation wrapper for libbrowserid. It only builds if the
 * CoreFoundation/CFRuntime.h private header is available (which may change
 * between OS releases). It makes the libbrowserid context, identity and
 * cache types first-class CoreFoundation (and thus Objective-C) objects,
 * and provides accessor functions that take and return CF types.
 *
 * There are examples in ../sample/bidcf{get,verify}.m that show how to use
 * these APIs from an Objective-C program.
 */

const CFStringRef kBIDIdentitySubjectKey    = CFSTR("sub");
const CFStringRef kBIDIdentityIssuerKey     = CFSTR("iss");
const CFStringRef kBIDIdentityExpiryTimeKey = CFSTR("exp");
const CFStringRef kBIDIdentityIssuedAtKey   = CFSTR("iat");
const CFStringRef kBIDIdentityPublicKeyKey  = CFSTR("public-key");
const CFStringRef kBIDIdentityPrincipalKey  = CFSTR("principal");

static CFTypeID _BIDIdentityTypeID          = _kCFRuntimeNotATypeID;
static CFTypeID _BIDContextTypeID           = _kCFRuntimeNotATypeID;
static CFTypeID _BIDCacheTypeID             = _kCFRuntimeNotATypeID;

#if __BLOCKS__
static dispatch_queue_t _BIDBackgroundQueue = NULL;
#endif

static void
_BIDCFInit(void) __attribute__((__constructor__));

static CFStringRef
_BIDIdentityCopyDebugDescription(CFTypeRef cf);

static CFErrorRef
_BIDCFMapError(BIDContext context, BIDError err);

static const CFRuntimeClass _BIDIdentityClass = {
    0,
    "BIDIdentity",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeIdentity,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    _BIDIdentityCopyDebugDescription, // copyDebugDesc
};

static const CFRuntimeClass _BIDContextClass = {
    0,
    "BIDContext",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeContext,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    NULL, // copyDebugDesc
};

static const CFRuntimeClass _BIDCacheClass = {
    0,
    "BIDCache",
    NULL, // init
    NULL, // copy
    (void (*)(CFTypeRef))_BIDFinalizeCache,
    NULL, // equal
    NULL, // hash
    NULL, // copyFormattingDesc
    NULL, // copyDebugDesc
};

static void
_BIDCFInit(void)
{
    _BIDIdentityTypeID = _CFRuntimeRegisterClass(&_BIDIdentityClass);
    BID_ASSERT(_BIDIdentityTypeID != _kCFRuntimeNotATypeID);
    _CFRuntimeBridgeClasses(_BIDIdentityTypeID, "__BIDCFIdentity");

    _BIDContextTypeID = _CFRuntimeRegisterClass(&_BIDContextClass);
    BID_ASSERT(_BIDContextTypeID != _kCFRuntimeNotATypeID);

    _BIDCacheTypeID = _CFRuntimeRegisterClass(&_BIDCacheClass);
    BID_ASSERT(_BIDCacheTypeID != _kCFRuntimeNotATypeID);

#if __BLOCKS__
    _BIDBackgroundQueue = dispatch_queue_create("com.padl.BrowserID.queue", DISPATCH_QUEUE_CONCURRENT);
    BID_ASSERT(_BIDBackgroundQueue != NULL);
#endif
}

CFTypeID
BIDIdentityGetTypeID(void)
{
    BID_ASSERT(_BIDIdentityTypeID != _kCFRuntimeNotATypeID);
    return _BIDIdentityTypeID;
}

CFTypeID
BIDContextGetTypeID(void)
{
    BID_ASSERT(_BIDContextTypeID != _kCFRuntimeNotATypeID);
    return _BIDContextTypeID;
}

CFTypeID
BIDCacheGetTypeID(void)
{
    BID_ASSERT(_BIDCacheTypeID != _kCFRuntimeNotATypeID);
    return _BIDCacheTypeID;
}

static CFErrorRef
_BIDCFMapError(BIDContext context, BIDError err)
{
    CFErrorRef cfError = NULL;
    CFDictionaryRef cfDict = NULL;
    const char *szErr = NULL;
    CFAllocatorRef allocator = (context == BID_C_NO_CONTEXT) ? kCFAllocatorDefault : CFGetAllocator(context);

    BIDErrorToString(err, &szErr);

    if (szErr != NULL) {
        CFStringRef errDesc;

        errDesc = CFStringCreateWithCString(allocator, szErr, kCFStringEncodingASCII);
        cfDict = CFDictionaryCreate(allocator,
                                    (const void **)&kCFErrorDescriptionKey,
                                    (const void **)&errDesc,
                                    1,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
        CFRelease(errDesc);
    }

    cfError = CFErrorCreate(allocator, CFSTR("com.padl.BrowserID"), err, cfDict);

    if (cfDict != NULL)
        CFRelease(cfDict);

    return cfError;
}

BIDContext
BIDContextCreate(
    CFAllocatorRef allocator,
    CFStringRef configFile,
    uint32_t ulContextOptions,
    CFErrorRef *pError)
{
    BIDError err;
    BIDContext context = BID_C_NO_CONTEXT;
    char *szConfigFile = NULL;
    struct BIDAcquireContextArgsDesc args;

    if (configFile != NULL) {
        szConfigFile = json_string_copy(configFile);
        if (szConfigFile == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    memset(&args, 0, sizeof(args));
    args.Version = BID_ACQUIRE_CONTEXT_ARGS_VERSION;
    args.cbHeaderLength = sizeof(args);
    args.cbStructureLength = args.cbHeaderLength;
    args.CFAllocator = allocator;

    err = BIDAcquireContext(szConfigFile, ulContextOptions, &args, &context);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    BIDFree(szConfigFile);

    return context;
}

BIDIdentity
BIDIdentityCreateByVerifyingAssertion(
    BIDContext context,
    CFStringRef assertion,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFAbsoluteTime verificationTime,
    uint32_t ulReqFlags,
    uint32_t *pulVerifyFlags,
    CFErrorRef *pError)
{
    char *szAssertion = NULL;
    char *szAudienceOrSpn = NULL;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    time_t expiryTime;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    BIDError err;

    if (pulVerifyFlags != NULL)
        *pulVerifyFlags = 0;
    if (pError != NULL)
        *pError = NULL;

    if (assertion == NULL)
        return NULL;

    szAssertion = json_string_copy(assertion);
    if (szAssertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (audienceOrSpn != NULL) {
        szAudienceOrSpn = json_string_copy(audienceOrSpn);
        if (szAudienceOrSpn == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    if (channelBindings != NULL) {
        pbChannelBindings = CFDataGetBytePtr(channelBindings);
        cbChannelBindings = CFDataGetLength(channelBindings);
    }

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE, szAssertion,
                             szAudienceOrSpn, pbChannelBindings, cbChannelBindings,
                             verificationTime + kCFAbsoluteTimeIntervalSince1970,
                             ulReqFlags, &identity, &expiryTime, pulVerifyFlags);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    BIDFree(szAssertion);
    BIDFree(szAudienceOrSpn);

    return identity;
}

static CFStringRef
_BIDIdentityCopyDebugDescription(
    CFTypeRef cf)
{
    CFStringRef desc;
    BIDIdentity identity = (BIDIdentity)cf;
    CFStringRef sub = NULL, iss = NULL;

    if (identity->Attributes != NULL) {
        sub = CFDictionaryGetValue(identity->Attributes, kBIDIdentitySubjectKey);
        iss = CFDictionaryGetValue(identity->Attributes, kBIDIdentityIssuerKey);
    }
    if (sub == NULL)
        sub = CFSTR("?");
    if (iss == NULL)
        iss = CFSTR("?");

    desc = CFStringCreateWithFormat(CFGetAllocator(cf), NULL,
                                    CFSTR("<BIDIdentity %p>{subject = \"%@\", issuer = \"%@\"}"),
                                    cf, sub, iss);

    return desc;
}

BIDIdentity
BIDIdentityCreateFromString(
    BIDContext context,
    CFStringRef assertion,
    uint32_t ulReqFlags,
    uint32_t *pulRetFlags,
    CFErrorRef *pError)
{
    char *szAssertion = NULL;
    time_t expiryTime;
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;

    if (pulRetFlags != NULL)
        *pulRetFlags = 0;
    if (pError != NULL)
        *pError = NULL;

    if (assertion == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    szAssertion = json_string_copy(assertion);
    if (szAssertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BIDAcquireAssertionFromString(context, szAssertion, ulReqFlags,
                                        &identity, &expiryTime, pulRetFlags);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    BIDFree(szAssertion);

    return (err == BID_S_OK) ? identity : NULL;
}

CFDictionaryRef
BIDIdentityCopyAttributeDictionary(
    BIDIdentity identity)
{
    if (identity == BID_C_NO_IDENTITY)
        return NULL;

    return CFRetain(identity->Attributes);
}

CFTypeRef
BIDIdentityCopyAttributeValue(
    BIDIdentity identity,
    CFStringRef attribute)
{
    CFTypeRef value;

    if (identity == NULL || identity->Attributes == NULL)
        return NULL;

    value = CFDictionaryGetValue(identity->Attributes, attribute);
    if (value != NULL)
        CFRetain(value);

    return value;
}

CFStringRef
BIDAssertionCreateUI(
    BIDContext context,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFStringRef optionalIdentity,
    uint32_t ulFlags,
    BIDIdentity *pAssertedIdentity,
    uint32_t *pulFlags,
    CFErrorRef *pError)
{
    return BIDAssertionCreateUIWithClaims(context,
                                          audienceOrSpn,
                                          channelBindings,
                                          optionalIdentity,
                                          ulFlags,
                                          NULL,
                                          pAssertedIdentity,
                                          pulFlags,
                                          pError);
}

CFStringRef
BIDAssertionCreateUIWithClaims(
    BIDContext context,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFStringRef optionalIdentity,
    uint32_t ulFlags,
    CFDictionaryRef userClaims,
    BIDIdentity *pAssertedIdentity,
    uint32_t *pulFlags,
    CFErrorRef *pError)
{
    char *szAudienceOrSpn = NULL;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    char *szIdentity = NULL;
    char *szAssertion = NULL;
    CFStringRef assertion = NULL;
    time_t expiryTime;
    BIDError err;

    if (pulFlags != NULL)
        *pulFlags = 0;
    if (pError != NULL)
        *pError = NULL;

    if (audienceOrSpn != NULL) {
        szAudienceOrSpn = json_string_copy(audienceOrSpn);
        if (szAudienceOrSpn == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    if (channelBindings != NULL) {
        pbChannelBindings = CFDataGetBytePtr(channelBindings);
        cbChannelBindings = CFDataGetLength(channelBindings);
    }

    if (optionalIdentity != NULL) {
        szIdentity = json_string_copy(optionalIdentity);
        if (szIdentity == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    err = BIDAcquireAssertionEx(context, BID_C_NO_TICKET_CACHE, szAudienceOrSpn,
                                pbChannelBindings, cbChannelBindings, szIdentity,
                                ulFlags, userClaims, &szAssertion, pAssertedIdentity,
                                &expiryTime, pulFlags);
    BID_BAIL_ON_ERROR(err);

    assertion = CFStringCreateWithCString(CFGetAllocator(context), szAssertion, kCFStringEncodingASCII);
    if (assertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    BIDFree(szAudienceOrSpn);
    BIDFree(szIdentity);
    BIDFree(szAssertion);

    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    return assertion;
}

BIDTicketCache
BIDTicketCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError)
{
    BIDError err;
    char *szCacheName;
    BIDTicketCache ticketCache = BID_C_NO_TICKET_CACHE;

    if (pError != NULL)
        *pError = NULL;

    szCacheName = json_string_copy(cacheName);
    if (szCacheName == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BIDAcquireTicketCache(context, szCacheName, &ticketCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szCacheName);

    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    return ticketCache;
}

BIDReplayCache
BIDReplayCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError)
{
    BIDError err;
    char *szCacheName;
    BIDReplayCache replayCache = BID_C_NO_REPLAY_CACHE;

    if (pError != NULL)
        *pError = NULL;

    szCacheName = json_string_copy(cacheName);
    if (szCacheName == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BIDAcquireReplayCache(context, szCacheName, &replayCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szCacheName);

    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(context, err);

    return replayCache;
}

CFAbsoluteTime
BIDIdentityGetExpiryTime(
    BIDIdentity identity)
{
    time_t expiryTime;

    BIDGetIdentityExpiryTime(BID_C_NO_CONTEXT, identity, &expiryTime);

    return expiryTime - kCFAbsoluteTimeIntervalSince1970;
}

#if __BLOCKS__
void
BIDVerifyAssertionWithHandler(
    BIDContext context,
    CFStringRef assertion,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFAbsoluteTime verificationTime,
    uint32_t ulReqFlags,
    dispatch_queue_t queue,
    void (^handler)(BIDIdentity, uint32_t, CFErrorRef))
{
    dispatch_retain(queue);
    CFRetain(context);
    CFRetain(assertion);
    CFRetain(audienceOrSpn);
    if (channelBindings != NULL)
        CFRetain(channelBindings);

    dispatch_async(_BIDBackgroundQueue, ^{
        BIDIdentity identity = BID_C_NO_IDENTITY;
        uint32_t ulVerifyFlags = 0;
        CFErrorRef error = NULL;

        identity = BIDIdentityCreateByVerifyingAssertion(context,
                                                         assertion,
                                                         audienceOrSpn,
                                                         channelBindings,
                                                         verificationTime,
                                                         ulReqFlags,
                                                         &ulVerifyFlags,
                                                         &error);

        dispatch_async(queue, ^{
            handler(identity, ulVerifyFlags, error);

            dispatch_release(queue);
            CFRelease(context);
            CFRelease(assertion);
            CFRelease(audienceOrSpn);
            if (channelBindings != NULL)
                CFRelease(channelBindings);
            if (identity != BID_C_NO_IDENTITY)
                CFRelease(identity);
            if (error != NULL)
                CFRelease(error);
        });
    });
}

BIDError
_BIDCachePerformBlock(
    BIDContext context,
    BIDCache cache,
    BIDError (^block)(BIDContext, BIDCache, CFStringRef, CFTypeRef))
{
    BIDError err;

    err = _BIDPerformCacheObjectsWithBlock(context, cache,
        ^(BIDContext context, BIDCache cache, const char *szKey, json_t *jsonObject) {
        BIDError err2;
        CFStringRef key = CFStringCreateWithCString(CFGetAllocator(cache), szKey, kCFStringEncodingASCII);

        if (key == NULL)
            return BID_S_NO_MEMORY;

        err2 = block(context, cache, key, jsonObject);

        CFRelease(key);

        return err2;
    });

    return err;
}
#endif /* __BLOCKS__ */

#define CF_CLASSIMPLEMENTATION(ClassName)                                       \
- (id)retain                                                                    \
{                                                                               \
    return CFRetain((CFTypeRef)self);                                           \
}                                                                               \
                                                                                \
- (oneway void)release                                                          \
{                                                                               \
    CFRelease((CFTypeRef)self);                                                 \
}                                                                               \
                                                                                \
- (NSUInteger)retainCount                                                       \
{                                                                               \
    return CFGetRetainCount((CFTypeRef)self);                                   \
}                                                                               \
                                                                                \
- (BOOL)isEqual:(id)anObject                                                    \
{                                                                               \
    if (anObject == nil)                                                        \
        return NO;                                                              \
    return CFEqual((CFTypeRef)self, (CFTypeRef)anObject);                       \
}                                                                               \
                                                                                \
- (NSUInteger)hash                                                              \
{                                                                               \
    return CFHash((CFTypeRef)self);                                             \
}                                                                               \
                                                                                \
- (BOOL)allowsWeakReference                                                     \
{                                                                               \
    return ![self _isDeallocating];                                             \
}                                                                               \
                                                                                \
- (BOOL)retainWeakReference                                                     \
{                                                                               \
    return [self _tryRetain];                                                   \
}                                                                               \
                                                                                \
- (BOOL)_isDeallocating                                                         \
{                                                                               \
    return _CFIsDeallocating((CFTypeRef)self);                                  \
}                                                                               \
                                                                                \
- (BOOL)_tryRetain                                                              \
{                                                                               \
    return _CFTryRetain((CFTypeRef)self) != NULL;                               \
}                                                                               \
                                                                                \
- (NSString *)description                                                       \
{                                                                               \
    return [NSMakeCollectable(CFCopyDescription((CFTypeRef)self)) autorelease]; \
}                                                                               \

/*
 * This is not a full Objective-C interface to BIDIdentity, it's just there so it
 * can be serialized. To make it fully toll free bridged would require all public
 * APIs to be instrumented so that subclasses can be invoked.
 */

@interface __BIDCFIdentity : NSObject
@end

@implementation __BIDCFIdentity

+ (id)allocWithZone:(NSZone *)zone
{
    static __BIDCFIdentity *placeholderField;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        if (placeholderField == nil)
            placeholderField = [super allocWithZone:zone];
    });

    return placeholderField;
}

CF_CLASSIMPLEMENTATION(__BIDCFIdentity)

- (BIDIdentity)_identity
{
    return (BIDIdentity)self;
}

- (CFTypeID)_cfTypeID
{
    return BIDIdentityGetTypeID();
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
    BIDIdentity identity = [self _identity];

    if (identity->Attributes != NULL)
        [coder encodeObject:identity->Attributes forKey:@"attributes"];
    if (identity->PrivateAttributes != NULL)
        [coder encodeObject:identity->PrivateAttributes forKey:@"privateAttributes"];
}

- (id)initWithCoder:(NSCoder *)coder
{
    BIDError err;
    BIDIdentity identity;
    NSDictionary *attributes;
    NSDictionary *privateAttributes;

    attributes = [coder decodeObjectOfClass:[NSDictionary class] forKey:@"attributes"];
    privateAttributes = [coder decodeObjectOfClass:[NSDictionary class] forKey:@"privateAttributes"];

    err = _BIDAllocIdentity(BID_C_NO_CONTEXT, attributes, &identity);
    if (err != BID_S_OK)
        return nil;

    if (privateAttributes)
        identity->PrivateAttributes = CFRetain(privateAttributes);

    self = (id)identity;

    return self;
}

@end

#endif /* HAVE_COREFOUNDATION_CFRUNTIME_H */
