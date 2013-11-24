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

const CFStringRef kBIDIdentityAudienceKey   = CFSTR("aud");
const CFStringRef kBIDIdentitySubjectKey    = CFSTR("sub");
const CFStringRef kBIDIdentityIssuerKey     = CFSTR("iss");
const CFStringRef kBIDIdentityExpiryTimeKey = CFSTR("exp");
const CFStringRef kBIDIdentityIssuedAtKey   = CFSTR("iat");
const CFStringRef kBIDIdentityPublicKeyKey  = CFSTR("public-key");
const CFStringRef kBIDIdentityPrincipalKey  = CFSTR("principal");

static CFTypeID _BIDIdentityTypeID = _kCFRuntimeNotATypeID;
static CFTypeID _BIDContextTypeID = _kCFRuntimeNotATypeID;
static CFTypeID _BIDCacheTypeID = _kCFRuntimeNotATypeID;

static void
_BIDCFInit(void) __attribute__((__constructor__));

static CFStringRef
_BIDIdentityCopyDebugDescription(CFTypeRef cf);

static CFErrorRef
_BIDCFMapError(BIDError err);

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
    _BIDContextTypeID = _CFRuntimeRegisterClass(&_BIDContextClass);
    _BIDCacheTypeID = _CFRuntimeRegisterClass(&_BIDCacheClass);
}

CFTypeID
BIDIdentityGetTypeID(void)
{
    return _BIDIdentityTypeID;
}

CFTypeID
BIDContextGetTypeID(void)
{
    return _BIDContextTypeID;
}

CFTypeID
BIDCacheGetTypeID(void)
{
    return _BIDCacheTypeID;
}

static CFErrorRef
_BIDCFMapError(BIDError err)
{
    CFErrorRef cfError = NULL;
    CFDictionaryRef cfDict = NULL;
    const char *szErr = NULL;

    BIDErrorToString(err, &szErr);

    if (szErr != NULL) {
        CFStringRef errDesc;

        errDesc = CFStringCreateWithCString(kCFAllocatorDefault, szErr, kCFStringEncodingASCII);
        cfDict = CFDictionaryCreate(kCFAllocatorDefault,
                                    (const void **)&kCFErrorDescriptionKey,
                                    (const void **)&errDesc,
                                    1,
                                    &kCFTypeDictionaryKeyCallBacks,
                                    &kCFTypeDictionaryValueCallBacks);
        CFRelease(errDesc);
    }

    cfError = CFErrorCreate(kCFAllocatorDefault, CFSTR("com.padl.BrowserID"), err, cfDict);

    if (cfDict != NULL)
        CFRelease(cfDict);

    return cfError;
}

BIDContext
BIDContextCreate(
    CFStringRef configFile,
    uint32_t ulContextOptions,
    CFErrorRef *pError)
{
    BIDError err;
    BIDContext context;
    const char *szConfigFile;

    szConfigFile = CFStringGetCStringPtr(configFile, kCFStringEncodingUTF8);

    err = BIDAcquireContext(szConfigFile, ulContextOptions, NULL, &context);
    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(err);

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
    const char *szAssertion = NULL;
    const char *szAudienceOrSpn = NULL;
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

    szAssertion = CFStringGetCStringPtr(assertion, kCFStringEncodingASCII);
    if (audienceOrSpn != NULL)
        szAudienceOrSpn = CFStringGetCStringPtr(audienceOrSpn, kCFStringEncodingUTF8);
    if (channelBindings != NULL) {
        pbChannelBindings = CFDataGetBytePtr(channelBindings);
        cbChannelBindings = CFDataGetLength(channelBindings);
    }

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE, szAssertion,
                             szAudienceOrSpn, pbChannelBindings, cbChannelBindings,
                             verificationTime + kCFAbsoluteTimeIntervalSince1970,
                             ulReqFlags, &identity, &expiryTime, pulVerifyFlags);
                             
    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(err);

    return identity;
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
    void (^func)(BIDIdentity, uint32_t, CFErrorRef))
{
    void (^callback)(BIDIdentity, uint32_t, CFErrorRef);

    callback = Block_copy(func);
    CFRetain(context);
    CFRetain(assertion);
    if (channelBindings != NULL)
        CFRetain(channelBindings);

    dispatch_async(queue, ^{
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
        callback(identity, ulVerifyFlags, error);

        CFRelease(assertion);
        CFRelease(context);
        if (channelBindings != NULL)
            CFRelease(channelBindings);
        if (identity != NULL)
            CFRelease(identity);
        if (error != NULL)
            CFRelease(error);
    });
}
#endif /* __BLOCKS __ */

static CFStringRef
_BIDIdentityCopyDebugDescription(
    CFTypeRef cf)
{
    return BIDIdentityCopyAttribute((BIDIdentity)cf, CFSTR("sub"));
}

BIDIdentity
BIDIdentityCreateFromString(
    BIDContext context,
    CFStringRef assertion,
    uint32_t ulReqFlags,
    uint32_t *pulRetFlags,
    CFErrorRef *pError)
{
    const char *szAssertion;
    time_t expiryTime;
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;

    if (pulRetFlags != NULL)
        *pulRetFlags = 0;
    if (pError != NULL)
        *pError = NULL;

    if (assertion == NULL)
        return NULL;

    szAssertion = CFStringGetCStringPtr(assertion, kCFStringEncodingASCII);

    err = BIDAcquireAssertionFromString(context, szAssertion, ulReqFlags,
                                        &identity, &expiryTime, pulRetFlags);

    if (err != BID_S_OK && pError != NULL)
        *pError = _BIDCFMapError(err);

    return (err == BID_S_OK) ? identity : NULL;
}

CFTypeRef
BIDIdentityCopyAttribute(
    BIDIdentity identity,
    CFStringRef attribute)
{
    CFDictionaryRef dict;
    CFTypeRef value;

    dict = BIDIdentityCopyAttributeDictionary(identity);
    if (dict == NULL)
        return NULL;

    value = CFDictionaryGetValue(dict, attribute);

    CFRelease(dict);

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
    const char *szAudienceOrSpn = NULL;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    const char *szIdentity = NULL;
    char *szAssertion = NULL;
    CFStringRef assertion;
    time_t expiryTime;
    BIDError err;

    if (pulFlags != NULL)
        *pulFlags = 0;
    if (pError != NULL)
        *pError = NULL;

    if (audienceOrSpn != NULL)
        szAudienceOrSpn = CFStringGetCStringPtr(audienceOrSpn, kCFStringEncodingUTF8);
    if (channelBindings != NULL) {
        pbChannelBindings = CFDataGetBytePtr(channelBindings);
        cbChannelBindings = CFDataGetLength(channelBindings);
    }
    if (optionalIdentity != NULL)
        szIdentity = CFStringGetCStringPtr(optionalIdentity, kCFStringEncodingUTF8);

    err = BIDAcquireAssertion(context, BID_C_NO_TICKET_CACHE, szAudienceOrSpn,
                              pbChannelBindings, cbChannelBindings, szIdentity,
                              ulFlags, &szAssertion, pAssertedIdentity,
                              &expiryTime, pulFlags);
    if (err != BID_S_OK && pError != NULL) {
        *pError = _BIDCFMapError(err);
        return NULL;
    }

    assertion = CFStringCreateWithCString(kCFAllocatorDefault, szAssertion, kCFStringEncodingASCII);
    BIDFree(szAssertion);

    return assertion;
}

BIDTicketCache
BIDTicketCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError)
{
    BIDError err;
    const char *szCacheName;
    BIDTicketCache ticketCache = BID_C_NO_TICKET_CACHE;

    if (pError != NULL)
        *pError = NULL;

    szCacheName = CFStringGetCStringPtr(cacheName, kCFStringEncodingUTF8);

    err = BIDAcquireTicketCache(context, szCacheName, &ticketCache);
    if (err != BID_S_OK && pError != NULL) {
        *pError = _BIDCFMapError(err);
        return BID_C_NO_TICKET_CACHE;
    }

    return ticketCache;
}

BIDReplayCache
BIDReplayCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError)
{
    BIDError err;
    const char *szCacheName;
    BIDReplayCache replayCache = BID_C_NO_REPLAY_CACHE;

    if (pError != NULL)
        *pError = NULL;

    szCacheName = CFStringGetCStringPtr(cacheName, kCFStringEncodingUTF8);

    err = BIDAcquireReplayCache(context, szCacheName, &replayCache);
    if (err != BID_S_OK && pError != NULL) {
        *pError = _BIDCFMapError(err);
        return BID_C_NO_REPLAY_CACHE;
    }

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
