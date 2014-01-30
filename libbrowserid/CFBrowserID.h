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

#ifndef _CFBROWSERID_H_
#define _CFBROWSERID_H_ 1

#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
extern "C" {
#endif

CFTypeID
BIDIdentityGetTypeID(void);

CFTypeID
BIDContextGetTypeID(void);

CFTypeID
BIDCacheGetTypeID(void);

BIDContext
BIDContextCreate(
    CFAllocatorRef allocator,
    CFStringRef configFile,
    uint32_t ulContextOptions,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

CFStringRef
BIDAssertionCreateUI(
    BIDContext context,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFStringRef optionalIdentity,
    uint32_t ulFlags,
    BIDIdentity *pAssertedIdentity,
    uint32_t *pulFlags,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

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
    CFErrorRef *pError) CF_RETURNS_RETAINED;

#if __BLOCKS__
BIDError
BIDAssertionCreateUIWithHandler(
    BIDContext context,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFStringRef optionalIdentity,
    uint32_t ulFlags,
    CFDictionaryRef userClaims,
    void (^completionHandler)(CFStringRef assertion, BIDIdentity identity, CFErrorRef error));
#endif

BIDIdentity
BIDIdentityCreateFromString(
    BIDContext context,
    CFStringRef assertion,
    uint32_t ulFlags,
    uint32_t *pulFlags,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

BIDIdentity
BIDIdentityCreateByVerifyingAssertion(
    BIDContext context,
    CFStringRef assertion,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFAbsoluteTime verificationTime,
    uint32_t ulReqFlags,
    uint32_t *pulVerifyFlags,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

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
    void (^handler)(BIDIdentity, uint32_t, CFErrorRef));
#endif

extern const CFStringRef kBIDIdentitySubjectKey;
extern const CFStringRef kBIDIdentityIssuerKey;
extern const CFStringRef kBIDIdentityExpiryTimeKey;
extern const CFStringRef kBIDIdentityIssuedAtKey;
extern const CFStringRef kBIDIdentityPublicKeyKey;
extern const CFStringRef kBIDIdentityPrincipalKey;

CFTypeRef
BIDIdentityCopyAttributeValue(
    BIDIdentity identity,
    CFStringRef attribute) CF_RETURNS_RETAINED;

CFAbsoluteTime
BIDIdentityGetExpiryTime(
    BIDIdentity identity);

CFDictionaryRef
BIDIdentityCopyAttributeDictionary(
    BIDIdentity identity) CF_RETURNS_RETAINED;

BIDReplayCache
BIDReplayCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

BIDTicketCache
BIDTicketCacheCreate(
    BIDContext context,
    CFStringRef cacheName,
    CFErrorRef *pError) CF_RETURNS_RETAINED;

#if 0
BIDError
_BIDCachePerformBlock(
    BIDContext context,
    BIDCache cache,
    BIDError (^block)(BIDContext, BIDCache, CFStringRef, CFTypeRef));
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CFBROWSERID_H_ */
