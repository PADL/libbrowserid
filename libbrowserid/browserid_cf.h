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

#ifndef _BROWSERID_CF_H_
#define _BROWSERID_CF_H_ 1

#include <CoreFoundation/CoreFoundation.h>

CFTypeID
BIDIdentityGetTypeID(void);

CFTypeID
BIDContextGetTypeID(void);

CFTypeID
BIDCacheGetTypeID(void);

BIDContext
BIDContextCreate(
    CFStringRef configFile,
    uint32_t ulContextOptions);

CFStringRef
BIDAssertionCreateUI(
    BIDContext context,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFStringRef optionalIdentity,
    uint32_t ulFlags,
    BIDIdentity *pAssertedIdentity,
    CFAbsoluteTime *pExpiryTime,
    uint32_t *pulFlags);

BIDIdentity
BIDIdentityCreateFromString(
    BIDContext context,
    CFStringRef assertion,
    uint32_t ulFlags,
    CFAbsoluteTime *pExpiryTime,
    uint32_t *pulFlags);

BIDIdentity
BIDIdentityFromVerifyingAssertion(
    BIDContext context,
    CFStringRef assertion,
    CFStringRef audienceOrSpn,
    CFDataRef channelBindings,
    CFAbsoluteTime verificationTime,
    uint32_t ulReqFlags,
    CFAbsoluteTime *pExpiryTime,
    uint32_t *pulVerifyFlags);

CFTypeRef
BIDIdentityCopyAttribute(
    BIDContext context,
    BIDIdentity identity,
    CFStringRef attribute);

CFDictionaryRef
BIDIdentityCopyAttributeDictionary(
    BIDContext context,
    BIDIdentity identity);

#endif /* _BROWSERID_CF_H_ */
