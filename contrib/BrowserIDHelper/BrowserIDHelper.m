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

/*
 * This program is a Mail.app bundle designed to fool it into thinking that
 * BrowserID is actually the GSSAPI Kerberos mechanism.
 */

#include <Foundation/Foundation.h>
#include <objc/Runtime.h>

#include "MailInternal.h"

static NSString *kBrowserIDSASLMechanism = @"BROWSERID-AES128";
static NSString *kGSSAPISASLMechanism = @"GSSAPI";

static void
BrowserIDInterpose(
    Class class,
    SEL originalSelector,
    SEL newSelector,
    BOOL isClassMethod)
{
    Method originalMethod = isClassMethod ? class_getClassMethod(class, originalSelector) : class_getInstanceMethod(class, originalSelector);
    Method categoryMethod = isClassMethod ? class_getClassMethod(class, newSelector) : class_getInstanceMethod(class, newSelector);
    method_exchangeImplementations(originalMethod, categoryMethod);
}

@interface SASLClient (BrowserIDInterposing)
+ BrowserID_newSASLClientWithMechanismName:mechName account:account externalSecurityLayer:(unsigned int)ssf;
- (NSString *)BrowserID_mechanismName;
@end

@implementation SASLClient (BrowserIDInterposing)
+ (void)load
{
    BrowserIDInterpose([SASLClient class],
                       @selector(newSASLClientWithMechanismName:account:externalSecurityLayer:),
                       @selector(BrowserID_newSASLClientWithMechanismName:account:externalSecurityLayer:),
                       YES);
    BrowserIDInterpose([SASLClient class],
                       @selector(mechanismName),
                       @selector(BrowserID_mechanismName),
                       NO);
}

+ BrowserID_newSASLClientWithMechanismName:mechName account:account externalSecurityLayer:(unsigned int)ssf
{
    NSString *newMechName;

    if ([mechName isEqualToString:kGSSAPISASLMechanism])
        newMechName = kBrowserIDSASLMechanism;
    else
        newMechName = mechName;

    NSLog(@"BrowserID_newSASLClientWithMechanismName:%@", newMechName);

    return [SASLClient BrowserID_newSASLClientWithMechanismName:newMechName account:account externalSecurityLayer:ssf];
}

- (NSString *)BrowserID_mechanismName
{
    NSString *realMechName = [self BrowserID_mechanismName];

#if 0
    if ([realMechName isEqual:kBrowserIDSASLMechanism])
        return kGSSAPISASLMechanism;
#endif

    return realMechName;
}
@end

@interface IMAPConnection (BrowserIDInterposing)
- BrowserID_authenticationMechanisms;
@end

@implementation IMAPConnection (BrowserIDInterposing)
+ (void)load
{
    BrowserIDInterpose([IMAPConnection class],
                       @selector(authenticationMechanisms),
                       @selector(BrowserID_authenticationMechanisms),
                       NO);
}

- BrowserID_authenticationMechanisms
{
    id mechs = [self BrowserID_authenticationMechanisms];

    if ([mechs containsObject:kBrowserIDSASLMechanism]) {
        NSMutableArray *rewrittenMechs = [NSMutableArray arrayWithArray:mechs];
        NSUInteger index;

        index = [rewrittenMechs indexOfObject:kGSSAPISASLMechanism];
        if (index != NSNotFound) {
            [rewrittenMechs removeObject:kBrowserIDSASLMechanism];
            [rewrittenMechs replaceObjectAtIndex:index withObject:kBrowserIDSASLMechanism];
        }

        return rewrittenMechs;
    }

    return mechs;
}
@end

@interface BrowserIDHelper : NSObject
@end

@implementation BrowserIDHelper
+ (void)load
{
}
@end
