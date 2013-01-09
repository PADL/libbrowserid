/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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

    NSLog(@"BrowserID_mechanismName %@ self %@", realMechName, self);

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

        NSLog(@"BrowserID_authenticationMechanisms: %@", rewrittenMechs);

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
    NSLog(@"BrowserIDHelper load");
}
@end
