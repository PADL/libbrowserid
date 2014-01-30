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
#include "bid_wk.h"

/*
 * AppKit/UIKit common code
 */

@interface BIDIdentityController ()
@property(nonatomic, retain, readwrite) NSString *assertion;
@property(nonatomic, readwrite) BIDContext bidContext;
@property(nonatomic, readwrite) BIDError bidError;
@end

@implementation BIDIdentityController
#pragma mark - accessors

- (void)dealloc
{
#if !__has_feature(objc_arc)
    [_audience release];
    [_claims release];
    [_emailHint release];
    [_siteName release];
    [_assertion release];
    _BIDReleaseModalSession(_bidContext, _bidModalSession);
    if (_bidContext)
        CFRelease(_bidContext);
#if TARGET_OS_IPHONE
    [_parentWindow release];
    [_webView release];
#else
    [_identityDialog release];
    [_parentWindow release];
    [_webView release];
#endif
#if TARGET_OS_IPHONE
    [_rls release];
#endif
#endif
    [super dealloc];
}

@synthesize claims = _claims;
@synthesize emailHint = _emailHint;
@synthesize siteName = _siteName;
@synthesize assertion = _assertion;

- (BIDContext)bidContext
{
    return _bidContext;
}

- (void)setBidContext:(BIDContext)bidContext
{
    if (bidContext != _bidContext) {
        if (_bidContext != NULL)
            CFRelease(_bidContext);
        _bidContext = (BIDContext)CFRetain(bidContext);
    }
}

@synthesize bidModalSession = _bidModalSession;
@synthesize bidError = _bidError;
@synthesize forceAuthentication = _forceAuthentication;
#if !TARGET_OS_IPHONE
@synthesize identityDialog = _identityDialog;
#endif
@synthesize parentWindow = _parentWindow;
@synthesize webView = _webView;

- (NSString *)audience
{
    return _audience;
}

- (void)setAudience:(NSString *)value
{
    if (value != _audience) {
        NSArray *princComponents;

        _audience = [value copy];

        princComponents = [_audience componentsSeparatedByString:@"/"];
        if ([princComponents count] > 1)
            self.siteName = [princComponents objectAtIndex:1];
        else
            self.siteName = _audience;
    }
}

#pragma mark - helpers

- (void)abortWithError:(NSError *)error
{
    if (error != nil &&
        ([[error domain] isEqualToString:NSURLErrorDomain]
#if !TARGET_OS_IPHONE
         || [[error domain] isEqualToString:WebKitErrorDomain]
#endif
        ))
        self.bidError = BID_S_HTTP_ERROR;
    else
        self.bidError = BID_S_INTERACT_FAILURE;

    [self closeIdentityDialog];
}

#pragma mark - javascript methods

- (void)identityCallback:(NSString *)anAssertion
              withParams:(id)BID_UNUSED params
{
    if ([anAssertion length])
        self.bidError = BID_S_OK;
    else
        self.bidError = BID_S_INTERACT_FAILURE;

    self.assertion = anAssertion;
    [self closeIdentityDialog];
}

#pragma mark - delegates

- (void)acquireAssertion:(id)sender
{
#if TARGET_OS_IPHONE
#define CONTROLLER_CLAIMS               "controller.claims()"
#else
#define CONTROLLER_CLAIMS               "JSON.parse(controller.claimsString())"
#endif

    NSString *function = @"                                                                             \
        var controller = window.IdentityController;                                                     \
        var options = { siteName: controller.siteName(),                                                \
                        experimental_forceAuthentication: !!controller.forceAuthentication(),           \
                        experimental_emailHint: controller.emailHint(),                                 \
                        experimental_voluntaryScopes: [ '*' ],                                          \
                        experimental_userAssertedClaims: " CONTROLLER_CLAIMS "                          \
        };                                                                                              \
                                                                                                        \
        BrowserID.internal.get(                                                                         \
            controller.audience(),                                                                      \
            function(assertion, params) {                                                               \
                controller.identityCallback(assertion, params);                                         \
            },                                                                                          \
            options);                                                                                   \
    ";

    [self showIdentityDialog];

    [sender stringByEvaluatingJavaScriptFromString:function];
}

#pragma mark - public
- (id)init
{
    self.bidError = BID_S_INTERACT_FAILURE;

    return [super init];
}

- (instancetype)initWithContext:(BIDContext)bidContext audience:(NSString *)anAudience claims:(NSDictionary *)someClaims
{
    self = [self init];

    if (self != nil) {
        self.bidContext = bidContext;
        self.audience = anAudience;
        self.claims = someClaims;
    }

    return self;
}

- (BIDError)getAssertion
{
    self.webView = [self dispenseWebView];

    [self loadIdentityDialog];

    return self.bidError;
}

- (void)_completeModalSession
{
    char *szAssertion = NULL;

    if (self.bidError == BID_S_OK)
        szAssertion = json_string_copy((__bridge json_t *)self.assertion);

    _BIDCompleteModalSession(self.bidContext, self.bidError, szAssertion, &_bidModalSession);

    BIDFree(szAssertion);
}

@end

static void
_BIDBrowserGetAssertion_FinalizeUIContext(
    BIDContext context BID_UNUSED,
    void *data)
{
    CFBridgingRelease((__bridge id)data);
}

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags BID_UNUSED,
    BIDModalSession modalSession)
{
    BIDIdentityController *controller = nil;

    @autoreleasepool {
#if !TARGET_OS_IPHONE
#ifdef GSSBID_DEBUG
        /*
         * Only applications that are NSApplicationActivationPolicyRegular or
         * NSApplicationActivationPolicyAccessory can interact with the user.
         * Don't try to show UI if this is not the case, unless building with
         * compile time debugging.
         */
        if ([NSApp activationPolicy] == NSApplicationActivationPolicyProhibited ||
            ![NSApp isRunning]) {
            ProcessSerialNumber psn = { 0, kCurrentProcess };
            TransformProcessType(&psn, kProcessTransformToUIElementApplication);
        }
#endif /* GSSBID_DEBUG */

        if ([NSApp activationPolicy] == NSApplicationActivationPolicyProhibited ||
            !NSApplicationLoad())
            return BID_S_INTERACT_UNAVAILABLE;
#endif /* !TARGET_OS_IPHONE */

        controller = [[BIDIdentityController alloc] initWithContext:context
                                                           audience:[NSString stringWithUTF8String:szAudienceOrSpn]
                                                             claims:(__bridge NSDictionary *)claims];
        controller.bidContext = context;
        controller.bidModalSession = modalSession;
        if (szIdentityName != NULL)
            controller.emailHint = [NSString stringWithUTF8String:szIdentityName];
        if (context->ParentWindow != NULL)
            controller.parentWindow = (__bridge id)context->ParentWindow;
        else
#if TARGET_OS_IPHONE
            controller.parentWindow = [UIApplication sharedApplication].keyWindow;
#else
            controller.parentWindow = [NSApplication sharedApplication].mainWindow;
#endif
        controller.forceAuthentication = !!(ulReqFlags & BID_ACQUIRE_FLAG_FORCE_AUTH);

        [controller performSelectorOnMainThread:@selector(getAssertion) withObject:nil waitUntilDone:TRUE];

        _BIDSetModalSessionUIContext(context, modalSession, (void *)CFBridgingRetain(controller), _BIDBrowserGetAssertion_FinalizeUIContext);
    }

    return BID_S_OK;
}

BIDError
_BIDRunModalSession(
    BIDContext context,
    BIDModalSession *pModalSession)
{
    BIDIdentityController *controller = _BIDGetModalSessionUIContext(context, *pModalSession);

    [controller performSelectorOnMainThread:@selector(_runModal) withObject:nil waitUntilDone:TRUE];

    *pModalSession = controller.bidModalSession;
    BID_ASSERT(*pModalSession == NULL);

    return BID_S_OK;
}
