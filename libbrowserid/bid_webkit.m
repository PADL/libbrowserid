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

#include <AppKit/AppKit.h>
#include <WebKit/WebKit.h>

#include "bid_private.h"
#include "bid_json.h"

@interface BIDIdentityDialog : NSPanel
+ (BIDIdentityDialog *)identityDialog;
@end

@implementation BIDIdentityDialog
+ (BIDIdentityDialog *)identityDialog
{
    return [[[self alloc] init] autorelease];
}

- (id)init
{
    NSRect frame = NSMakeRect(0, 0, 700, 375);
    NSUInteger styleMask = NSTitledWindowMask | NSClosableWindowMask | NSUtilityWindowMask;
    NSRect rect = [NSPanel contentRectForFrameRect:frame styleMask:styleMask];

    self = [super initWithContentRect:rect styleMask:styleMask backing:NSBackingStoreBuffered defer:YES];

    [self setHidesOnDeactivate:YES];
    [self setWorksWhenModal:YES];

    return self;
}

- (BOOL)acceptsFirstResponder
{
    return YES;
}

- (BOOL)canBecomeKeyWindow
{
    return YES;
}

- (BOOL)canBecomeMainWindow
{
    return YES;
}
@end

@interface BIDIdentityController : NSObject <NSWindowDelegate>
{
@private
    NSString *audience;
    NSDictionary *claims;
    NSString *servicePrincipalName;
    NSString *requiredEmail;
    NSString *siteName;
    BOOL canInteract;
    BOOL silent;
    NSString *assertion;
    BIDIdentityDialog *identityDialog;
    WebView *webView;
    NSWindow *parentWindow;
    BIDError bidError;
}

/* accessors */
- (void)setAudience:(NSString *)value;
- (NSString *)audience;

- (void)setClaims:(NSDictionary *)value;
- (NSDictionary *)claims;

- (void)setServicePrincipalName:(NSString *)value;
- (NSString *)servicePrincipalName;

- (void)setRequiredEmail:(NSString *)value;
- (NSString *)requiredEmail;

- (void)setAssertion:(NSString *)value;
- (NSString *)assertion;

- (BOOL)canInteract;
- (void)setCanInteract:(BOOL)value;

- (BOOL)silent;
- (void)setSilent:(BOOL)value;

- (NSWindow *)parentWindow;
- (void)setParentWindow:(NSWindow *)value;

- (BIDError)bidError;

/* helpers */
- (void)closeIdentityDialog;
- (void)abortWithError:(NSError *)error;
- (void)identityCallback:(NSString *)assertion withParameters:(id)parameters;
- (void)interposeAssertionSign:(WebView *)sender;
- (void)acquireAssertion:(WebView *)webView;
- (WebView *)newWebView;

- (void)fillFormWithDefaultEmail:(WebView *)sender;

/* public interface */
- (BIDError)getAssertion;
- (id)initWithAudience:(NSString *)anAudience claims:(NSDictionary *)someClaims;
@end

@implementation BIDIdentityController

#pragma mark - accessors

- (NSString *)audience
{
    return [[audience retain] autorelease];
}

- (void)setAudience:(NSString *)value
{
    if (value != audience) {
        [audience release];
        audience = [value retain];
    }
}

- (NSDictionary *)claims
{
    return [[claims retain] autorelease];
}

- (void)setClaims:(NSDictionary *)value
{
    if (value != claims) {
        [claims release];
        claims = [value retain];
    }
}

- (NSString *)servicePrincipalName
{
    return [[servicePrincipalName retain] autorelease];
}

- (void)setServicePrincipalName:(NSString *)value
{
    if (value != servicePrincipalName) {
        NSArray *princComponents;

        [servicePrincipalName release];
        servicePrincipalName = [value retain];

        princComponents = [servicePrincipalName componentsSeparatedByString:@"/"];
        if ([princComponents count] > 1)
            siteName = [[princComponents objectAtIndex:1] retain];
        else
            siteName = [servicePrincipalName retain];
    }
}

- (NSString *)requiredEmail
{
    return [[requiredEmail retain] autorelease];
}

- (void)setRequiredEmail:(NSString *)value
{
    if (value != requiredEmail) {
        [requiredEmail release];
        requiredEmail = [value retain];
    }
}

- (BOOL)canInteract
{
    return canInteract;
}

- (void)setCanInteract:(BOOL)value
{
    canInteract = value;
}

- (BOOL)silent
{
    return silent;
}

- (void)setSilent:(BOOL)value
{
    silent = value;
}

- (NSString *)assertion
{
    return [[assertion retain] autorelease];
}

- (void)setAssertion:(NSString *)value
{
    if (value != assertion) {
        [assertion release];
        assertion = [value retain];
    }
}

- (BIDError)bidError
{
    return bidError;
}

- (NSWindow *)parentWindow
{
    return parentWindow;
}

- (void)setParentWindow:(NSWindow *)value
{
    if (value != parentWindow) {
        [parentWindow release];
        parentWindow = [value retain];
    }
}

#pragma mark - helpers

- (WebView *)newWebView
{
    NSRect frame = NSMakeRect(0, 0, 700, 375);
    WebView *aWebView = [[[WebView alloc] initWithFrame:frame] autorelease];

    [aWebView setFrameLoadDelegate:self];
    [aWebView setResourceLoadDelegate:self];
    [aWebView setUIDelegate:self];
    [aWebView setPolicyDelegate:self];
    [aWebView setHostWindow:identityDialog];
    [aWebView setShouldCloseWithWindow:YES];

    return aWebView;
}

- (void)closeIdentityDialog
{
    [identityDialog close];
}

- (void)abortWithError:(NSError *)error
{
    if (error != nil &&
        ([[error domain] isEqualToString:NSURLErrorDomain] ||
         [[error domain] isEqualToString:WebKitErrorDomain]))
        bidError = BID_S_HTTP_ERROR;
    else
        bidError = BID_S_INTERACT_FAILURE;

    [self closeIdentityDialog];
}

#pragma mark - javascript methods

- (void)identityCallback:(NSString *)anAssertion withParameters:(id)parameters
{
    if (anAssertion != nil)
        bidError = BID_S_OK;
    else if ([self silent])
        bidError = BID_S_INTERACT_REQUIRED;
    else
        bidError = BID_S_INTERACT_FAILURE;

    if (bidError == BID_S_INTERACT_REQUIRED && canInteract) {
        [self setSilent:NO];
        [self acquireAssertion:webView];
    } else {
        [self setAssertion:anAssertion];
        [self closeIdentityDialog];
    }
}

#pragma mark - delegates

+ (BOOL)isKeyExcludedFromWebScript:(const char *)property
{
    if (strcmp(property, "siteName") == 0               ||
        strcmp(property, "servicePrincipalName") == 0   ||
        strcmp(property, "claims") == 0                 ||
        strcmp(property, "silent") == 0                 ||
        strcmp(property, "canInteract") == 0            ||
        strcmp(property, "requiredEmail") == 0          ||
        strcmp(property, "audience") == 0)
        return NO;

    return YES;
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)selector
{
    if (selector == @selector(identityCallback:withParameters:))
        return NO;

    return YES;
}

- (void)windowWillClose:(NSNotification *)notification
{
    [NSApp stopModal];
}

- (void)interposeAssertionSign:(WebView *)sender
{
    NSString *function = @"                                                                             \
        var controller = window.IdentityController;                                                     \
        var oldLoad = BrowserID.CryptoLoader.load;                                                      \
                                                                                                        \
        BrowserID.CryptoLoader.load = function(onSuccess, onFailure) {                                  \
            oldLoad(function(jwCrypto) {                                                                \
                var assertionSign = jwCrypto.assertion.sign;                                            \
                                                                                                        \
                jwCrypto.assertion.sign = function(payload, assertionParams, secretKey, cb) {           \
                    var gssPayload = JSON.parse(controller.claims.stringRepresentation());              \
                    for (var k in payload) {                                                            \
                        if (payload.hasOwnProperty(k)) gssPayload[k] = payload[k];                      \
                    }                                                                                   \
                    assertionSign(gssPayload, assertionParams, secretKey, cb);                          \
                };                                                                                      \
                onSuccess(jwCrypto);                                                                    \
            }, onFailure);                                                                              \
        };                                                                                              \
    ";

    [sender stringByEvaluatingJavaScriptFromString:function];
}

- (void)fillFormWithDefaultEmail:(WebView *)sender
{
    if (requiredEmail != nil) {
        DOMHTMLInputElement *email = (DOMHTMLInputElement *)[[[sender mainFrame] DOMDocument] getElementById:@"authentication_email"];
        [email setValue:requiredEmail];
    }
}

- (void)acquireAssertion:(WebView *)sender
{
    NSString *function = @"                                                                             \
        var controller = window.IdentityController;                                                     \
        var options = { siteName: controller.siteName, silent: controller.silent,                       \
                        requiredEmail: controller.requiredEmail };                                      \
                                                                                                        \
        if (controller.servicePrincipalName) {                                                          \
            BrowserID.User.getHostname = function() { return controller.servicePrincipalName; };        \
        }                                                                                               \
                                                                                                        \
        BrowserID.internal.setPersistent(                                                               \
            controller.audience,                                                                        \
            function() {                                                                                \
                BrowserID.internal.get(                                                                 \
                    controller.audience,                                                                \
                    function(assertion, params) {                                                       \
                        controller.identityCallback_withParameters_(assertion, params);                 \
                    },                                                                                  \
                    options);                                                                           \
        });                                                                                             \
    ";

    [sender stringByEvaluatingJavaScriptFromString:function];

    if (![self silent]) {
        [self fillFormWithDefaultEmail:sender];
        [identityDialog makeFirstResponder:sender];
        [identityDialog setContentView:sender];
        [identityDialog makeKeyAndOrderFront:sender];
        [identityDialog center];
    }
}

- (void)webView:(WebView *)webView addMessageToConsole:(NSDictionary *)message
{
    NSLog(@"%@", message);
}

- (void)webView:(WebView *)sender didFinishLoadForFrame:(WebFrame *)frame
{
    if ([sender isEqual:webView] && frame == [sender mainFrame]) {
        if ([claims count])
            [self interposeAssertionSign:sender];
        [self acquireAssertion:sender];
    }
}

- (void)webView:(WebView *)sender windowScriptObjectAvailable:(WebScriptObject *)windowScriptObject
{
    [windowScriptObject setValue:self forKey:@"IdentityController"];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailLoadWithError:%@ forFrame:%@", [sender description], [error description], [frame name]);
    if ([error code] == NSURLErrorCancelled)
        return;
    else
        [self abortWithError:error];
}

- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailProvisionalLoadWithError:%@ forFrame:%@", [sender description], [error description], [frame name]);
    [self abortWithError:error];
}

- (void)webView:(WebView *)sender decidePolicyForNavigationAction:(NSDictionary *)actionInformation request:(NSURLRequest *)request frame:(WebFrame *)frame decisionListener:(id<WebPolicyDecisionListener>)listener
{
#if 0
    NSLog(@"webView:%@ decidePolicyForNavigationAction:%@ request:%@ frame:%@ decisionListener:%@", sender, [actionInformation objectForKey:WebActionOriginalURLKey], request, [frame name], listener);
#endif
    [listener use];
}

- (void)webView:(WebView *)sender decidePolicyForNewWindowAction:(NSDictionary *)actionInformation request:(NSURLRequest *)request newFrameName:(NSString *)frameName decisionListener:(id<WebPolicyDecisionListener>)listener
{
    NSLog(@"webView:%@ decidePolicyForNewWindowAction:%@ request:%@ frame:%@", sender, [actionInformation objectForKey:WebActionOriginalURLKey], request, frameName);
    if ([actionInformation objectForKey:WebActionElementKey]) {
        [listener ignore];
        [[NSWorkspace sharedWorkspace] openURL:[request URL]];
    } else {
        [listener use];
    }
}

#if 0
- (WebView *)webView:(WebView *)sender createWebViewWithRequest:(NSURLRequest *)request
{
    WebView *aWebView = [self newWebView];

    NSLog(@"createWebViewWithRequest %@", request);
    [identityDialog setContentView:aWebView];

    return aWebView;
}
#endif

#pragma mark - public
- (id)init
{
    audience = nil;
    servicePrincipalName = nil;
    requiredEmail = nil;
    siteName = nil;
    assertion = nil;
    identityDialog = nil;
    webView = nil;
    parentWindow = nil;
    bidError = BID_S_INTERACT_FAILURE;

    return [super init];
}

- (id)initWithAudience:(NSString *)anAudience claims:(NSDictionary *)someClaims
{
    self = [self init];

    [self setAudience:anAudience];
    [self setClaims:someClaims];

    return self;
}

- (void)dealloc
{
    [super dealloc];

    [audience release];
    [servicePrincipalName release];
    [requiredEmail release];
    [siteName release];
    [assertion release];
    [identityDialog release];
    [webView release];
}

- (BIDError)getAssertion
{
    NSApplication *app = [NSApplication sharedApplication];
    NSURL *personaURL = [NSURL URLWithString:@BID_SIGN_IN_URL];

    if ([self audience] == nil)
        return (bidError = BID_S_INVALID_AUDIENCE_URN);

    if ([self canInteract] == NO && [self silent] == NO)
        return (bidError = BID_S_INTERACT_REQUIRED);

    identityDialog = [[BIDIdentityDialog identityDialog] retain];
    [identityDialog setDelegate:self];
    if ([self silent])
        [identityDialog orderOut:nil];
    if (parentWindow != nil)
        [identityDialog setParentWindow:parentWindow];

    webView = [[self newWebView] retain];
    [[webView mainFrame] loadRequest:[NSURLRequest requestWithURL:personaURL]];

    [app runModalForWindow:identityDialog];

    return bidError;
}

@end

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    char **pAssertion)
{
    BIDError err = BID_S_INTERACT_FAILURE;
    BIDIdentityController *controller = nil;

    *pAssertion = NULL;

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

    @autoreleasepool {
        NSDictionary *claimsDict = [[BIDJsonDictionary alloc] initWithJsonObject:claims];

        controller = [[BIDIdentityController alloc] initWithAudience:[NSString stringWithUTF8String:szPackedAudience] claims:claimsDict];
        if (context->ContextOptions & BID_CONTEXT_GSS)
            [controller setServicePrincipalName:[NSString stringWithUTF8String:szAudienceOrSpn]];
        if (szIdentityName != NULL) {
            [controller setRequiredEmail:[NSString stringWithUTF8String:szIdentityName]];
            [controller setSilent:!!(context->ContextOptions & BID_CONTEXT_BROWSER_SILENT)];
        }
        if (context->ParentWindow != NULL)
            [controller setParentWindow:context->ParentWindow];
        [controller setCanInteract:_BIDCanInteractP(context, ulReqFlags)];
        [controller performSelectorOnMainThread:@selector(getAssertion) withObject:nil waitUntilDone:TRUE];

        err = [controller bidError];
        if (err == BID_S_OK)
            err = _BIDDuplicateString(context, [[controller assertion] cString], pAssertion);

        [controller release];
    }

    return err;
}
