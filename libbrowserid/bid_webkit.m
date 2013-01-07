/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#ifdef __APPLE__

#include <AppKit/AppKit.h>
#include <WebKit/WebKit.h>

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
    NSUInteger styleMask = NSTitledWindowMask | NSUtilityWindowMask;
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

- (BIDError)bidError;

/* helpers */
- (void)closeIdentityDialog;
- (void)abortWithError:(NSError *)error;
- (void)identityCallback:(NSString *)assertion withParameters:(id)parameters;
- (void)acquireAssertion:(WebView *)webView;
- (WebView *)newWebView;

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
    [NSApp stopModal];
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

- (void)acquireAssertion:(WebView *)sender
{
    NSString *function = @"                                                                             \
        var jwcrypto = require('./lib/jwcrypto');                                                       \
        var assertionSign = jwcrypto.assertion.sign;                                                    \
        var controller = window.IdentityController;                                                     \
        var options = { siteName: controller.siteName, silent: controller.silent, requiredEmail: controller.requiredEmail };           \
                                                                                                        \
        jwcrypto.assertion.sign = function(payload, assertionParams, secretKey, cb) {                   \
            var gssPayload = JSON.parse(controller.claims.stringRepresentation());                      \
            for (var k in payload) {                                                                    \
                if (payload.hasOwnProperty(k)) gssPayload[k] = payload[k];                              \
            }                                                                                           \
            assertionSign(gssPayload, assertionParams, secretKey, cb);                                  \
        };                                                                                              \
                                                                                                        \
        BrowserID.User.getHostname = function() { return controller.servicePrincipalName; };            \
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

    if (!silent) {
        [identityDialog makeFirstResponder:sender];
        [identityDialog setContentView:sender];
        [identityDialog makeKeyAndOrderFront:nil];
        [identityDialog center];
    }
}

- (void)webView:(WebView *)sender didFinishLoadForFrame:(WebFrame *)frame
{
    if ([sender isEqual:webView] && frame == [sender mainFrame])
        [self acquireAssertion:sender];
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
    assertion = nil;
    identityDialog = nil;
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
    NSURL *personaURL = [NSURL URLWithString:@"https://login.persona.org/sign_in#NATIVE"];

    if ([self audience] == nil)
        return (bidError = BID_S_INVALID_AUDIENCE_URN);

    if ([self canInteract] == NO && [self silent] == NO)
        return (bidError = BID_S_INTERACT_REQUIRED);

    identityDialog = [[BIDIdentityDialog identityDialog] retain];
    [identityDialog setDelegate:self];

    webView = [[self newWebView] retain];
    [[webView mainFrame] loadRequest:[NSURLRequest requestWithURL:personaURL]];

    [app runModalForWindow:identityDialog];

    return bidError;
}

@end

static BIDError
_BIDWebkitGetAssertion(
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

        controller = [[BIDIdentityController alloc] initWithAudience:[NSString stringWithCString:szPackedAudience] claims:claimsDict];
        [controller setServicePrincipalName:[NSString stringWithCString:szAudienceOrSpn]];

        if (szIdentityName != NULL) {
            [controller setRequiredEmail:[NSString stringWithCString:szIdentityName]];
            [controller setSilent:!!(context->ContextOptions & BID_CONTEXT_BROWSER_SILENT)];
        }
        [controller setCanInteract:_BIDCanInteractP(context, ulReqFlags)];
        [controller performSelectorOnMainThread:@selector(getAssertion) withObject:nil waitUntilDone:TRUE];

        err = [controller bidError];
        if (err == BID_S_OK)
            err = _BIDDuplicateString(context, [[controller assertion] cString], pAssertion);

        [controller release];
    }

    return err;
}
#endif /* __APPLE__ */

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
#ifdef __APPLE__
    return _BIDWebkitGetAssertion(context, szPackedAudience, szAudienceOrSpn, claims,
                                  szIdentityName, ulReqFlags, pAssertion);
#else
    return BID_S_INTERACT_UNAVAILABLE;
#endif
}
