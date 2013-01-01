/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#ifdef __APPLE__

#include <AppKit/AppKit.h>
#include <WebKit/WebKit.h>

@interface BIDGSSURLProtocol : NSURLProtocol
@end

@implementation BIDGSSURLProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    return [[[request URL] scheme] isEqualToString:@"gss"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    return request;
}

- (void)startLoading
{
    NSHTTPURLResponse *response;
    NSURLRequest *request = [self request];
    id client = [self client];

    NSLog(@"BIDURLProtocol start loading");

    response = [[NSHTTPURLResponse alloc] initWithURL:[request URL]
                                           statusCode:200
                                          HTTPVersion:@"HTTP/1.1"
                                         headerFields:nil];

    [client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [client URLProtocol:self didLoadData:nil];
    [client URLProtocolDidFinishLoading:self];

    [response release];    
}
@end

@interface BIDLoginPanel : NSPanel
+ (BIDLoginPanel *)panel;
@end

@implementation BIDLoginPanel
+ (BIDLoginPanel *)panel
{
    return [[[self alloc] init] autorelease];
}

- init
{
    NSRect frame = NSMakeRect(0, 0, 0, 0);

    self = [super initWithContentRect:frame
                            styleMask:NSTitledWindowMask | NSUtilityWindowMask
                              backing:NSBackingStoreBuffered
                                defer:YES];

    [self setHidesOnDeactivate:NO];
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

@interface BIDAssertionLoader : NSObject <NSWindowDelegate>
{
@private
    NSString *audience;
    NSString *siteName;
    NSString *assertion;
    BIDLoginPanel *panel;
    BIDError bidError;
}

/* accessors */
- (void)setAudience:(NSString *)value;
- (NSString *)audience;
- (void)setSiteName:(NSString *)value;
- (NSString *)siteName;
- (void)setAssertion:(NSString *)value;
- (NSString *)assertion;
- (BIDError)bidError;

/* JavaScript called methods */
- (void)onlogin:(NSString *)string;
- (void)onlogout;

/* helpers */
- (void)closePanelAndStopModal;
- (void)didAbortLoad:(NSError *)error;
- (void)didLoadAssertion;
- (WebView *)newWebView;

/* public interface */
- (BIDError)loadAssertion;
@end

@implementation BIDAssertionLoader
#pragma mark - accessors
- (NSString *)audience
{
    return [[audience retain] autorelease];
}

- (void)setAudience:(NSString *)value
{
    if (value != audience) {
        [audience release];
        audience = [value copy];
    }
}

- (NSString *)siteName
{
    return [[siteName retain] autorelease];
}

- (void)setSiteName:(NSString *)value
{
    if (value != siteName) {
        [siteName release];
        siteName = [value copy];
    }
}

- (NSString *)assertion
{
    return [[assertion retain] autorelease];
}

- (void)setAssertion:(NSString *)value
{
    if (value != assertion) {
        [assertion release];
        assertion = [value copy];
    }
}

- (BIDError)bidError
{
    return bidError;
}

#pragma mark - helpers

- (WebView *)newWebView
{
    NSRect frame = NSMakeRect(0,0,0,0);
    WebView *webView = [[[WebView alloc] initWithFrame:frame] autorelease];

    [webView setFrameLoadDelegate:self];
    [webView setResourceLoadDelegate:self];
    [webView setUIDelegate:self];
    [webView setPolicyDelegate:self];
    [webView setHostWindow:panel];
    [webView setShouldCloseWithWindow:YES];

    return webView;
}

- (void)closePanelAndStopModal
{
    [panel close];
    [NSApp stopModal];
}

- (void)didAbortLoad:(NSError *)error
{
    if (error != nil &&
        ([[error domain] isEqualToString:NSURLErrorDomain] ||
         [[error domain] isEqualToString:WebKitErrorDomain]))
        bidError = BID_S_HTTP_ERROR;
    else
        bidError = BID_S_INTERACT_FAILURE;

    [self closePanelAndStopModal];
}

- (void)didLoadAssertion
{
    bidError = (assertion != nil && [assertion length]) ? BID_S_OK : BID_S_INTERACT_FAILURE;
    [self closePanelAndStopModal];
}

#pragma mark - javascript methods

- (void)onlogin:(NSString *)string
{
    [self setAssertion:string];
    [self didLoadAssertion];
}

- (void)onlogout
{
    [self didAbortLoad:nil];
}

#pragma mark - delegates

+ (BOOL)isKeyExcludedFromWebScript:(const char *)property
{
    if (strcmp(property, "siteName") == 0)
        return NO;

    return YES;
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)selector
{
    if (selector == @selector(onlogin:) || selector == @selector(onlogout))
        return NO;

    return YES;
}

- (void)webView:(WebView *)sender didCommitLoadForFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didCommitLoadForFrame:%@ (parent %@)", [sender description], [frame name], [[frame parentFrame] name]);
}

- (void)webView:(WebView *)sender didFinishLoadForFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFinishLoadForFrame:%@", [sender description], [frame name]);

    if ([[frame name] length] == 0) {
        NSString *function = @"                                                                             \
            navigator.id.watch({                                                                            \
                onlogin: function(assertion) { window.AssertionLoader.onlogin_(assertion); },               \
                onlogout: function() { window.AssertionLoader.onlogout; }                                   \
            });                                                                                             \
                                                                                                            \
            navigator.id.request({siteName: window.AssertionLoader.siteName});  \
         ";

        [sender stringByEvaluatingJavaScriptFromString:function];
    }
}

- (void)webView:(WebView *)webView windowScriptObjectAvailable:(WebScriptObject *)windowScriptObject
{
    [windowScriptObject setValue:self forKey:@"AssertionLoader"];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailLoadWithError:%@ forFrame:%@", [sender description], [error description], [frame name]);

    if ([error code] == NSURLErrorCancelled)
        return;
    else
        [self didAbortLoad:error];
}

- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailProvisionalLoadWithError:%@ forFrame:%@", [sender description], [error description], [frame name]);
    [self didAbortLoad:error];
}

- (void)webView:(WebView *)sender decidePolicyForNavigationAction:(NSDictionary *)actionInformation request:(NSURLRequest *)request frame:(WebFrame *)frame decisionListener:(id<WebPolicyDecisionListener>)listener
{
    NSLog(@"webView:%@ decidePolicyForNavigationAction:%@ request:%@ frame:%@ decisionListener:%@", sender, [actionInformation objectForKey:WebActionOriginalURLKey], request, [frame name], listener);
    [listener use];
}

- (void)webView:(WebView *)webView decidePolicyForNewWindowAction:(NSDictionary *)actionInformation request:(NSURLRequest *)request newFrameName:(NSString *)frameName decisionListener:(id < WebPolicyDecisionListener >)listener
{
    NSLog(@"webView:%@ decidePolicyForNewWindowAction:%@ request:%@ frame:%@", webView, [actionInformation objectForKey:WebActionOriginalURLKey], request, frameName);

    if ([actionInformation objectForKey:WebActionElementKey]) {
        [listener ignore];
        [[NSWorkspace sharedWorkspace] openURL:[request URL]];
    } else {
        [listener use];
    }
}

#if 0
- (WebView *)webView:(WebView *)sender createWebViewModalDialogWithRequest:(NSURLRequest *)request
{
    WebView *webView = [self newWebView];
    BIDLoginPanel *newPanel = [BIDLoginPanel panel];

    [newPanel setParentWindow:panel];
    [newPanel setContentView:webView];

    return webView;
}

- (void)webViewRunModal:(WebView *)sender
{
    [self webViewShow:sender];
}
#endif

- (WebView *)webView:(WebView *)sender createWebViewWithRequest:(NSURLRequest *)request
{
    WebView *webView = [self newWebView];

    [panel setContentView:webView];

    return webView;
}

- (void)webViewShow:(WebView *)webView
{
    [panel makeKeyAndOrderFront:nil];
    [panel makeFirstResponder:webView];
    [panel center];
}

#if 0
- (void)webViewClose:(WebView *)sender
{
    [self didAbortLoad:nil];
}

- (void)webView:(WebView *)sender makeFirstResponder:(NSResponder *)responder
{
    [panel makeFirstResponder:responder];
}
#endif

#if 0
- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource
{
    return request;
}

- (void)webView:(WebView *)sender resource:(id)identifier didFailLoadingWithError:(NSError *)error fromDataSource:(WebDataSource *)dataSource
{
    [self didAbortLoad:error];
}
#endif

#pragma mark - public
- init
{
    audience = nil;
    assertion = nil;
    panel = nil;
    bidError = BID_S_INTERACT_FAILURE;

    return [super init];
}

- (void)dealloc
{
    [super dealloc];

    [audience release];
    [assertion release];
    [panel release];
}

- (BIDError)loadAssertion
{
    NSApplication *app = [NSApplication sharedApplication];
    NSURL *baseURL = [NSURL URLWithString:audience];
    WebFrame *mainFrame;
    WebView *webView;

    if (baseURL == nil) {
        bidError = BID_S_INVALID_AUDIENCE_URN;
        return bidError;
    }

    [NSURLProtocol registerClass:[BIDGSSURLProtocol class]];
    [WebView registerURLSchemeAsLocal:@"gss"];

    panel = [[BIDLoginPanel panel] retain];
    [panel setDelegate:self];

    webView = [self newWebView];

    mainFrame = [webView mainFrame];

    [mainFrame loadHTMLString:@"<script src=\"https://browserid.org/include.js\" type=\"text/javascript\"></script>"
               baseURL:baseURL];

    [app runModalForWindow:panel];
    [panel orderOut:nil];
    [NSURLProtocol unregisterClass:[BIDGSSURLProtocol class]];

    return bidError;
}
@end

static BIDError
_BIDWebkitGetAssertion(
    BIDContext context,
    const char *szAudience,
    const char *szSiteName,
    char **pAssertion)
{
    BIDError err = BID_S_INTERACT_FAILURE;
    BIDAssertionLoader *loader = nil;

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
        loader = [[BIDAssertionLoader alloc] init];
        [loader setAudience:[NSString stringWithCString:szAudience]];
        [loader setSiteName:[NSString stringWithCString:szSiteName]];
        [loader performSelectorOnMainThread:@selector(loadAssertion) withObject:nil waitUntilDone:TRUE];

        NSLog(@"assertion = %@", [loader assertion]);

        err = [loader bidError];
        if (err == BID_S_OK)
            err = _BIDDuplicateString(context, [[loader assertion] cString], pAssertion);

        [loader release];
    }

    return err;
}
#endif /* __APPLE__ */

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szAudience,
    const char *szSiteName,
    char **pAssertion)
{
#ifdef __APPLE__
    return _BIDWebkitGetAssertion(context, szAudience, szSiteName, pAssertion);
#else
    return BID_S_INTERACT_UNAVAILABLE;
#endif
}
