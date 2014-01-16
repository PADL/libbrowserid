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

#if !TARGET_OS_IPHONE

/*
 * AppKit (Mac OS X) specific WebKit interface
 */

@interface BIDIdentityDialog : NSPanel
+ (BIDIdentityDialog *)identityDialog;
@end

@implementation BIDIdentityController (PlatformUI)
+ (NSString *)webScriptNameForSelector:(SEL)sel
{
    if (sel == @selector(identityCallback:withParams:))
        return @"identityCallback";
    else
        return nil;
}

- (NSString *)claimsString
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:self.claims options:0 error:NULL];
    NSString *claimsString;

    claimsString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
#if !__has_feature(objc_arc)
    [claimsString autorelease];
#endif

    return claimsString;
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)selector
{
    if (selector == @selector(identityCallback:withParams:) ||
        selector == @selector(siteName) ||
        selector == @selector(claimsString) ||
        selector == @selector(emailHint) ||
        selector == @selector(forceAuthentication) ||
        selector == @selector(audience))
        return NO;

    return YES;
}

- (WebView *)dispenseWebView
{
    NSRect frame = NSMakeRect(0, 0, 700, 375);
    WebView *aWebView = [[WebView alloc] initWithFrame:frame];

    if (aWebView != nil) {
        aWebView.frameLoadDelegate = self;
        aWebView.resourceLoadDelegate = self;
        aWebView.UIDelegate = self;
        aWebView.policyDelegate = self;
        aWebView.hostWindow = self.identityDialog;
        aWebView.shouldCloseWithWindow = YES;
    }

#if __has_feature(objc_arc)
    return aWebView;
#else
    return [aWebView autorelease];
#endif
}

- (void)webView:(WebView *)sender didFinishLoadForFrame:(WebFrame *)frame
{
    if ([sender isEqual:self.webView] && frame == [sender mainFrame]) {
        if (self.claims.count)
            [self interposeAssertionSign:sender];
        [self acquireAssertion:sender];
    }
}

- (void)windowWillClose:(NSNotification *)BID_UNUSED notification
{
    [NSApp stopModalWithCode:self.bidError];
}

- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailProvisionalLoadWithError:%@ forFrame:%@", sender, error, frame.name);
    [self abortWithError:error];
}

- (void)webView:(WebView *)BID_UNUSED sender decidePolicyForNavigationAction:(NSDictionary *)BID_UNUSED actionInformation request:(NSURLRequest *)BID_UNUSED request frame:(WebFrame *)BID_UNUSED frame decisionListener:(id<WebPolicyDecisionListener>)listener
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

- (void)webView:(WebView *)BID_UNUSED sender windowScriptObjectAvailable:(WebScriptObject *)windowScriptObject
{
    [windowScriptObject setValue:self forKey:@"IdentityController"];
}

- (void)webView:(WebView *)webView addMessageToConsole:(NSDictionary *)message
{
    [self webView:webView addMessageToConsole:message withSource:nil];
}

- (void)webView:(WebView *)BID_UNUSED webView addMessageToConsole:(NSDictionary *)message withSource:(NSString *)BID_UNUSED source
{
    NSLog(@"%@", [message objectForKey:@"message"]);
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    NSLog(@"webView:%@ didFailLoadWithError:%@ frame:%@", sender, error, frame);
    if (error.code == NSURLErrorCancelled)
        return;
    else
        [self abortWithError:error];
}

- (void)closeIdentityDialog
{
    [self.identityDialog close];
}

- (void)loadIdentityDialog
{
    NSURL *personaURL = [NSURL URLWithString:@BID_SIGN_IN_URL];
    NSModalSession modalSession;
    NSModalResponse modalResponse;

    self.identityDialog = [BIDIdentityDialog identityDialog];
    self.identityDialog.delegate = self;

    [[self.webView mainFrame] loadRequest:[NSURLRequest requestWithURL:personaURL]];
    [self.identityDialog orderOut:self.webView];

    if (self.parentWindow != nil) {
        [self.parentWindow beginSheet:self.identityDialog completionHandler:^(NSModalResponse returnCode BID_UNUSED) {
        }];
    }

    modalSession = [NSApp beginModalSessionForWindow:self.identityDialog];
    do {
        modalResponse = [NSApp runModalSession:modalSession];
    } while (modalResponse == NSModalResponseContinue &&
             [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate distantFuture]]);

    [NSApp endModalSession:modalSession];
}

- (void)showIdentityDialog
{
    [self.identityDialog makeFirstResponder:self.webView];
    self.identityDialog.contentView = self.webView;
    [self.identityDialog makeKeyAndOrderFront:self.webView];
    if (self.parentWindow == nil)
        [self.identityDialog center];
}
@end

@implementation BIDIdentityDialog
+ (BIDIdentityDialog *)identityDialog
{
    BIDIdentityDialog *identityDialog;

    identityDialog = [[self alloc] init];

#if __has_feature(objc_arc)
    return identityDialog;
#else
    return [identityDialog autorelease];
#endif
}

- (id)init
{
    NSRect frame = NSMakeRect(0, 0, 700, 375);
    NSUInteger styleMask = NSTitledWindowMask | NSClosableWindowMask | NSUtilityWindowMask;
    NSRect rect = [NSPanel contentRectForFrameRect:frame styleMask:styleMask];

    self = [super initWithContentRect:rect styleMask:styleMask backing:NSBackingStoreBuffered defer:YES];

    self.hidesOnDeactivate = YES;
    self.worksWhenModal = YES;

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

#endif /* !TARGET_OS_IPHONE */
