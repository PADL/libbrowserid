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

#if TARGET_OS_IPHONE

/*
 * UIKit (iOS) specific WebKit interface
 */

static void
_BIDDismissIdentityDialogAndStopModal(void *obj);

@implementation BIDIdentityController (PlatformUI)
- (UIWebView *)dispenseWebView
{
    UIWebView *aWebView = [[UIWebView alloc] initWithFrame:self.parentWindow.bounds];

#if !__has_feature(objc_arc)
    [aWebView autorelease];
#endif

    aWebView.delegate = self;
    aWebView.suppressesIncrementalRendering = YES;
    aWebView.scrollView.scrollEnabled = NO;
    aWebView.scalesPageToFit = YES;

    return aWebView;
}

- (void)webView:(UIWebView *)sender didFailLoadWithError:(NSError *)error
{
    NSLog(@"webView:%@ didFailLoadWithError:%@", sender, error);
    if (error.code == NSURLErrorCancelled)
        return;
    else
        [self abortWithError:error];
}

- (void)webViewDidFinishLoad:(UIWebView *)sender
{
    JSContext *jsContext;

    if (![sender isEqual:self.webView])
        return;

    jsContext = [self.webView valueForKeyPath:@"documentView.webView.mainFrame.javaScriptContext"];
    jsContext[@"IdentityController"] = self;

    [self acquireAssertion:sender];
}

- (void)closeIdentityDialog
{
    if (_rls != nil) {
        CFRunLoopSourceSignal((__bridge CFRunLoopSourceRef)_rls);
        CFRunLoopWakeUp(CFRunLoopGetMain());
    }
    [self _completeModalSession];
}

- (void)loadIdentityDialog
{
    NSURL *personaURL = [NSURL URLWithString:@BID_SIGN_IN_URL];
    UIViewController *viewController = self.parentWindow.rootViewController;
    self.webView.hidden = YES;

    [self.webView loadRequest:[NSURLRequest requestWithURL:personaURL]];
    [self.parentWindow addSubview:self.webView];

    [viewController presentViewController:self animated:NO completion:nil];
}

- (void)showIdentityDialog
{
    self.webView.hidden = NO;
}

- (void)dismissIdentityDialogAndStopModal
{
    [self dismissViewControllerAnimated:NO completion:^{
    }];
    [self.webView removeFromSuperview];
    if (_rls != nil)
        CFRunLoopStop(CFRunLoopGetMain());
}

- (void)_runModal
{
    CFRunLoopSourceContext rlContext = {
        0,                 // version
        (__bridge void *)self,
        CFRetain,          // retain
        CFRelease,         // release
        CFCopyDescription, // copyDescription
        CFEqual,           // equal
        CFHash,            // hash
        0,                 // schedule
        0,                 // cancel
        &_BIDDismissIdentityDialogAndStopModal // perform
    };

    _rls = CFBridgingRelease(CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &rlContext));
    CFRunLoopAddSource(CFRunLoopGetMain(), (__bridge CFRunLoopSourceRef)_rls, kCFRunLoopCommonModes);
    CFRunLoopRun();
}

@end

static void
_BIDDismissIdentityDialogAndStopModal(void *obj)
{
    [(__bridge BIDIdentityController *)obj dismissIdentityDialogAndStopModal];
}

#endif /* TARGET_OS_IPHONE */
