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

#ifndef _BID_WK_H_
#define _BID_WK_H_ 1

/*
 * Apple WebKit implementation behind _BIDBrowserGetAssertion
 */

#include "bid_private.h"

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#include <UIKit/UIKit.h>
#include <JavaScriptCore/JavaScriptCore.h>
#else
#include <AppKit/AppKit.h>
#include <WebKit/WebKit.h>
#endif

@class BIDJsonDictionary;

#if TARGET_OS_IPHONE
@protocol BIDIdentityControllerJS <JSExport>
JSExportAs(identityCallback,
- (void)identityCallback:(NSString *)assertion withParams:(id)params
);
- (NSString *)siteName;
- (BIDJsonDictionary *)claims;
- (BOOL)silent;
- (NSString *)emailHint;
- (NSString *)audience;
- (void)setAssertion:(NSString *)assertion;
@end

@interface BIDIdentityController : UIViewController <BIDIdentityControllerJS>
#else
@class BIDIdentityDialog;

@interface BIDIdentityController : NSObject
#endif
{
    NSString *_audience;
#if TARGET_OS_IPHONE
    id _rls;
#endif
}

@property(nonatomic, copy) NSString *audience;
@property(nonatomic, retain) BIDJsonDictionary *claims;
@property(nonatomic, copy) NSString *emailHint;
@property(nonatomic, copy) NSString *siteName;
@property(nonatomic, retain, readonly) NSString *assertion;
@property(nonatomic, assign) BOOL canInteract;
@property(nonatomic, assign) BOOL silent;
@property(nonatomic, readonly) BIDError bidError;

/* platform properties */
#if TARGET_OS_IPHONE
@property(nonatomic, retain, readwrite) UIWindow *parentWindow;
@property(nonatomic, retain, readwrite) UIWebView *webView;
#else
@property(nonatomic, retain, readwrite) BIDIdentityDialog *identityDialog;
@property(nonatomic, retain, readwrite) NSWindow *parentWindow;
@property(nonatomic, retain, readwrite) WebView *webView;
#endif

/* public interface */
- (BIDError)getAssertion;
- (id)initWithAudience:(NSString *)anAudience claims:(BIDJsonDictionary *)someClaims;

/* private interface */
- (void)abortWithError:(NSError *)error;
- (void)interposeAssertionSign:(id)sender;
- (void)acquireAssertion:(id)sender;
@end

#if TARGET_OS_IPHONE
@interface BIDIdentityController (PlatformUI) <UIWebViewDelegate>
#else
@interface BIDIdentityController (PlatformUI) <NSWindowDelegate>
#endif
- (id)newWebView;
- (void)closeIdentityDialog;
- (void)loadIdentityDialog;
- (void)showIdentityDialog;
@end

#endif /* _BID_WK_H_ */
