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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AppKit/AppKit.h>

#include "browserid.h"
#include "CFBrowserID.h"
#include "bid_private.h"

#define SAFE_CFRELEASE(x) do { if ((x)) { CFRelease((x)); (x) = NULL; } } while (0)

/*
 * Test acquiring an assertion and verifying it using CoreFoundation API.
 */

int main(int argc, const char *argv[])
{
    int exitCode = 0;
    BIDContext context = NULL;
    CFStringRef assertion = NULL;
    CFStringRef audience = NULL;
    CFStringRef name = CFSTR("lukeh@rand.mit.de.padl.com");
    __block CFErrorRef err = NULL;
    CFDataRef cb = NULL;
    uint32_t flags = 0;
    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_USER_AGENT |
                       BID_CONTEXT_GSS | BID_CONTEXT_REPLAY_CACHE;
    dispatch_queue_t q = dispatch_queue_create("com.padl.BrowserID.tests.bid_cf", NULL);
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSDictionary *moreClaims = @{ @"foo" : @"bar", @"baz" : @"123" };

    if (argc > 2 && !strcmp(argv[1], "-identity")) {
        name = CFStringCreateWithCString(kCFAllocatorDefault, argv[2], kCFStringEncodingASCII);
        argc -= 2;
        argv += 2;
    }
    if (argc > 1) {
        audience = CFStringCreateWithCString(kCFAllocatorDefault, argv[1], kCFStringEncodingASCII);
        argc--;
        argv++;
    }

    /*
     * As of OS X Mavericks, the workaround in bid_webkit.m for app-ifying console
     * applications no longer works. So we need to initialize things here.
     */
    [NSApplication sharedApplication];

    context = BIDContextCreate(NULL, options, &err);
    if (context == NULL) {
        NSLog(@"Failed to create context: %@", err);
        goto cleanup;
    }

    if (audience == NULL)
        audience = CFSTR("host/www.persona.org");

    cb = CFDataCreate(kCFAllocatorDefault, (UInt8 *)"foo", 3);

    assertion = BIDAssertionCreateUIWithClaims(context, audience, cb, name,
                                               0, (__bridge CFDictionaryRef)moreClaims,
                                               NULL, &flags, &err);
    if (assertion == NULL) {
        NSLog(@"Failed to acquire assertion: %@", err);
        goto cleanup;
    }

    NSLog(@"Assertion is %@", assertion);

    BIDVerifyAssertionWithHandler(context,
                                  assertion,
                                  audience,
                                  cb,
                                  CFAbsoluteTimeGetCurrent(),
                                  0, // flags
                                  q,
                                  ^(BIDIdentity identity, uint32_t flags, CFErrorRef verifyErr) {
        if (identity == NULL) {
            err = (CFErrorRef)CFRetain(verifyErr);
            NSLog(@"Failed to verify assertion: %@", err);
        } else {
            CFDictionaryRef dict;

            NSLog(@"Verified assertion for identity %@ / flags %08x!", identity, flags);

            dict = BIDIdentityCopyAttributeDictionary(identity);
            NSLog(@"Identity %@ dictionary is %@", identity, dict);
            SAFE_CFRELEASE(dict);
        }
        dispatch_semaphore_signal(sema);
    });
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

cleanup:
    if (err)
        exitCode = CFErrorGetCode(err);

    SAFE_CFRELEASE(context);
    SAFE_CFRELEASE(assertion);
    SAFE_CFRELEASE(cb);
    SAFE_CFRELEASE(err);

    exit(exitCode);
}
