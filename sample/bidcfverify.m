#include <Cocoa/Cocoa.h>
#include "../libbrowserid/CFBrowserID.h"

#define SAFE_CFRELEASE(x) do { if ((x)) { CFRelease((x)); (x) = NULL; } } while (0)

int main(int argc, const char *argv[])
{
    BIDContext context = NULL;
    CFStringRef audience = NULL;
    CFStringRef assertion = NULL;
    CFErrorRef err = NULL;
    BIDIdentity identity = NULL;
    CFDictionaryRef attrs = NULL;
    CFAbsoluteTime expires;
    uint32_t flags = 0;

    if (argc != 3) {
        NSLog(@"Usage: %s audience assertion\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    context = BIDContextCreate(NULL, BID_CONTEXT_RP, &err);
    if (context == NULL) {
        NSLog(@"Failed to create BIDContext: %@", err);
        goto cleanup;
    }

    audience = CFStringCreateWithCString(kCFAllocatorDefault, argv[1], kCFStringEncodingASCII);
    assertion = CFStringCreateWithCString(kCFAllocatorDefault, argv[2], kCFStringEncodingASCII);

    identity = BIDIdentityFromVerifyingAssertion(context, assertion, audience, NULL,
                                                 CFAbsoluteTimeGetCurrent(), 0, &expires, &flags, &err);
    if (identity == NULL) {
        NSLog(@"Failed to verify assertion: %@", err);
        goto cleanup;
    }

    attrs = BIDIdentityCopyAttributeDictionary(context, identity);

    NSLog(@"Verified assertion: %@", attrs);

cleanup:
    SAFE_CFRELEASE(attrs);
    SAFE_CFRELEASE(audience);
    SAFE_CFRELEASE(assertion);
    SAFE_CFRELEASE(context);

    int exitCode = 0;

    if (err) {
        exitCode = CFErrorGetCode(err);
        CFRelease(err);
    }

    exit(exitCode);
}
