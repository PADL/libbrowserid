#include <Cocoa/Cocoa.h>
#include "../libbrowserid/CFBrowserID.h"

#define SAFE_CFRELEASE(x) do { if ((x)) { CFRelease((x)); (x) = NULL; } } while (0)

int main(int argc, const char *argv[])
{
    BIDContext context = NULL;
    CFStringRef audience = NULL;
    CFStringRef assertion = NULL;
    CFErrorRef err = NULL;
    CFAbsoluteTime expires;
    uint32_t flags = 0;

    if (argc != 2) {
        NSLog(@"Usage: %s audience\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    audience = CFStringCreateWithCString(kCFAllocatorDefault, argv[1], kCFStringEncodingASCII);

    [NSApplication sharedApplication];

    context = BIDContextCreate(NULL, BID_CONTEXT_USER_AGENT, &err);
    if (context == NULL) {
        NSLog(@"Failed to create BIDContext: %@", err);
        goto cleanup;
    }

    assertion = BIDAssertionCreateUI(context, audience, NULL, NULL, 0, NULL, &expires, &flags, &err);
    if (assertion == NULL) {
        NSLog(@"Failed to get assertion: %@", err);
        goto cleanup;
    }

    NSLog(@"Assertion is %@", assertion);

cleanup:
    SAFE_CFRELEASE(assertion);
    SAFE_CFRELEASE(audience);
    SAFE_CFRELEASE(context);

    int exitCode = 0;

    if (err) {
        exitCode = CFErrorGetCode(err);
        CFRelease(err);
    }

    exit(exitCode);
}
