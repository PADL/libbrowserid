#include <Cocoa/Cocoa.h>
#include "../libbrowserid/CFBrowserID.h"

// Display assertion dialog to get assertion for designated audience
NSString *
PersonaGetAssertion(NSString *audience, NSWindow *parentWindow, NSError **error)
{
    BIDContext context = NULL;
    CFStringRef assertion = NULL;
    CFErrorRef cfErr = NULL;
    CFAbsoluteTime expires;
    uint32_t flags = 0;

    // create a BrowserID user agent context
    context = BIDContextCreate(NULL, BID_CONTEXT_USER_AGENT, &cfErr);
    if (context == NULL) {
        *error = CFBridgingRelease(cfErr);
        return NULL;
    }

    // set parent window handle for modal dialog
    BIDSetContextParam(context, BID_PARAM_PARENT_WINDOW, (__bridge void *)parentWindow);


    // display UI and acquire assertion
    assertion = BIDAssertionCreateUI(context, (__bridge CFStringRef)audience,
                                     NULL, NULL, 0, NULL, &expires, &flags, &cfErr);

    if (cfErr)
        *error = CFBridgingRelease(cfErr);

    CFRelease(context);
    return CFBridgingRelease(assertion);
}

int main(int argc, const char *argv[])
{
    int exitCode = BID_S_OK;

    if (argc != 2) {
        NSLog(@"Usage: %s audience\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    @autoreleasepool {
        NSString *audience = [NSString stringWithUTF8String:argv[1]];
        NSString *assertion = NULL;
        NSError *error = NULL;

        [NSApplication sharedApplication];

        assertion = PersonaGetAssertion(audience, NULL, &error);
        if (assertion) {
            NSLog(@"Assertion is %@", assertion);
        } else {
            NSLog(@"Failed to get assertion: %@", error);
            exitCode = [error code];
        }
    }

    exit(exitCode);
}
