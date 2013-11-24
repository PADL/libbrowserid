#include <Cocoa/Cocoa.h>
#include <CFBrowserID.h>

/*
 * Display a modal dialog acquiring an assertion for the given audience.
 */
NSString *
PersonaGetAssertion(
    NSString *audience,
    NSWindow *parentWindow,
    NSError * __autoreleasing *error)
{
    BIDContext context = NULL;
    CFStringRef assertion = NULL;
    CFErrorRef cfErr = NULL;
    uint32_t flags = 0;

    context = BIDContextCreate(NULL, BID_CONTEXT_USER_AGENT, &cfErr);
    if (context == NULL) {
        *error = CFBridgingRelease(cfErr);
        return NULL;
    }

    BIDSetContextParam(context, BID_PARAM_PARENT_WINDOW, (__bridge void *)parentWindow);

    assertion = BIDAssertionCreateUI(context, (__bridge CFStringRef)audience,
                                     NULL, NULL, 0, NULL, &flags, &cfErr);

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
