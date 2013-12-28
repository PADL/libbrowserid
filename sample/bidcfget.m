#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#include <UIKit/UIKit.h>
#else
#include <Cocoa/Cocoa.h>
#endif

#include <browserid.h>
#include <CFBrowserID.h>

/*
 * Display a modal dialog acquiring an assertion for the given audience.
 */
NSString *
PersonaGetAssertion(
    NSString *audience,
#if TARGET_OS_IPHONE
    UIWindow *parentWindow,
#else
    NSWindow *parentWindow,
#endif
    NSError * __autoreleasing *error)
{
    BIDContext context;
    CFStringRef assertion;
    CFErrorRef cfErr;
    uint32_t flags;

    context = BIDContextCreate(kCFAllocatorDefault, NULL, BID_CONTEXT_USER_AGENT, &cfErr);
    if (context == NULL) {
        if (error)
            *error = CFBridgingRelease(cfErr);
        else
            CFRelease(cfErr);
        return NULL;
    }

    BIDSetContextParam(context, BID_PARAM_PARENT_WINDOW, (__bridge void *)parentWindow);

    assertion = BIDAssertionCreateUI(context, (__bridge CFStringRef)audience,
                                     NULL, NULL, 0, NULL, &flags, &cfErr);

    if (cfErr) {
        if (error)
            *error = CFBridgingRelease(cfErr);
        else
            CFRelease(cfErr);
    }

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
        NSString *assertion;
        NSError *error = NULL;

#if TARGET_OS_IPHONE
        [UIApplication sharedApplication];
#else
        [NSApplication sharedApplication];
#endif

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
