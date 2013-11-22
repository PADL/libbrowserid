#include <Cocoa/Cocoa.h>
#include <CFBrowserID.h>

id
PersonaVerifyAssertion(
    NSString *assertion,
    NSString *audience,
    NSError * __autoreleasing *error)
{
    BIDContext context = NULL;
    CFErrorRef cfErr = NULL;
    BIDIdentity identity = NULL;
    CFAbsoluteTime expires;
    uint32_t flags = 0;

    context = BIDContextCreate(NULL, BID_CONTEXT_RP, &cfErr);
    if (context == NULL) {
        *error = CFBridgingRelease(cfErr);
        return NULL;
    }

    identity = BIDIdentityCreateFromVerifyingAssertion(context,
                                                       (__bridge CFStringRef)assertion,
                                                       (__bridge CFStringRef)audience,
                                                       NULL, // channel bindings
                                                       CFAbsoluteTimeGetCurrent(),
                                                       0, // flags
                                                       &expires,
                                                       &flags,
                                                       &cfErr);

    *error = CFBridgingRelease(cfErr);

    CFRelease(context);

    return CFBridgingRelease(identity);
}

int main(int argc, const char *argv[])
{
    int exitCode = BID_S_OK;

    if (argc != 3) {
        NSLog(@"Usage: %s audience assertion\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    @autoreleasepool {
        NSString *audience = [NSString stringWithUTF8String:argv[1]];
        NSString *assertion = [NSString stringWithUTF8String:argv[2]];
        id identity;
        NSError *error;

        identity = PersonaVerifyAssertion(assertion, audience, &error);
        if (identity) {
            NSLog(@"Verified assertion: %@", identity);
        } else {
            NSLog(@"Failed to verify assertion: %@", error);
            exitCode = [error code];
        }
    }

    exit(exitCode);
}
