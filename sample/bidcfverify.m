#include <Cocoa/Cocoa.h>
#include <CFBrowserID.h>

void
PersonaVerifyAssertion(
    NSString *assertion,
    NSString *audience,
    dispatch_queue_t q,
    void (^handler)(id identity, NSError *error))
{
    BIDContext context = NULL;
    CFErrorRef cfErr;

    context = BIDContextCreate(NULL, BID_CONTEXT_RP, &cfErr);
    if (context == NULL) {
        handler(NULL, (__bridge NSError *)cfErr);
        CFRelease(cfErr);
        return;
    }

    BIDVerifyAssertionWithHandler(context,
                                  (__bridge CFStringRef)assertion,
                                  (__bridge CFStringRef)audience,
                                  NULL, // channel bindings
                                  CFAbsoluteTimeGetCurrent(),
                                  0, // flags
                                  q,
                                  ^(BIDIdentity identity, uint32_t flags, CFErrorRef error) {
        handler((__bridge id)identity, (__bridge NSError *)error);
        });

    CFRelease(context);
}

int main(int argc, const char *argv[])
{
    __block int exitCode = BID_S_OK;
    dispatch_queue_t q = dispatch_queue_create("com.padl.BrowserID.example", NULL);
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    if (argc != 3) {
        NSLog(@"Usage: %s audience assertion\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    @autoreleasepool {
        NSString *audience = [NSString stringWithUTF8String:argv[1]];
        NSString *assertion = [NSString stringWithUTF8String:argv[2]];

        PersonaVerifyAssertion(assertion, audience, q,
                               ^(id identity, NSError *error) {
            NSDictionary *attrs;

            if (identity) {
                NSLog(@"Verified assertion: %@", identity);
                attrs = CFBridgingRelease(BIDIdentityCopyAttributeDictionary((__bridge BIDIdentity)identity));
                NSLog(@"Attributes: %@", attrs);
            } else {
                NSLog(@"Failed to verify assertion: %@", error);
                exitCode = [error code];
            }
            dispatch_semaphore_signal(sema);
        });
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    }

    exit(exitCode);
}
