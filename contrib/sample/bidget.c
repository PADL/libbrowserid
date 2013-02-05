#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"

int main(int argc, const char *argv[])
{
    BIDError err;
    BIDContext context = NULL;
    char *assertion = NULL;
    BIDIdentity identity = NULL;
    time_t expires;
    uint32_t flags = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s audience\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    err = BIDAcquireContext(BID_CONTEXT_USER_AGENT, &context);
    if (err != BID_S_OK)
        goto cleanup;

    err = BIDAcquireAssertion(context, BID_C_NO_TICKET_CACHE, argv[1],
                              NULL, 0, NULL, 0,
                              &assertion, NULL, &expires, &flags);
    if (err != BID_S_OK)
        goto cleanup;

    printf("Assertion:\n%s\n", assertion);

cleanup:
    if (context != BID_C_NO_CONTEXT) {
        BIDFreeAssertion(context, assertion);
        BIDReleaseIdentity(context, identity);
        BIDReleaseContext(context);
    }

    if (err != BID_S_OK) {
        const char *s;
        BIDErrorToString(err, &s);
        fprintf(stderr, "libbrowserid error %s[%d]\n", s, err);
    }

    exit(err);
}
