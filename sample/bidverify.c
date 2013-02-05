#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"

int main(int argc, const char *argv[])
{
    BIDError err;
    BIDContext context = NULL;
    BIDIdentity identity = NULL;
    time_t expires;
    uint32_t flags = 0;
    const char *iss = NULL, *sub = NULL;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s audience assertion\n", argv[0]);
        exit(BID_S_INVALID_PARAMETER);
    }

    err = BIDAcquireContext(BID_CONTEXT_RP | BID_CONTEXT_AUTHORITY_CACHE, &context);
    if (err != BID_S_OK)
        goto cleanup;

    err = BIDVerifyAssertion(context, BID_C_NO_REPLAY_CACHE,
                             argv[2], argv[1],
                             NULL, 0, time(NULL), 0, &identity,
                             &expires, &flags);
    if (err != BID_S_OK)
        goto cleanup;

    printf("Expires: %s", ctime(&expires));
    if (BIDGetIdentitySubject(context, identity, &sub) == BID_S_OK)
        printf("Subject: %s\n", sub);
    if (BIDGetIdentityIssuer(context, identity, &iss) == BID_S_OK)
        printf("Issuer:  %s\n", sub);

cleanup:
    if (context != BID_C_NO_CONTEXT) {
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
