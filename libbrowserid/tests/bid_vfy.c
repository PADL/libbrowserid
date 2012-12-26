/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "browserid.h"
#include "bid_private.h"

int main(int argc, char *argv[])
{
    BIDError err;
    BIDContext context = NULL;
    char *a = NULL;
    unsigned char fakeChannelBindingInfo[] = { "\x7B\x28\xE1\x6E\x07\x22\xA2\x28\xEC\xBB\x38\xB5\x9E\x28\xFD" };
    size_t fakeChannelBindingLen = sizeof(fakeChannelBindingInfo) - 1;
    BIDIdentity id = NULL;
    time_t expires;
    json_t *j = NULL;
    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_GSS;

    if (argc > 1 && !strcmp(argv[1], "-remote"))
        options |= BID_CONTEXT_VERIFY_REMOTE;

    err = BIDAcquireContext(options, &context);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDuplicateString(context, "eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkRTIiwieSI6ImZhZGY1YmNhZjcyNjkzOTMzMzFlZGY2YTM0ZDE1MDIyMjllMmJhNzg4MWVkNTMyOTIzNjVkMWYyZjc2ODZlOTVkM2FjYTZiN2E3YjExZGE3YWMyMGQ4ODAyMzhhNmI0NTExZWZmNGNiNjI4YjVjMjQ0Nzc5NDg5YWMyNjQ4ZTM0ZTk3NGViYWYyNDRkN2NiNjJkZDY1YjZkYTNlMzk5MGNkZGJjYTg3ZGNiNDc5MzU1OWI2ZWExZDEyMGQ2NDdjYTMyZGNmNjZiYzA5MTRjMGJiMjg5ZTc2ZDljZjExYzc1NWVmNzI5Y2M0ZDYzMmRjNzJmNTE2ODJkMDRkNzljZTUiLCJwIjoiZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2UyM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTdlYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzNmNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDRmOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTNjODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDVkZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTMyOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDdhNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImVtYWlsIjoibHVrZWhAcGFkbC5jb20ifSwiaWF0IjoxMzU2ODM3NzYwMDU1LCJleHAiOjEzNTY4NDEzNjAwNTUsImlzcyI6ImxvZ2luLnBlcnNvbmEub3JnIn0.KD10FGgd96RRrEhg-OhGNPITzsJPxuNoSV9CHHW2S2EM_HKHqGMR3tnCefK6_x5aPd2JnxJnSWxzCTXwV940nXHPdYDabe7qavNsT6Hdchln7E0_mNmTnwOfAoenCVthJ0TdX-kD8MYpgpThLOQp0mBY15j5PATaJ2bQwVDfzezZVKJg7PSlnb6JpcpWKoeOD0O6rQdjDJ68p4znLe3fdtStDB4gAEtojtX3n8jsyAMAIIxrrkPMYVA0DUdfQRTBfgb7-cvGNWLyih9YlRQmLDvzNuyLQ5uaHD7P-1iVQRrBF_U4ib8NHOmwm1RBbvqP5YJ8OuBqxSsUgs7MT-wnwA~eyJhbGciOiJEUzEyOCJ9.eyJleHAiOjEzNTY4Mzc4ODAwODAsImF1ZCI6ImdzczovL2hvc3QucmFuZC5taXQuZGUucGFkbC5jb20uZXlqaGJnY2lvaWpzdXppMW5pajkifQ.qnRKIwXoBYsEQbVvnjmbxBMn5vkFmONIb2kF6gXKfXAl7lLziOEkFg", &a);
    BID_BAIL_ON_ERROR(err);

    err = BIDVerifyAssertion(context, a, "host/rand.mit.de.padl.com",
                             fakeChannelBindingInfo, fakeChannelBindingLen,
                             time(NULL), &id, &expires);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentityJsonObject(context, id, NULL, &j);
    BID_BAIL_ON_ERROR(err);

    json_dumpf(j, stdout, 0);
    printf("\n");

cleanup:
    json_decref(j);
    BIDFree(a);
    BIDReleaseIdentity(context, id);
    BIDReleaseContext(context);
    if (err) {
        const char *s;
        BIDErrorToString(err, &s);
        fprintf(stderr, "Error %d %s\n", err, s);
    }

    exit(err);
}
