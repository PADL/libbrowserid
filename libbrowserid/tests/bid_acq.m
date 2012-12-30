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

#include <AppKit/AppKit.h>

#ifdef BUILD_AS_DSO
int _BIDTestAcquire(void)
#else
int main(int argc, const char *argv[])
#endif
{
    BIDError err;
    BIDContext context = NULL;
    char *assertion = NULL;
    const char *s;
    BIDIdentity identity = NULL;
#if 1
    unsigned char *fakeChannelBindingInfo = NULL;
    size_t fakeChannelBindingLen = 0;
#else
    unsigned char fakeChannelBindingInfo[] = { "\x7B\x28\xE1\x6E\x07\x22\xA2\x28\xEC\xBB\x38\xB5\x9E\x28\xFD" };
    size_t fakeChannelBindingLen = sizeof(fakeChannelBindingInfo) - 1;
#endif
    time_t expires;
    json_t *j = NULL;

#ifdef __APPLE__
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToUIElementApplication);
#endif

    uint32_t options = BID_CONTEXT_RP | BID_CONTEXT_GSS;

#ifndef BUILD_AS_DSO
    if (argc > 1 && !strcmp(argv[1], "-remote"))
        options |= BID_CONTEXT_VERIFY_REMOTE;
#endif

    err = BIDAcquireContext(options, &context);
    BID_BAIL_ON_ERROR(err);

#if 1
//    err = _BIDBrowserGetAssertion(context, "gss://host.rand.mit.de.padl.com.eyJhbGciOiJSUzI1NiJ9", &assertion);
    err = _BIDBrowserGetAssertion(context, "gss://host.rand.mit.de.padl.com.", &assertion);
    BID_BAIL_ON_ERROR(err);
#else
    assertion = strdup("eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkRTIiwieSI6IjlmZGU3NmMxNzY1NTVhYjk4MmU5ZGExNzBhZmRiMmQ0ZWUzYmQ1MjNhNTAxM2ViZDNmYWI4MjNhNTY3NzE2NGVkZjk3YmVkZmIwZjZhNjI2MjE4ODY3YzFhMTQzNDA0M2JlZTVlN2RhZTJiNWE5NmMyZGExYTVjOGEyMDAxNDdmZGE4MThlNjJhM2NiOTU5NTBiYzQ2OWRmY2VmNGI0NzA0NTQ5MTZiNTc4ZDkxMDQ2MDk4NTdiNmZiZDFiODI1MThlMjI0MWM5NTZlZTFiZGE1NjJiNjVkNDkzMTI2Y2MxMjZmZjY4ZmFlYzIzZTU2ZmViZDg0OTU3NDhmYTY0ZWQiLCJwIjoiZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2UyM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTdlYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzNmNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDRmOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTNjODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDVkZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTMyOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDdhNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImVtYWlsIjoibHVrZWhAcGFkbC5jb20ifSwiaWF0IjoxMzU2NzgzOTc3ODkxLCJleHAiOjEzNTY3ODc1Nzc4OTEsImlzcyI6ImxvZ2luLnBlcnNvbmEub3JnIn0.GloqzzHFYxd-K16UV-p67GzDehLn_bwizWddrB9X3ZwpIcXSPxMRC_9N4XW1wsK-wMlDXUigtOFd0ryLJitzyMDVpvk417EaC7LpMghkDwon5x-OiUVf9OnZPdownWI6gb4t8ovQ5UkzHe6piGbF51WhrmLZJSWEiP-m1D6d47vF8yDNrR4XiJxnf3gOdOMRPv5Sjg-zR2Dx2GE9l-qLZPktSnxrulmF1rmCowMdD21GAmuzR6_Tgzs22WecBTdI_nEFnGqjrmllhnPjWgm2teW-27gdHv7LX6kK-ZgElQEGQnYMrfxSI5k3f7LNVIyo5_BMhsqgfTcQLnlIwJnkvw~eyJhbGciOiJEUzEyOCJ9.eyJleHAiOjEzNTY3ODQwOTc5MTQsImF1ZCI6ImdzczovL2hvc3QucmFuZC5taXQuZGUucGFkbC5jb20uZXlqaGJnY2lvaWpzdXppMW5pajkifQ.3Lz2ewURvPvuwNaQLO58LHiEyUKb1wf1xr-WxhjSlNIuHUwy12XDYA");
#endif

    err = BIDVerifyAssertion(context, assertion, "host/rand.mit.de.padl.com",
                             fakeChannelBindingInfo, fakeChannelBindingLen,
                             time(NULL), &identity, &expires);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetIdentityJsonObject(context, identity, NULL, &j);
    BID_BAIL_ON_ERROR(err);

    json_dumpf(j, stdout, 0);

cleanup:
    BIDReleaseIdentity(context, identity);
    BIDReleaseContext(context);
    BIDFree(assertion);
    json_decref(j);

    if (err != BID_S_OK) {
        BIDErrorToString(err, &s);
        fprintf(stderr, "Error %d %s\n", err, s);
    }

    exit(err);
}
