/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"
#include "bid_private.h"

/*
 * Test Base64 encoders.
 */
static void dump(unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        printf("%02x", data[i] & 0xff);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    BIDError err;
    unsigned char *data = NULL;
    size_t len;

    err = _BIDBase64UrlDecode("eyJhbGciOiJSUzI1NiJ9", &data, &len);
    if (err == BID_S_OK)
        printf("%.*s\n", (int)len, data);
    else
        fprintf(stderr, "Error %d\n", err);

    BIDFree(data);
    data = NULL;

    /* should fail */
    err = _BIDBase64UrlDecode("eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkRTIiwieSI6IjlmZGU3NmMxNzY1NTVhYjk4MmU5ZGExNzBhZmRiMmQ0ZWUzYmQ1MjNhNTAxM2ViZDNmYWI4MjNhNTY3NzE2NGVkZjk3YmVkZmIwZjZhNjI2MjE4ODY3YzFhMTQzNDA0M2JlZTVlN2RhZTJiNWE5NmMyZGExYTVjOGEyMDAxNDdmZGE4MThlNjJhM2NiOTU5NTBiYzQ2OWRmY2VmNGI0NzA0NTQ5MTZiNTc4ZDkxMDQ2MDk4NTdiNmZiZDFiODI1MThlMjI0MWM5NTZlZTFiZGE1NjJiNjVkNDkzMTI2Y2MxMjZmZjY4ZmFlYzIzZTU2ZmViZDg0OTU3NDhmYTY0ZWQiLCJwIjoiZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2UyM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTdlYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzNmNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDRmOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTNjODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDVkZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTMyOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDdhNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImVtYWlsIjoibHVrZWhAcGFkbC5jb20ifSwiaWF0IjoxMzU2NzgzOTc3ODkxLCJleHAiOjEzNTY3ODc1Nzc4OTEsImlzcyI6ImxvZ2luLnBlcnNvbmEub3JnIn0.GloqzzHFYxd-K16UV-p67GzDehLn_bwizWddrB9X3ZwpIcXSPxMRC_9N4XW1wsK-wMlDXUigtOFd0ryLJitzyMDVpvk417EaC7LpMghkDwon5x-OiUVf9OnZPdownWI6gb4t8ovQ5UkzHe6piGbF51WhrmLZJSWEiP-m1D6d47vF8yDNrR4XiJxnf3gOdOMRPv5Sjg-zR2Dx2GE9l-qLZPktSnxrulmF1rmCowMdD21GAmuzR6_Tgzs22WecBTdI_nEFnGqjrmllhnPjWgm2teW-27gdHv7LX6kK-ZgElQEGQnYMrfxSI5k3f7LNVIyo5_BMhsqgfTcQLnlIwJnkvw", &data, &len);
    if (err == BID_S_OK)
        dump(data, len);
    else 
        fprintf(stderr, "(should fail) Error %d\n", err);

    BIDFree(data);
    exit(err);
}
