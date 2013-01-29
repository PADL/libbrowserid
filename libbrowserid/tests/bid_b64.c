/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
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
