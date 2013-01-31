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

#include "bid_private.h"

const char *_BIDErrorTable[] = {
    "Success",
    "No context",
    "Out of memory",
    "Not implemented",
    "Invalid parameter",
    "Invalid usage",
    "Unavailable",
    "Unknown JSON key",
    "Invalid JSON",
    "Invalid Base64",
    "Invalid assertion",
    "Cannot encode JSON",
    "Cannot encode Base64",
    "Too many certs",
    "Untrusted issuer",
    "invalid issuer",
    "Missing issuer",
    "Missing audience",
    "Bad audience",
    "Assertion expired",
    "Assertion not yet valid",
    "Certificate expired",
    "Certificate not yet valid",
    "Invalid signature",
    "Missing algorithm",
    "Unknown algorithm",
    "Invalid key",
    "Invalid key set",
    "No key",
    "Internal crypto error",
    "HTTP error",
    "Buffer too small",
    "Buffer too large",
    "Remote verification failure",
    "Missing principal",
    "Unknown principal type",
    "Missing certificate",
    "Unknown attribute",
    "Missing channel bindings",
    "Channel bindings mismatch",
    "No session key",
    "Document not modified",
    "Process does not support UI interaction",
    "Failed to acquire assertion interactively",
    "Interaction required to acquire assertion",
    "Invalid audience URN",
    "Invalid JSON web token",
    "No more items",
    "Cache open error",
    "Cache read error",
    "Cache write error",
    "Cache close error",
    "Cache lock error",
    "Cache lock timed out",
    "Cache unlock error",
    "Cache delete error",
    "Cache permission denied",
    "Invalid cache version",
    "Cache scheme unknown",
    "Cache already exists",
    "Cache not found",
    "Cache key not found",
    "Assertion is a replay",
    "Failed to generate Diffie-Hellman parameters",
    "Failed to generate Diffie-Hellman key",
    "No ticket cache",
    "Corrupted ticket cache",
    "Certificate file unreadable",
    "Private key file unreadable",
    "Untrusted X.509 relying party certificate",
    "Assertion is not re-authentication assertion",
    "Bad subject name",
    "Response from relying party does not match request",
    "JSON web token is missing signature",
    "Invalid secret handle",
    "Unknown error code"
};

BIDError
BIDErrorToString(
    BIDError error,
    const char **pszErr)
{
    *pszErr = NULL;

    if (pszErr == NULL)
        return BID_S_INVALID_PARAMETER;

    if (error < BID_S_OK || error > BID_S_UNKNOWN_ERROR_CODE)
        return BID_S_UNKNOWN_ERROR_CODE;

    *pszErr = _BIDErrorTable[error];
    return BID_S_OK;
}
