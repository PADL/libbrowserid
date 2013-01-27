/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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
    "Diffie-Helman check not prime",
    "Diffie-Helman check not safe prime",
    "Diffie-Helman not suitable generator",
    "Diffie-Helman unable to check generator",
    "No ticket cache",
    "Corrupted ticket cache",
    "Expired ticket",
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

