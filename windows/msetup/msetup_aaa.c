/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * msetup user map helper functions
 */

#include "msetup.h"

DWORD
MsOpenRadiusKey(HKEY hKey, BOOLEAN fWritable, PHKEY phRadiusKey)
{
    DWORD dwAccess;
    DWORD lResult;

    dwAccess = KEY_READ;
    if (fWritable)
        dwAccess |= KEY_WRITE;

    lResult = RegCreateKeyEx(hKey,
                             L"Radius",
                             0,                /* Reserved */
                             NULL,             /* lpClass */
                             REG_OPTION_NON_VOLATILE,
                             dwAccess,
                             NULL,             /* lpSecurityAttributes */
                             phRadiusKey,
                             NULL);            /* lpdwDisposition */
    return lResult;
}

DWORD
MsAddAaaServer(
    HKEY hSspKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD lResult;
    HKEY hRadiusKey = NULL;
    HKEY hAaaServerKey = NULL;

    lResult = MsOpenRadiusKey(hSspKey, TRUE, &hRadiusKey);
    if (lResult != ERROR_SUCCESS)
        goto cleanup;

    lResult = RegCreateKeyEx(hRadiusKey,
                             ServerInfo->Server,
                             0,             /* Reserved */
                             NULL,          /* lpClass */
                             REG_OPTION_NON_VOLATILE,
                             KEY_WRITE,
                             NULL,
                             &hAaaServerKey,
                             NULL);
    if (lResult != ERROR_SUCCESS)
        goto cleanup;

    if (ServerInfo->Secret != NULL) {
        lResult = RegSetValueEx(hAaaServerKey, L"Secret", 0,
                                REG_SZ, (PBYTE)ServerInfo->Secret,
                                (wcslen(ServerInfo->Secret) + 1) * sizeof(WCHAR));
        if (lResult != ERROR_SUCCESS)
            goto cleanup;
    }

    if (ServerInfo->Service != NULL) {
        lResult = RegSetValueEx(hAaaServerKey, L"Service", 0,
                                REG_SZ, (PBYTE)ServerInfo->Service,
                                (wcslen(ServerInfo->Service) + 1) * sizeof(WCHAR));
        if (lResult != ERROR_SUCCESS)
            goto cleanup;
    }

cleanup:
    if (hAaaServerKey != NULL)
        RegCloseKey(hAaaServerKey);
    if (hRadiusKey != NULL)
        RegCloseKey(hRadiusKey);

    return lResult;
}

DWORD
MsDeleteAaaServer(
    HKEY hSspKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD lResult;
    HKEY hRadiusKey;

    lResult = MsOpenRadiusKey(hSspKey, TRUE, &hRadiusKey);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    lResult = RegDeleteKey(hRadiusKey, ServerInfo->Server);

    RegCloseKey(hRadiusKey);

    return lResult;
}

