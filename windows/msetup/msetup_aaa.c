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

static DWORD
OpenRadiusKey(HKEY hKey, PHKEY hRadiusKey)
{
    return RegCreateKeyEx(hKey,
                          L"Radius",
                          0,                /* Reserved */
                          NULL,             /* lpClass */
                          REG_OPTION_NON_VOLATILE,
                          KEY_WRITE,
                          NULL,             /* lpSecurityAttributes */
                          hRadiusKey,
                          NULL);            /* lpdwDisposition */
}

DWORD
MsAddAaaServer(
    HKEY hKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD lResult;
    HKEY hRadiusKey = NULL;
    HKEY hAaaServerKey = NULL;

    lResult = OpenRadiusKey(hKey, &hRadiusKey);
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
        lResult = RegSetValueEx(hKey, L"Secret", 0,
                                REG_SZ, (PBYTE)ServerInfo->Secret,
                                wcslen(ServerInfo->Secret) * sizeof(WCHAR));
        if (lResult != ERROR_SUCCESS)
            goto cleanup;
    }

    if (ServerInfo->Service != NULL) {
        lResult = RegSetValueEx(hKey, L"Service", 0,
                                REG_SZ, (PBYTE)ServerInfo->Service,
                                wcslen(ServerInfo->Service) * sizeof(WCHAR));
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
    HKEY hKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD lResult;
    HKEY hRadiusKey;

    lResult = OpenRadiusKey(hKey, &hRadiusKey);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    lResult = RegDeleteKey(hRadiusKey, ServerInfo->Server);

    RegCloseKey(hRadiusKey);

    return lResult;
}

