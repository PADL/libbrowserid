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
MsOpenUserListKey(HKEY hKey, BOOLEAN fWritable, PHKEY hMapKey)
{
    return RegCreateKeyEx(hKey,
                          L"UserList",
                          0,                /* Reserved */
                          NULL,             /* lpClass */
                          REG_OPTION_NON_VOLATILE,
                          (fWritable ? KEY_WRITE : KEY_READ) | KEY_QUERY_VALUE,
                          NULL,             /* lpSecurityAttributes */
                          hMapKey,
                          NULL);            /* lpdwDisposition */
}

DWORD
MsMapUser(
    HKEY hKey,
    LPCWSTR wszPrincipal,
    LPCWSTR wszAccount)
{
    DWORD dwResult;
    HKEY hMapKey;

    dwResult = MsOpenUserListKey(hKey, TRUE, &hMapKey);
    if (dwResult != ERROR_SUCCESS)
        return dwResult;

    if (wszAccount != NULL) {
        dwResult = RegSetValueEx(hMapKey, wszPrincipal, 0,
                                 REG_SZ, (PBYTE)wszAccount,
                                 (wcslen(wszAccount) + 1) * sizeof(WCHAR));
    } else {
        dwResult = RegDeleteValue(hMapKey, wszPrincipal);
    }

    RegCloseKey(hMapKey);

    return dwResult;
}

DWORD
MsQueryUser(
    HKEY hKey,
    DWORD dwUserIndex,
    LPWSTR *outUser,
    LPWSTR *outAccount)
{
    DWORD dwResult;
    HKEY hMapKey=NULL;
    LPWSTR tmpUser=NULL;
    LPWSTR tmpAccount=NULL;
    WCHAR wszUser[256];
    WCHAR wszAccount[256];
    DWORD cchUser = sizeof(wszUser) / sizeof(wszUser[0]);
    DWORD cchAccount = sizeof(wszAccount) / sizeof(wszAccount[0]);

    dwResult = MsOpenUserListKey(hKey, TRUE, &hMapKey);
    if (dwResult != ERROR_SUCCESS)
        goto cleanup;

    dwResult = RegEnumValue(hMapKey, dwUserIndex, wszUser, &cchUser,
                            NULL, NULL, (PBYTE)(&wszAccount[0]), &cchAccount);
    if (dwResult == ERROR_NO_MORE_ITEMS) {
        goto cleanup;
    } else if (dwResult != ERROR_SUCCESS) {
        fwprintf(stderr, L"Failed enumerating user mapping value", dwResult);
        goto cleanup;
    }

    tmpUser = HeapAlloc(GetProcessHeap(), 0, (cchUser+1)*sizeof(tmpUser[0]));
    if (tmpUser==NULL)
        goto cleanup;
    tmpAccount = HeapAlloc(GetProcessHeap(), 0, (cchAccount+1)*sizeof(tmpAccount[0]));
    if (tmpAccount==NULL)
        goto cleanup;

    memcpy(tmpUser, wszUser, cchUser * sizeof(wszUser[0]));
    tmpUser[cchUser] = 0;
    memcpy(tmpAccount, wszAccount, cchAccount * sizeof(wszAccount[0]));
    tmpAccount[cchAccount] = 0;
    *outUser = tmpUser;
    tmpUser = NULL;
    *outAccount = tmpAccount;
    tmpAccount = NULL;
cleanup:
    if (hMapKey)
        RegCloseKey(hMapKey);
    if (tmpUser)
        HeapFree(GetProcessHeap(), 0, tmpUser);
    if (tmpAccount)
        HeapFree(GetProcessHeap(), 0, tmpAccount);
    return dwResult;
}