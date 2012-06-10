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
OpenUserListKey(HKEY hKey, PHKEY hMapKey)
{
    return RegCreateKeyEx(hKey,
                          L"UserList",
                          0,                /* Reserved */
                          NULL,             /* lpClass */
                          REG_OPTION_NON_VOLATILE,
                          KEY_WRITE,
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
    DWORD lResult;
    HKEY hMapKey;

    lResult = OpenUserListKey(hKey, &hMapKey);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    if (wszAccount != NULL) {
        lResult = RegSetValueEx(hKey, wszPrincipal, 0,
                                REG_SZ, (PBYTE)wszAccount,
                                wcslen(wszAccount) * sizeof(WCHAR));
    } else {
        lResult = RegDeleteValue(hKey, wszPrincipal);
    }

    RegCloseKey(hMapKey);

    return lResult;
}
