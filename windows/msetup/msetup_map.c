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
                          fWritable ? KEY_WRITE : KEY_QUERY_VALUE,
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

    lResult = MsOpenUserListKey(hKey, TRUE, &hMapKey);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    if (wszAccount != NULL) {
        lResult = RegSetValueEx(hMapKey, wszPrincipal, 0,
                                REG_SZ, (PBYTE)wszAccount,
                                (wcslen(wszAccount) + 1) * sizeof(WCHAR));
    } else {
        lResult = RegDeleteValue(hMapKey, wszPrincipal);
    }

    RegCloseKey(hMapKey);

    return lResult;
}
