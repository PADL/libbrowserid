/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * msetup registry helper functions
 */

#include "msetup.h"

DWORD
MsOpenKey(LPWSTR wszServer, BOOLEAN fWritable, PHKEY phkResult)
{
    DWORD dwResult;
    DWORD dwAccess;
    HKEY hklm;

    if (wszServer != NULL) {
        dwResult = RegConnectRegistry(wszServer, HKEY_LOCAL_MACHINE, &hklm);
        if (dwResult != ERROR_SUCCESS)
            return dwResult;
    } else {
        hklm = HKEY_LOCAL_MACHINE;
    }

    dwAccess = KEY_READ;
    if (fWritable)
        dwAccess |= KEY_WRITE;

    dwResult = RegOpenKeyEx(hklm,
                            L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\EapSSP",
                            0, dwAccess, phkResult);

    if (wszServer != NULL)
        RegCloseKey(hklm);

    return dwResult;
}

DWORD
MsCloseKey(HKEY hKey)
{
    return RegCloseKey(hKey);
}

