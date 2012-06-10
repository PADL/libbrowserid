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
MsOpenKey(BOOLEAN fWritable, PHKEY phkResult)
{
    DWORD lResult;

    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\EapSSP",
			   0, fWritable ? KEY_WRITE : KEY_QUERY_VALUE,
                           phkResult);

    return lResult;
}

DWORD
MsCloseKey(HKEY hKey)
{
    return RegCloseKey(hKey);
}

