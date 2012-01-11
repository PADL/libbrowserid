/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Install a security package without rebooting system
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <sspi.h>
#include <stdio.h>

typedef SECURITY_STATUS
(AddSecurityPackageFn)(LPWSTR, PSECURITY_PACKAGE_OPTIONS);

typedef SECURITY_STATUS
(DeleteSecurityPackageFn)(LPWSTR);

static AddSecurityPackageFn *pfnAddSecurityPackage;
static DeleteSecurityPackageFn *pfnDeleteSecurityPackage;

BOOL APIENTRY
DllMain(
    HANDLE hModule,
    DWORD ulReasonForCall,
    LPVOID lpSReserved)
{
    return TRUE;
}

static HMODULE
LoadSecur32(void)
{
    return LoadLibrary(L"SECUR32.DLL");
}

BOOLEAN
IsPackageInstalled(LPWSTR wszSspName)
{
    DWORD dwStatus;
    DWORD i;
    ULONG cPackages;
    PSecPkgInfo pPackages;
    BOOLEAN bPackageInstalled = FALSE;

    dwStatus = EnumerateSecurityPackages(&cPackages, &pPackages);
    if (dwStatus != ERROR_SUCCESS)
        return FALSE;

    for (i = 0; i < cPackages; i++) {
        if (pPackages[i].Name != NULL &&
            wcsicmp(pPackages[i].Name, wszSspName) == 0) {
            bPackageInstalled = TRUE;
            break;
        }
    }

    return bPackageInstalled;
}

VOID
LogPackageInstall(MSIHANDLE hModule, LPWSTR pwszMessage)
{
    MSIHANDLE hRecord;
    UINT uiStatus;

    hRecord = MsiCreateRecord(1);
    if (hRecord == 0)
        return;

    uiStatus = MsiRecordSetString(hRecord, 0, pwszMessage);
    if (uiStatus != ERROR_SUCCESS) {
        MsiCloseHandle(hRecord);
        return;
    }

    MsiProcessMessage(hModule, INSTALLMESSAGE_INFO, hRecord);
    MsiCloseHandle(hRecord);
}

UINT __stdcall
InstallSecurityPackage(MSIHANDLE hModule)
{
    UINT uiStatus;
    WCHAR wszSspName[MAX_PATH];
    DWORD cbSspName = sizeof(wszSspName);
    SECURITY_PACKAGE_OPTIONS Options;

    if (pfnAddSecurityPackage == NULL) {
        HMODULE hSecur32 = LoadSecur32();

        if (hSecur32 == NULL)
            return GetLastError();

        pfnAddSecurityPackage = (AddSecurityPackageFn *)GetProcAddress(hSecur32, "AddSecurityPackageW");
        if (pfnAddSecurityPackage == NULL) {
            LogPackageInstall(hModule, L"This version of Windows does not support AddSecurityPackage");
            return ERROR_SUCCESS;
        }
    }

    uiStatus = MsiGetProperty(hModule, L"CustomActionData",
                              wszSspName, &cbSspName);
    if (uiStatus != ERROR_SUCCESS) {
        LogPackageInstall(hModule, L"No CustomActionData");
        return uiStatus;
    }

    LogPackageInstall(hModule, L"Attempting to add security package");
    LogPackageInstall(hModule, wszSspName);

    if (!IsPackageInstalled(wszSspName)) {
        memset(&Options, 0, sizeof(Options));

        Options.Size = sizeof(Options);
        Options.Type = SECPKG_OPTIONS_TYPE_UNKNOWN;
        Options.Flags = SECPKG_OPTIONS_PERMANENT;

        uiStatus = (*pfnAddSecurityPackage)(wszSspName, &Options);
    }

    if (uiStatus == ERROR_SUCCESS) {
        LogPackageInstall(hModule, L"Added security package");
    } else {
        LogPackageInstall(hModule, L"Failed to add security package");
        _snwprintf(wszSspName, sizeof(wszSspName), L"%08x", uiStatus);
        LogPackageInstall(hModule, wszSspName);
    }

    return uiStatus;
}

UINT __stdcall
UninstallSecurityPackage(MSIHANDLE hModule)
{
    UINT uiStatus;
    WCHAR wszSspName[MAX_PATH];
    DWORD cbSspName = sizeof(wszSspName);

    if (pfnDeleteSecurityPackage == NULL) {
        HMODULE hSecur32 = LoadSecur32();

        if (hSecur32 == NULL)
            return GetLastError();

        pfnDeleteSecurityPackage = (DeleteSecurityPackageFn *)GetProcAddress(hSecur32, "DeleteSecurityPackageW");
        if (pfnDeleteSecurityPackage == NULL) {
            LogPackageInstall(hModule, L"This version of Windows does not support DeleteSecurityPackage");
            return ERROR_SUCCESS;
        }
    }

    uiStatus = MsiGetProperty(hModule, L"CustomActionData",
                              wszSspName, &cbSspName);
    if (uiStatus != ERROR_SUCCESS) {
        LogPackageInstall(hModule, L"No CustomActionData");
        return uiStatus;
    }

    if (IsPackageInstalled(wszSspName))
        uiStatus = (*pfnDeleteSecurityPackage)(wszSspName);

    if (uiStatus == ERROR_SUCCESS)
        LogPackageInstall(hModule, L"Deleted security package");
    else
        LogPackageInstall(hModule, L"Failed to delete security package");

    return uiStatus;
}
