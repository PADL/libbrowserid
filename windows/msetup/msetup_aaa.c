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
#include <aclapi.h>

DWORD
MsOpenRadiusKey(HKEY hKey, BOOLEAN fWritable, PHKEY phRadiusKey)
{
    DWORD dwAccess;
    DWORD dwResult;

    dwAccess = KEY_READ;
    if (fWritable)
        dwAccess |= KEY_WRITE;

    dwResult = RegCreateKeyEx(hKey,
                              L"Radius",
                              0,                /* Reserved */
                              NULL,             /* lpClass */
                              REG_OPTION_NON_VOLATILE,
                              dwAccess,
                              NULL,             /* lpSecurityAttributes */
                              phRadiusKey,
                              NULL);            /* lpdwDisposition */

    return dwResult;
}

/*
 * Build a security descriptor to protect the RADIUS shared secret
 * from being read. We allow SYSTEM and Administrators full control,
 * and don't inherit any other permissions.
 */
static DWORD
BuildAaaSecurityDescriptor(PSECURITY_DESCRIPTOR *ppSD, PACL *ppACL)
{
    DWORD dwResult;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SID_IDENTIFIER_AUTHORITY SidAuthNT = SECURITY_NT_AUTHORITY;
    PSID pLocalSystemSid = NULL;
    PSID pAdministratorsSid = NULL;
    EXPLICIT_ACCESS ea[2] = { 0 };
    PACL pACL = NULL;

    *ppSD = NULL;
    *ppACL = NULL;

    if (!AllocateAndInitializeSid(&SidAuthNT, 1,
                                  SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0,
                                  &pLocalSystemSid)) {
        dwResult = GetLastError();
        goto cleanup;
    }

    ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pLocalSystemSid;

    if (!AllocateAndInitializeSid(&SidAuthNT, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &pAdministratorsSid)) {
        dwResult = GetLastError();
        goto cleanup;
    }

    ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pAdministratorsSid;

    dwResult = SetEntriesInAcl(sizeof(ea) / sizeof(ea[0]), ea, NULL, &pACL);
    if (dwResult != ERROR_SUCCESS) {
        fwprintf(stderr, L"Failed to SetEntriesInAcl: %08x\n", dwResult);
        goto cleanup;
    }

    pSD = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (pSD == NULL) {
        dwResult = GetLastError();
        goto cleanup;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"Failed to InitializeSecurityDescriptor: %08x\n", dwResult);
        goto cleanup;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"Failed to SetSecurityDescriptorDacl: %08x\n", dwResult);
        goto cleanup;
    }

    *ppSD = pSD;
    pSD = NULL;

    *ppACL = pACL;
    pACL = NULL;

cleanup:
    if (pLocalSystemSid != NULL)
        LocalFree(pLocalSystemSid);
    if (pAdministratorsSid != NULL)
        LocalFree(pAdministratorsSid);
    if (pACL != NULL)
        LocalFree(pACL);
    if (pSD != NULL)
        LocalFree(pSD);

    return dwResult;
}

DWORD
MsAddAaaServer(
    HKEY hSspKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD dwResult;
    HKEY hRadiusKey = NULL;
    HKEY hAaaServerKey = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pACL = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };

    dwResult = MsOpenRadiusKey(hSspKey, TRUE, &hRadiusKey);
    if (dwResult != ERROR_SUCCESS)
        goto cleanup;

    dwResult = BuildAaaSecurityDescriptor(&pSD, &pACL);
    if (dwResult != ERROR_SUCCESS)
        goto cleanup;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    dwResult = RegCreateKeyEx(hRadiusKey,
                              ServerInfo->Server,
                              0,             /* Reserved */
                              NULL,          /* lpClass */
                              REG_OPTION_NON_VOLATILE,
                              KEY_WRITE,
                              &sa,
                              &hAaaServerKey,
                              NULL);
    if (dwResult != ERROR_SUCCESS)
        goto cleanup;

    if (ServerInfo->Secret != NULL) {
        dwResult = RegSetValueEx(hAaaServerKey, L"Secret", 0,
                                 REG_SZ, (PBYTE)ServerInfo->Secret,
                                 (wcslen(ServerInfo->Secret) + 1) * sizeof(WCHAR));
        if (dwResult != ERROR_SUCCESS)
            goto cleanup;
    }

    if (ServerInfo->Service != NULL) {
        dwResult = RegSetValueEx(hAaaServerKey, L"Service", 0,
                                 REG_SZ, (PBYTE)ServerInfo->Service,
                                 (wcslen(ServerInfo->Service) + 1) * sizeof(WCHAR));
        if (dwResult != ERROR_SUCCESS)
            goto cleanup;
    }

cleanup:
    if (pSD != NULL)
        LocalFree(pSD);
    if (pACL != NULL)
        LocalFree(pACL);
    if (hAaaServerKey != NULL)
        RegCloseKey(hAaaServerKey);
    if (hRadiusKey != NULL)
        RegCloseKey(hRadiusKey);

    return dwResult;
}

DWORD
MsDeleteAaaServer(
    HKEY hSspKey,
    PAAA_SERVER_INFO ServerInfo)
{
    DWORD dwResult;
    HKEY hRadiusKey;

    dwResult = MsOpenRadiusKey(hSspKey, TRUE, &hRadiusKey);
    if (dwResult != ERROR_SUCCESS)
        return dwResult;

    dwResult = RegDeleteKey(hRadiusKey, ServerInfo->Server);

    RegCloseKey(hRadiusKey);

    return dwResult;
}

