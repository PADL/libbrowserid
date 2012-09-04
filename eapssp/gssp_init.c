/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * SSP initialization routines
 */

#include "gssp.h"

PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = NULL;

static SpGetInfoFn SpGetInfoEapAes128;
static SpGetInfoFn SpGetInfoEapAes256;

SECPKG_PARAMETERS SpParameters;
ULONG GsspFlags = 0;
LUID GsspTokenSourceId = { 0, 0 };

/*
 * Dynamically load these as they may not be present on Windows XP.
 */
CredIsProtectedFn *pfnCredIsProtected = NULL;
CredProtectFn *pfnCredProtect         = NULL;
CredUnprotectFn *pfnCredUnprotect     = NULL;

static HMODULE hAdvApi32 = NULL;

DWORD
GsspGetRegFlags(void)
{
    DWORD dwResult;
    DWORD dwEapSspFlags = 0;
    HKEY hKey;

    dwResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\EapSSP",
                            0, KEY_QUERY_VALUE, &hKey);
    if (dwResult == ERROR_SUCCESS) {
        DWORD dwType = REG_DWORD;
        DWORD dwSize = sizeof(dwEapSspFlags);

        RegQueryValueEx(hKey, L"Flags", NULL, &dwType,
                        (PBYTE)&dwEapSspFlags, &dwSize);
        RegCloseKey(hKey);
    }

#ifdef DEBUG
    /* Debug builds always have debugging enabled */
    dwEapSspFlags |= GSSP_FLAG_DEBUG;
#endif

    return dwEapSspFlags & GSSP_FLAG_REG_MASK;
}

static SECPKG_FUNCTION_TABLE EapAesFunctionTable[] = {
{
    LsaApInitializePackage,
    NULL,   /* LsaApLogonUser */
    NULL,   /* LsaApCallPackage */
    LsaApLogonTerminated,
    NULL,   /* LsaApCallPackagedUntrusted */
    NULL,   /* LsaApCallPackagePassthrough */
    NULL,   /* LsaApLogonUserEx */
    (PLSA_AP_LOGON_USER_EX2)LsaApLogonUserEx2,
    SpInitialize,
    SpShutdown,
    SpGetInfoEapAes256,
    SpAcceptCredentialsEapAes256,
    SpAcquireCredentialsHandleEapAes256,
    SpQueryCredentialsAttributes,
    SpFreeCredentialsHandle,
    SpSaveCredentials,
    SpGetCredentials,
    SpDeleteCredentials,
    SpInitLsaModeContextEapAes256,
    SpAcceptLsaModeContext,
    SpDeleteContext,
    SpApplyControlToken,
    SpGetUserInfo,
    SpGetExtendedInformationEapAes256,
    SpQueryContextAttributes,
    SpAddCredentials,
    SpSetExtendedInformation,
    SpSetContextAttributes,
    SpSetCredentialsAttributes,
    NULL,   /* SpChangeAccountPassword */
    SpQueryMetaData,
    SpExchangeMetaData,
    SpGetCredUIContext,
    SpUpdateCredentials,
    SpValidateTargetInfo
},
{
    LsaApInitializePackage,
    NULL,   /* LsaApLogonUser */
    NULL,   /* LsaApCallPackage */
    LsaApLogonTerminated,
    NULL,   /* LsaApCallPackagedUntrusted */
    NULL,   /* LsaApCallPackagePassthrough */
    NULL,   /* LsaApLogonUserEx */
    (PLSA_AP_LOGON_USER_EX2)LsaApLogonUserEx2,
    SpInitialize,
    SpShutdown,
    SpGetInfoEapAes128,
    SpAcceptCredentialsEapAes128,
    SpAcquireCredentialsHandleEapAes128,
    SpQueryCredentialsAttributes,
    SpFreeCredentialsHandle,
    SpSaveCredentials,
    SpGetCredentials,
    SpDeleteCredentials,
    SpInitLsaModeContextEapAes128,
    SpAcceptLsaModeContext,
    SpDeleteContext,
    SpApplyControlToken,
    SpGetUserInfo,
    SpGetExtendedInformationEapAes128,
    SpQueryContextAttributes,
    SpAddCredentials,
    SpSetExtendedInformation,
    SpSetContextAttributes,
    SpSetCredentialsAttributes,
    NULL,   /* SpChangeAccountPassword */
    SpQueryMetaData,
    SpExchangeMetaData,
    SpGetCredUIContext,
    SpUpdateCredentials,
    SpValidateTargetInfo
}
};

extern const char SGS_VERS[];

NTSTATUS NTAPI
SpInitialize(
    IN ULONG_PTR PackageId,
    IN PSECPKG_PARAMETERS Parameters,
    IN PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    NTSTATUS Status;

    /* Only initialize us once */
    if (LsaSpFunctionTable == NULL) {
        LsaSpFunctionTable = FunctionTable;

        GsspSetAllocFree(LsaSpFunctionTable->AllocateLsaHeap,
                         LsaSpFunctionTable->FreeLsaHeap);

        Status = NtAllocateLocallyUniqueId(&GsspTokenSourceId);
        GSSP_BAIL_ON_ERROR(Status);

        RtlZeroMemory(&SpParameters, sizeof(SpParameters));

        SpParameters.Version      = Parameters->Version;
        SpParameters.MachineState = Parameters->MachineState;
        SpParameters.SetupMode    = Parameters->SetupMode;

        if (Parameters->DomainSid != NULL) {
            Status = GsspDuplicateSid(Parameters->DomainSid,
                                      FALSE, &SpParameters.DomainSid);
            GSSP_BAIL_ON_ERROR(Status);
        }

        Status = GsspDuplicateUnicodeString(&Parameters->DomainName,
                                            FALSE, &SpParameters.DomainName);
        GSSP_BAIL_ON_ERROR(Status);
                                            
        Status = GsspDuplicateUnicodeString(&Parameters->DnsDomainName,
                                            FALSE, &SpParameters.DnsDomainName);
        GSSP_BAIL_ON_ERROR(Status);

        RtlCopyMemory(&SpParameters.DomainGuid,
                      &Parameters->DomainGuid, sizeof(GUID));

        GsspFlags |= GsspGetRegFlags();
        GsspInitializeCredList();

        hAdvApi32 = LoadLibrary(L"Advapi32.dll");
        if (hAdvApi32 != NULL) {
            /* Cred API for LsaLogonUserEx2 */
            pfnCredIsProtected = (CredIsProtectedFn *)
                GetProcAddress(hAdvApi32, "CredIsProtectedW");
            pfnCredProtect     = (CredProtectFn *)
                GetProcAddress(hAdvApi32, "CredProtectW");
            pfnCredUnprotect   = (CredUnprotectFn *)
                GetProcAddress(hAdvApi32, "CredUnprotectW");

            /* Event API for tracing */
            GsspInitEvent(hAdvApi32);
        }

        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"Starting %S", SGS_VERS);
    }

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"SpInitialize: Entered with package ID %d version %08x",
                   PackageId, Parameters->Version);

    Status = STATUS_SUCCESS;

cleanup:
    return Status;
}

NTSTATUS NTAPI
SpShutdown(VOID)
{
    /* Only shutdown us once */
    if (LsaSpFunctionTable != NULL) {
        GsspFree(SpParameters.DomainSid);
        GsspFreeUnicodeString(&SpParameters.DomainName);
        GsspFreeUnicodeString(&SpParameters.DnsDomainName);
        RtlZeroMemory(&SpParameters, sizeof(SpParameters));
        GsspShutdownEvent();
        if (hAdvApi32 != NULL)
            FreeLibrary(hAdvApi32);

        GsspDeleteCredList();
        GsspSetAllocFree(NULL, NULL);
        LsaSpFunctionTable = NULL;
        GsspFlags = 0;
        hAdvApi32 = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
SpLsaModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_FUNCTION_TABLE *ppTables,
    OUT PULONG pcTables)
{
    NTSTATUS Status;
    RTL_OSVERSIONINFOW VersionInfo;

    *PackageVersion = 0;
    *ppTables = NULL;
    *pcTables = 0;

    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                        L"SpLsaModeInitialize: unsupported SPM version %08x", LsaVersion);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    Status = RtlGetVersion(&VersionInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    if (VersionInfo.dwMajorVersion > 6) {
        *PackageVersion = SECPKG_INTERFACE_VERSION_6;           /* newer */
    } else if (VersionInfo.dwMajorVersion == 6) {
        if (VersionInfo.dwMinorVersion >= 1)
            *PackageVersion = SECPKG_INTERFACE_VERSION_6;       /* Win7/8 */
        else if (VersionInfo.dwMinorVersion == 0)
            *PackageVersion = SECPKG_INTERFACE_VERSION_4;       /* Vista */
    } else if (VersionInfo.dwMajorVersion == 5) {
        if (VersionInfo.dwMinorVersion == 2)
            *PackageVersion = SECPKG_INTERFACE_VERSION_3;       /* W2K3 */
        else if (VersionInfo.dwMinorVersion == 1)
            *PackageVersion = SECPKG_INTERFACE_VERSION_2;       /* XP */
    }

    if (*PackageVersion == 0) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                        L"SpLsaModeInitialize: not supported on this version of Windows");
        return STATUS_NOT_SUPPORTED;
    }

    /*
     * Interactive logon support (FLAG_LOGON) implies storing logon
     * credentials for use by network authentication mechanism
     * (FLAG_LOGON_CREDS), although the latter can be set explicitly.
     */
    if (GsspFlags & GSSP_FLAG_LOGON)
        GsspFlags |= GSSP_FLAG_LOGON_CREDS;
    if (*PackageVersion >= SECPKG_INTERFACE_VERSION_4)
        GsspFlags |= GSSP_FLAG_UPLEVEL;
    if (VersionInfo.dwMajorVersion > 6 ||
        (VersionInfo.dwMajorVersion == 6 && VersionInfo.dwMinorVersion >= 2))
        GsspFlags |= GSSP_FLAG_TOKEN_CLAIMS;

    *ppTables = EapAesFunctionTable;
    *pcTables = sizeof(EapAesFunctionTable) / sizeof(EapAesFunctionTable[0]);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
GsspGetInfo(IN gss_OID Oid, OUT PSecPkgInfo PackageInfo)
{
    RtlZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities = EAPSSP_PACKAGE_CAPABILITIES;
#ifndef GSSEAP_ENABLE_ACCEPTOR
    PackageInfo->fCapabilities |= SECPKG_FLAG_CLIENT_ONLY;
#endif
    if (GsspFlags & GSSP_FLAG_DISABLE_SPNEGO)
        PackageInfo->fCapabilities &= ~(SECPKG_FLAG_NEGOTIABLE);
    if (GsspFlags & GSSP_FLAG_DISABLE_NEGOEX)
        PackageInfo->fCapabilities &= ~(SECPKG_FLAG_NEGOTIABLE2);

    PackageInfo->wVersion = EAPSSP_PACKAGE_VERSION;

    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = EAPSSP_MAX_TOKEN_SIZE;

    if (oidEqual(Oid, GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM)) {
        PackageInfo->wRPCID = EAP_AES256_RPCID;
        PackageInfo->Name = EAP_AES256_PACKAGE_NAME_W;
    } else if (oidEqual(Oid, GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM)) {
        /*
         * Note: The AP is only specified for EAP-AES128; there's no point in
         * using specific message protection services for interactive logon.
         * Because this support is experimental and may impact normal logon
         * behaviour, it is only enabled if a flag is set in the registry.
         */
         if (GsspFlags & GSSP_FLAG_LOGON)
            PackageInfo->fCapabilities |= SECPKG_FLAG_LOGON;

        PackageInfo->wRPCID = EAP_AES128_RPCID;
        PackageInfo->Name = EAP_AES128_PACKAGE_NAME_W;
    } else {
        GsspDebugTrace(WINEVENT_LEVEL_WARNING,
                       L"GsspGetInfo: unknown package OID");
        PackageInfo->Name = NULL;
    }

    PackageInfo->Comment = EAPSSP_PACKAGE_COMMENT_W;

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpGetInfoEapAes128(OUT PSecPkgInfo PackageInfo)
{
    return GsspGetInfo(GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM, PackageInfo);
}

static NTSTATUS NTAPI
SpGetInfoEapAes256(OUT PSecPkgInfo PackageInfo)
{
    return GsspGetInfo(GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM, PackageInfo);
}
