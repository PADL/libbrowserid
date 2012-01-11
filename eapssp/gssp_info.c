/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Query interfaces
 */

#include "gssp.h"

#ifndef WOW64_SYSTEM_DIRECTORY_U
#define WOW64_SYSTEM_DIRECTORY_U   L"SysWOW64"
#endif

ULONG GsspMutualAuthLevel = 0;

NTSTATUS NTAPI
SpGetUserInfo(
    IN PLUID LogonId,
    IN ULONG Flags,
    OUT PSecurityUserData * UserData)
{
    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpSetExtendedInformation(
    IN SECPKG_EXTENDED_INFORMATION_CLASS Class,
    IN PSECPKG_EXTENDED_INFORMATION Info)
{
    NTSTATUS Status;

    switch (Class) {
    case SecpkgMutualAuthLevel:
        GsspMutualAuthLevel = Info->Info.MutualAuthLevel.MutualAuthLevel;
        Status = STATUS_SUCCESS;
        break;
    default:
        Status = SEC_E_UNSUPPORTED_FUNCTION;
        break;
    }

    return Status;
}

static NTSTATUS
GsspGetGssInfo(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    PSECPKG_EXTENDED_INFORMATION pInfo;
    NTSTATUS Status;

    /* Already enough space for 4 bytes of OID */
    Status = GsspLsaCalloc(1, sizeof(*pInfo) - 2 + Oid->length, &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgGssInfo;
    pInfo->Info.GssInfo.EncodedIdLength = 2 + Oid->length;

    pInfo->Info.GssInfo.EncodedId[0] = 0x06;
    pInfo->Info.GssInfo.EncodedId[1] = Oid->length;
    RtlCopyMemory(&pInfo->Info.GssInfo.EncodedId[2], Oid->elements, Oid->length);

#if 0
    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspGetGssInfo: OID length %u %02x%02x%02x%02x...",
                   pInfo->Info.GssInfo.EncodedIdLength,
                   pInfo->Info.GssInfo.EncodedId[0] & 0xFF,
                   pInfo->Info.GssInfo.EncodedId[1] & 0xFF,
                   pInfo->Info.GssInfo.EncodedId[2] & 0xFF,
                   pInfo->Info.GssInfo.EncodedId[3] & 0xFF);
#endif

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static ULONG
GsspLsaModeInfoLevels[] = {
    SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS,
    SECPKG_ATTR_PROMPTING_NEEDED,
    SECPKG_ATTR_CREDENTIAL_NAME,
};

static NTSTATUS
GsspGetContextThunks(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    PSECPKG_EXTENDED_INFORMATION pInfo;
    NTSTATUS Status;

    Status = GsspLsaCalloc(1, sizeof(*pInfo) + sizeof(GsspLsaModeInfoLevels), &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgContextThunks;
    pInfo->Info.ContextThunks.InfoLevelCount = sizeof(GsspLsaModeInfoLevels) / sizeof(GsspLsaModeInfoLevels[0]);
    RtlCopyMemory(pInfo->Info.ContextThunks.Levels, GsspLsaModeInfoLevels, sizeof(GsspLsaModeInfoLevels));

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspGetMutualAuthLevel(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    PSECPKG_EXTENDED_INFORMATION pInfo;
    NTSTATUS Status;

    Status = GsspLsaCalloc(1, sizeof(*pInfo), &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgMutualAuthLevel;
    pInfo->Info.MutualAuthLevel.MutualAuthLevel = GsspMutualAuthLevel;

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspGetWowClientDll(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    NTSTATUS Status;
    PSECPKG_EXTENDED_INFORMATION pInfo;
    PSECURITY_STRING WowClientDllPath;
    DWORD cchWowClientDllPath;

    Status = GsspLsaCalloc(1, sizeof(*pInfo) +
                           (MAX_PATH * sizeof(WCHAR)), &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgWowClientDll;
    WowClientDllPath = &pInfo->Info.WowClientDll.WowClientDllPath;
    WowClientDllPath->Buffer = (PWCHAR)((PUCHAR)pInfo + sizeof(*pInfo));

    cchWowClientDllPath =
        ExpandEnvironmentStrings(L"%SystemRoot%\\" WOW64_SYSTEM_DIRECTORY_U L"\\EapSSP.DLL",
                                 WowClientDllPath->Buffer, MAX_PATH);

    WowClientDllPath->Length = cchWowClientDllPath * sizeof(WCHAR);
    WowClientDllPath->MaximumLength = WowClientDllPath->Length + sizeof(WCHAR);

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspGetExtraOids(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    PSECPKG_EXTENDED_INFORMATION pInfo;
    NTSTATUS Status;

    Status = GsspLsaCalloc(1, sizeof(*pInfo), &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgExtraOids;
    pInfo->Info.ExtraOids.OidCount = 0;

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspGetNego2Info(gss_OID Oid, PSECPKG_EXTENDED_INFORMATION *ppInfo)
{
    PSECPKG_EXTENDED_INFORMATION pInfo;
    NTSTATUS Status;
    OM_uint32 Major, Minor;

    Status = GsspLsaCalloc(1, sizeof(*pInfo), &pInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    pInfo->Class = SecpkgNego2Info;

    Major = gssQueryMechanismInfo(&Minor, Oid,
                                  pInfo->Info.Nego2Info.AuthScheme);
    if (GSS_ERROR(Major)) {
        GsspLsaFree(pInfo);
        return GsspMapStatus(Major, Minor);
    }

    pInfo->Info.Nego2Info.PackageFlags = 0;

    *ppInfo = pInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspGetExtendedInformation(
    IN  SECPKG_EXTENDED_INFORMATION_CLASS Class,
    IN  gss_OID Oid,
    OUT PSECPKG_EXTENDED_INFORMATION * ppInformation)
{
    NTSTATUS Status;

    *ppInformation = NULL;

    switch (Class) {
    case SecpkgGssInfo:
        Status = GsspGetGssInfo(Oid, ppInformation);
        break;
    case SecpkgContextThunks:
        Status = GsspGetContextThunks(Oid, ppInformation);
        break;
    case SecpkgMutualAuthLevel:
        Status = GsspGetMutualAuthLevel(Oid, ppInformation);
        break;
    case SecpkgWowClientDll:
        Status = GsspGetWowClientDll(Oid, ppInformation);
        break;
    case SecpkgExtraOids:
        Status = GsspGetExtraOids(Oid, ppInformation);
        break;
    case SecpkgNego2Info:
        Status = GsspGetNego2Info(Oid, ppInformation);
        break;
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

NTSTATUS NTAPI
SpGetExtendedInformationEapAes128(
    IN  SECPKG_EXTENDED_INFORMATION_CLASS Class,
    OUT PSECPKG_EXTENDED_INFORMATION * ppInformation)
{
    return GsspGetExtendedInformation(Class, GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM, ppInformation);
}

NTSTATUS NTAPI
SpGetExtendedInformationEapAes256(
    IN  SECPKG_EXTENDED_INFORMATION_CLASS Class,
    OUT PSECPKG_EXTENDED_INFORMATION * ppInformation)
{
    return GsspGetExtendedInformation(Class, GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM, ppInformation);
}

