/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Token helpers
 */

#include "gssp.h"

#ifndef DS_USER_PRINCIPAL_NAME_FOR_LOGON
#define DS_USER_PRINCIPAL_NAME_FOR_LOGON    0xFFFFFFF2
#endif

#ifndef DS_ALT_SECURITY_IDENTITIES_NAME
#define DS_ALT_SECURITY_IDENTITIES_NAME     0xFFFFFFF5
#endif

/* Attribute containing string SID representation */
#if 0
#define GROUP_SID_CLAIM_ATTR    "urn:ietf:params:gssapi:aaa-radius 26.25622.134"
#else
#define GROUP_SID_CLAIM_ATTR    "GroupSidClaim"
#endif

static NTSTATUS
RadiusGetAuthData(
    gss_ctx_id_t GssContext,
    PUCHAR *pAuthData,
    PULONG pcbAuthData)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    rs_const_avp *Pac;
    size_t ulPacSize = 0;

    *pAuthData = NULL;
    *pcbAuthData = 0;

    Major = gssEapRadiusGetRawAvp(&Minor, GssContext->acceptorCtx.vps,
                                  PW_MS_WINDOWS_AUTH_DATA, VENDORPEC_UKERNA,
                                  &Pac);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                    L"RadiusGetAuthData: found PAC for context %p", GssContext);

    rs_avp_fragmented_value(Pac, NULL, &ulPacSize);

    Status = GsspAlloc(ulPacSize, pAuthData);
    GSSP_BAIL_ON_ERROR(Status);

    if (rs_avp_fragmented_value(Pac, *pAuthData, &ulPacSize) != RSE_OK) {
        Status = STATUS_NO_SUCH_USER;
        goto cleanup;
    }

    *pcbAuthData = (ULONG)ulPacSize;

cleanup:
    if (Status != STATUS_SUCCESS) {
        GsspFree(*pAuthData);
        *pAuthData = NULL;
    }

    return Status;
}

static NTSTATUS
CrackGssName(
    gss_name_t GssName,
    DWORD RequestedFormat,
    PDS_NAME_RESULT *pResult)
{
    NTSTATUS Status;
    HANDLE hDS = NULL;
    PWSTR GssNameString = NULL;
    size_t cchGssNameString;
    PWSTR AltSecId = NULL;
    PDS_NAME_RESULT Result = NULL;

    *pResult = NULL;

    Status = GsspDisplayGssNameW(GssName, FALSE, &GssNameString);
    GSSP_BAIL_ON_ERROR(Status);

    cchGssNameString = wcslen(GssNameString);

    Status = DsBind(NULL, NULL, &hDS);
    if (Status != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CrackGssName: failed to bind to GC");
        goto cleanup;
    }

    Status = GsspAlloc((EAPSSP_ALTSECID_PREFIX_LENGTH + 1 + cchGssNameString + 1) * sizeof(WCHAR),
                       (PVOID *)&AltSecId);
    GSSP_BAIL_ON_ERROR(Status);

    /*
     * You'd think we could use CrackSingleName but it appears to be a
     * NOOP on a domain member, at least.
     */

    RtlCopyMemory(AltSecId, EAPSSP_ALTSECID_PREFIX_W,
                  EAPSSP_ALTSECID_PREFIX_LENGTH * sizeof(WCHAR));
    AltSecId[EAPSSP_ALTSECID_PREFIX_LENGTH] = L':';
    RtlCopyMemory(&AltSecId[EAPSSP_ALTSECID_PREFIX_LENGTH + 1],
                  GssNameString, (cchGssNameString + 1) * sizeof(WCHAR));

    Status = DsCrackNames(hDS,
                          DS_NAME_FLAG_GCVERIFY,
                          DS_ALT_SECURITY_IDENTITIES_NAME,
                          RequestedFormat,
                          1,
                          &AltSecId,
                          &Result);
    if (Status != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CrackGssName: DsCrackNames failed with %08x", Status);
        goto cleanup;
    }

    if (Result->cItems > 1) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CrackGssName: non-unique mapping for identity %ws", AltSecId);
        Status = SEC_E_MULTIPLE_ACCOUNTS;
        goto cleanup;
    }

    if (Result->cItems == 0 ||
        Result->rItems[0].status != DS_NAME_NO_ERROR) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CrackGssName: failed to map identity %ws", AltSecId);
        Status = SEC_E_LOGON_DENIED;
        goto cleanup;
    }

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"CrackGssName: mapped %ws -> %ws",
                   AltSecId, Result->rItems[0].pName);

    *pResult = Result;
    Result = NULL;

cleanup:
    if (hDS != NULL)
        DsUnBind(hDS);
    if (Result != NULL)
        DsFreeNameResult(Result);
    GsspFree(GssNameString);
    GsspFree(AltSecId);

    return Status;
}

static NTSTATUS
GetKerberosRealm(gss_name_t GssName, PUNICODE_STRING Realm)
{
    if (GssName == GSS_C_NO_NAME ||
        GssName->krbPrincipal == NULL)
        return SEC_E_NO_AUTHENTICATING_AUTHORITY;

    return GsspUTF8ToUnicodeString(KRB_PRINC_REALM(GssName->krbPrincipal), -1,
                                   FALSE, Realm);
}

static NTSTATUS
GetLocalSamNameMapping(
    PUNICODE_STRING Name,
    PUNICODE_STRING SamMappedName)
{
    NTSTATUS lResult;
    HKEY hKey;
    DWORD dwType, cbSamMappedName;

    lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			   L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\EapSSP\\UserList",
                           0, KEY_QUERY_VALUE, &hKey);
    if (lResult != STATUS_SUCCESS)
        return STATUS_NO_SUCH_USER;

    dwType = REG_SZ;
    cbSamMappedName = SamMappedName->MaximumLength;

    lResult = RegQueryValueEx(hKey, Name->Buffer, NULL, &dwType,
                              (PBYTE)SamMappedName->Buffer,
                              &cbSamMappedName);
    if (lResult != STATUS_SUCCESS) {
        dwType = REG_SZ;
        cbSamMappedName = SamMappedName->MaximumLength;

        /* Try wildcard mapping */
        lResult = RegQueryValueEx(hKey, L"*", NULL, &dwType,
                                  (PBYTE)SamMappedName->Buffer,
                                  &cbSamMappedName);
        if (lResult != STATUS_SUCCESS) {
            RegCloseKey(hKey);
            return STATUS_NO_SUCH_USER;
        }
    }

    SamMappedName->MaximumLength = cbSamMappedName;

    /*
     * This size includes any terminating NUL characters unless the
     * data was stored without one. Check this and return the length
     * of the string excluding any terminating NUL characters.
     */
    if (cbSamMappedName == 0) {
        lResult = STATUS_BUFFER_TOO_SMALL;
    } else if (cbSamMappedName % sizeof(WCHAR)) {
        lResult = STATUS_INVALID_BUFFER_SIZE;
    } else if (SamMappedName->Buffer[(cbSamMappedName / sizeof(WCHAR)) - 1] == 0) {
        cbSamMappedName -= sizeof(WCHAR);
    }

    RegCloseKey(hKey);

    SamMappedName->Length = cbSamMappedName;

    return lResult;
}

static NTSTATUS
GetAuthDataForUser(
    PUNICODE_STRING Name,
    PUCHAR *UserAuthData,
    PULONG UserAuthDataSize)
{
    NTSTATUS Status;
    UNICODE_STRING StringBuffer, AccountName;

    *UserAuthData = NULL;
    *UserAuthDataSize = 0;

    RtlInitUnicodeString(&AccountName, NULL);
    RtlInitUnicodeString(&StringBuffer, NULL);

    if (SpParameters.MachineState & SECPKG_STATE_DOMAIN_CONTROLLER) {
        RtlInitUnicodeString(&StringBuffer, EAPSSP_ALTSECID_PREFIX_W);

        Status = LsaSpFunctionTable->GetAuthDataForUser((PSECURITY_STRING)Name,
                                                        SecNameAlternateId,
                                                        (PSECURITY_STRING)&StringBuffer,
                                                        UserAuthData,
                                                        UserAuthDataSize,
                                                        &AccountName);
    } else {
        PUNICODE_STRING SamMappedName;
        WCHAR SamMappedNameBuffer[256];

        StringBuffer.Length         = sizeof(SamMappedNameBuffer);
        StringBuffer.MaximumLength  = sizeof(SamMappedNameBuffer);
        StringBuffer.Buffer         = SamMappedNameBuffer;

        Status = GetLocalSamNameMapping(Name, &StringBuffer);
        if (Status != STATUS_SUCCESS)
            return Status;

        /* If the user was mapped to "*" then use the unmapped name */
        SamMappedName = (wcscmp(SamMappedNameBuffer, L"*") == 0) ?
            Name : &StringBuffer;

        Status = LsaSpFunctionTable->GetAuthDataForUser((PSECURITY_STRING)SamMappedName,
                                                        SecNameFlat,
                                                        NULL,
                                                        UserAuthData,
                                                        UserAuthDataSize,
                                                        &AccountName);
    }

    if (Status != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GetUserAuthData: no local user for EAP name %wZ",
                      Name);
    }

    GsspFreeLsaUnicodeString(&AccountName);

    return Status;
}

static NTSTATUS
CreateTokenFromAuthData(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    PUCHAR AuthData = NULL;
    ULONG AuthDataSize = 0;
    TOKEN_SOURCE TokenSource;
    UNICODE_STRING AltSecId;
    UNICODE_STRING AccountName;
    UNICODE_STRING Realm;
    PUNICODE_STRING pDomainName;
    LUID LogonId;
    BOOLEAN bLsaAlloc = FALSE;

    RtlInitUnicodeString(&AltSecId, NULL);
    RtlInitUnicodeString(&AccountName, NULL);
    RtlInitUnicodeString(&Realm, NULL);

    /*
     * Get the authorization data from the RADIUS AAA attributes, or by
     * looking for a user mapped into the local SAM.
     */
    Status = RadiusGetAuthData(GssContext, &AuthData, &AuthDataSize);
    if (Status == STATUS_SUCCESS) {
        /*
         * XXX this won't work if the realm name is mapped and will return
         * a DNS domain rather than a NT4 one
         */
        Status = GetKerberosRealm(GssContext->initiatorName, &Realm);
        GSSP_BAIL_ON_ERROR(Status);

        bLsaAlloc = FALSE;

        RtlCopyMemory(TokenSource.SourceName,
                      EAPSSP_TOKEN_SOURCE_AAA,
                      sizeof(EAPSSP_TOKEN_SOURCE_AAA));
        pDomainName = &Realm;
    } else {
        Status = GsspDisplayGssNameUnicodeString(GssContext->initiatorName,
                                                 FALSE,
                                                 &AltSecId);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GetAuthDataForUser(&AltSecId, &AuthData, &AuthDataSize);
        GSSP_BAIL_ON_ERROR(Status);

        bLsaAlloc = TRUE;

        RtlCopyMemory(TokenSource.SourceName,
                      EAPSSP_TOKEN_LOCAL_SAM,
                      sizeof(EAPSSP_TOKEN_LOCAL_SAM));
        pDomainName = &SpParameters.DomainName; /* always a local user */
    }

    TokenSource.SourceIdentifier = GsspTokenSourceId;

    /*
     * If we are a domain member or domain controller, then expand
     * the domain groups in the authorization data.
     */
    if ((SpParameters.MachineState & SECPKG_STATE_STANDALONE) == 0) {
        PUCHAR ExpandedAuthData = NULL;
        ULONG ExpandedAuthDataSize = 0;

        Status = LsaSpFunctionTable->ExpandAuthDataForDomain(AuthData,
                                                             AuthDataSize,
                                                             NULL,
                                                             &ExpandedAuthData,
                                                             &ExpandedAuthDataSize);
        GSSP_BAIL_ON_ERROR(Status);

        if (bLsaAlloc)
            LsaSpFunctionTable->FreeLsaHeap(AuthData);
        else
            GsspFree(AuthData);

        AuthData = ExpandedAuthData;
        AuthDataSize = ExpandedAuthDataSize;

        bLsaAlloc = TRUE;
    }

    /*
     * Convert the authorization data into a NT token.
     */
    Status = LsaSpFunctionTable->ConvertAuthDataToToken(AuthData,
                                                        AuthDataSize,
                                                        SecurityImpersonation,
                                                        &TokenSource,
                                                        Network,
                                                        pDomainName,
                                                        &GssContext->TokenHandle,
                                                        &LogonId,
                                                        &AccountName,
                                                        &GssContext->SubStatus);
    if (Status != STATUS_SUCCESS || GssContext->SubStatus != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CreateTokenFromAuthData: failed to create token: %08x.%08x",
                       Status, GssContext->SubStatus);
        if (Status == STATUS_SUCCESS)
            Status = GssContext->SubStatus;
    }

    GsspInterlockedExchangeLuid(&GssContext->LogonId, &LogonId);

cleanup:
    GsspFreeLsaUnicodeString(&AccountName);
    GsspFreeUnicodeString(&AltSecId);
    GsspFreeUnicodeString(&Realm);
    if (bLsaAlloc)
        LsaSpFunctionTable->FreeLsaHeap(AuthData);
    else
        GsspFree(AuthData);

    return Status;
}

static NTSTATUS
GetLogonSessionData(
    PLUID LogonId,
    PUNICODE_STRING pAccountName,
    PULONG pUserFlags)
{
    PSECURITY_LOGON_SESSION_DATA SessionData = NULL;
    NTSTATUS Status;
    UNICODE_STRING AccountName;
    PUCHAR p;
    WCHAR DomainSep = L'\\';
    PUNICODE_STRING Domain;

    RtlInitUnicodeString(&AccountName, NULL);

    Status = LsaGetLogonSessionData(LogonId, &SessionData);
    GSSP_BAIL_ON_ERROR(Status);

    /*
     * The UserFlags member is only available in Vista and greater.
     * We could probably extract it directly from the profile but,
     * for now, this will do.
     */
    if (GsspFlags & GSSP_FLAG_UPLEVEL)
        *pUserFlags = SessionData->UserFlags;
    else
        *pUserFlags = 0; /* XXX too bad */

    if (SessionData->DnsDomainName.Length)
        Domain = &SessionData->DnsDomainName;
    else
        Domain = &SessionData->LogonDomain;

    AccountName.Length =
        Domain->Length + sizeof(WCHAR) + SessionData->UserName.Length;
    AccountName.MaximumLength = AccountName.Length + sizeof(WCHAR);

    Status = GsspAlloc(AccountName.MaximumLength, &AccountName.Buffer);
    GSSP_BAIL_ON_ERROR(Status);

    p = (PUCHAR)AccountName.Buffer;

    RtlCopyMemory(p, Domain->Buffer, Domain->Length);
    p += Domain->Length;
    RtlCopyMemory(p, &DomainSep, sizeof(DomainSep));
    p += sizeof(DomainSep);
    RtlCopyMemory(p, SessionData->UserName.Buffer, SessionData->UserName.Length);
    p += SessionData->UserName.Length;

    *p++ = '\0';
    *p   = '\0';

cleanup:
    if (SessionData != NULL)
        LsaFreeReturnBuffer(SessionData);
    if (Status == STATUS_SUCCESS)
        *pAccountName = AccountName;
    else
        GsspFreeUnicodeString(&AccountName);

    return Status;
}

static NTSTATUS
GetBuiltinAdministratorsSid(PSID *pSid)
{
    NTSTATUS Status;
    PSID Sid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    Status = GsspAlloc(RtlLengthRequiredSid(1), &Sid);
    GSSP_BAIL_ON_ERROR(Status);

    Status = RtlInitializeSid(Sid, &NtAuthority, 1);
    GSSP_BAIL_ON_ERROR(Status);

    *RtlSubAuthoritySid(Sid, 0) = SECURITY_LOCAL_SYSTEM_RID;

    *pSid = Sid;
    Sid = NULL;

cleanup:
    GsspFree(Sid);

    return Status;
}

static NTSTATUS
GetLocalSystemSid(PSID *pSid)
{
    NTSTATUS Status;
    PSID Sid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    Status = GsspAlloc(RtlLengthRequiredSid(2), &Sid);
    GSSP_BAIL_ON_ERROR(Status);

    Status = RtlInitializeSid(Sid, &NtAuthority, 2);
    GSSP_BAIL_ON_ERROR(Status);

    *RtlSubAuthoritySid(Sid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(Sid, 1) = DOMAIN_ALIAS_RID_ADMINS;

    *pSid = Sid;
    Sid = NULL;

cleanup:
    GsspFree(Sid);

    return Status;
}

NTSTATUS
QueryInformationTokenAlloc(
    HANDLE Token,
    TOKEN_INFORMATION_CLASS InfoClass,
    PVOID *ppInfo)
{
    NTSTATUS Status;
    DWORD cbInfo;
    PVOID pInfo = NULL;

    *ppInfo = NULL;

    Status = NtQueryInformationToken(Token, InfoClass, NULL, 0, &cbInfo);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        if (Status == STATUS_SUCCESS)
            Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    Status = GsspCalloc(1, cbInfo, &pInfo);
    GSSP_BAIL_ON_ERROR(Status);

    Status = NtQueryInformationToken(Token, InfoClass, pInfo, cbInfo, &cbInfo);
    GSSP_BAIL_ON_ERROR(Status);

    *ppInfo = pInfo;
    pInfo = NULL;

cleanup:
    if (Status != STATUS_SUCCESS)
        GsspFree(pInfo);

    return Status;
}

static NTSTATUS
QueryProcessOrThreadTokenAlloc(
    ULONG_PTR ProcessId,
    ULONG_PTR ThreadId,
    TOKEN_INFORMATION_CLASS InfoClass,
    PVOID *ppInfo)
{
    NTSTATUS Status;
    HANDLE ThreadToken = NULL;
    HANDLE ThreadHandle = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    *ppInfo = NULL;

    ClientId.UniqueThread = (PVOID)ThreadId;
    ClientId.UniqueProcess = (PVOID)ProcessId;

    if (ThreadId)
        Status = NtOpenThread(&ThreadHandle,
                              STANDARD_RIGHTS_READ | THREAD_QUERY_INFORMATION,
                              &ObjectAttributes, &ClientId);
    else
        Status = NtOpenProcess(&ThreadHandle,
                               STANDARD_RIGHTS_READ | PROCESS_QUERY_INFORMATION,
                               &ObjectAttributes, &ClientId);

    GSSP_BAIL_ON_ERROR(Status);

    if (ThreadId)
        Status = STATUS_INVALID_PARAMETER; /* Set only apparently XXX */
    else
        Status = NtOpenProcessToken(ThreadHandle,
                                    TOKEN_READ, &ThreadToken);
    GSSP_BAIL_ON_ERROR(Status);

    Status = QueryInformationTokenAlloc(ThreadToken, InfoClass, ppInfo);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    if (ThreadToken)
        CloseHandle(ThreadToken);
    if (ThreadHandle)
        CloseHandle(ThreadHandle);

    return Status;
}

static gss_buffer_desc
GroupSidClaimAttr = {
    sizeof(GROUP_SID_CLAIM_ATTR) - 1, GROUP_SID_CLAIM_ATTR
};

/*
 * Retrieve and parse a GSS attribute containing a group SID claim.
 */
static NTSTATUS
GetGroupSidClaim(
    gss_name_t InitiatorName,
    int *Index,
    PSID_AND_ATTRIBUTES pSidAndAttrs)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    int Authenticated, Complete;
    gss_buffer_desc Value = GSS_C_EMPTY_BUFFER;
    PWSTR StringSid = NULL;
    PSID Sid = NULL;

    RtlZeroMemory(pSidAndAttrs, sizeof(*pSidAndAttrs));

    Major = gssEapGetNameAttribute(&Minor,
                                   InitiatorName,
                                   &GroupSidClaimAttr,
                                   &Authenticated,
                                   &Complete,
                                   &Value,
                                   GSS_C_NO_BUFFER,
                                   Index);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    GSSP_ASSERT(Authenticated); /* caller should have checked */

    /* annoying, but it may not be NUL terminated */
    Status = GsspGssBufferToWideString(&Value, FALSE, &StringSid, NULL);
    GSSP_BAIL_ON_ERROR(Status);

    if (!ConvertStringSidToSid(StringSid, &Sid)) {
        Status = STATUS_INVALID_SID;
        goto cleanup;
    }

    pSidAndAttrs->Sid = Sid;
    pSidAndAttrs->Attributes = 0;

    Status = STATUS_SUCCESS;

cleanup:
    GsspReleaseBuffer(&Minor, &Value);
    GsspFree(StringSid);
    if (Status != STATUS_SUCCESS && Sid != NULL)
        LocalFree(Sid);

    return Status;
}

/*
 * Add individual SID claims from a SAML assertion or RADIUS response into
 * the authenticated user's token.
 */
static NTSTATUS
AddTokenSidClaims(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    OM_uint32 Major = GSS_S_UNAVAILABLE, Minor = GSSEAP_NO_SUCH_ATTR;
    int Authenticated = 0, Complete, More;
    ULONG cSidClaims;
    PTOKEN_GROUPS SidClaims = NULL;
    HANDLE RestrictedToken = NULL;

    /* Count the group SID claims */
    for (More = -1, cSidClaims = 0; More != 0; cSidClaims++) {
        Major = gssEapGetNameAttribute(&Minor,
                                       GssContext->initiatorName,
                                       &GroupSidClaimAttr,
                                       &Authenticated,
                                       &Complete,
                                       GSS_C_NO_BUFFER,
                                       GSS_C_NO_BUFFER,
                                       &More);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    if (Authenticated == 0 || cSidClaims == 0) {
        Status = STATUS_SUCCESS;
        goto cleanup;
    }

    Status = GsspCalloc(1,
                        sizeof(*SidClaims) +
                            ((cSidClaims - 1) * sizeof(SID_AND_ATTRIBUTES)),
                        &SidClaims);
    GSSP_BAIL_ON_ERROR(Status);

    for (More = -1, SidClaims->GroupCount = 0; More != 0; ) {
        OM_uint32 TmpMinor;
        gss_buffer_desc Value = GSS_C_EMPTY_BUFFER;

        Status = GetGroupSidClaim(GssContext->initiatorName,
                                  &More,
                                  &SidClaims->Groups[SidClaims->GroupCount]);
        GsspReleaseBuffer(&TmpMinor, &Value);
        if (Status == STATUS_INVALID_SID)
            continue;
        else if (Status != STATUS_SUCCESS)
            goto cleanup;

        SidClaims->GroupCount++;
    }

    Status = NtFilterToken(GssContext->TokenHandle,
                           0,       /* Flags */
                           NULL,    /* SidsToDisable */
                           NULL,    /* PrivilegesToDelete */
                           SidClaims,
                           &RestrictedToken);
    GSSP_BAIL_ON_ERROR(Status);

    CloseHandle(GssContext->TokenHandle);
    GssContext->TokenHandle = RestrictedToken;

cleanup:
    if (SidClaims != NULL) {
        ULONG i;

        for (i = 0; i < SidClaims->GroupCount; i++) {
            if (SidClaims->Groups[i].Sid != NULL)
                LocalFree(SidClaims->Groups[i].Sid);
        }
        GsspFree(SidClaims);
    }

    if (Major == GSS_S_UNAVAILABLE && Minor == GSSEAP_NO_SUCH_ATTR)
        Status = STATUS_SUCCESS;

    return Status;
}

#if 0
/*
 * This is not current with Windows 8 FCS. TokenUserClaimAttributes is now
 * a PCLAIMS_BLOB which is an opaque encoded claims set. Additionally, we
 * may need to create a token with the claims as it's unlikely we can adjust
 * the token claims after token creation.
 */
static NTSTATUS
AddTokenClaims(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    PAUTHZ_SECURITY_ATTRIBUTES_INFORMATION Attributes = NULL;

    Status = GsspQuerySubjectSecurityAttributes(GssContext,
                                                SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES,
                                                &Attributes);
    if (Status == STATUS_SUCCESS) {
        /* Call NtAdjustTokenClaimsAndDeviceGroups */
    }
    /* XXX leaky on error case */

    return Status;
}
#endif

/*
 * The token returned by S4U has a DACL which prevents it from working
 * in some caller contexts. Adjust the DACL so that the token user,
 * process user (if impersonating) and BUILTIN Administrators all have
 * TOKEN_ALL_ACCESS.
 *
 * XXX we need to add the thread user after reversion, how to do that?
 */
static NTSTATUS
AdjustTokenSecurity(HANDLE Token)
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR TokenSD = NULL;
    PSECURITY_DESCRIPTOR TokenAbsoluteSD = NULL;
    DWORD dwTokenSDSize = 0;
    DWORD dwAbsoluteSDSize = 0;
    BOOLEAN DaclPresent = FALSE;
    PACL AdjustedDacl = NULL;
    DWORD dwTokenAceSize = 0;
    BOOLEAN DaclDefaulted = FALSE;
    SECPKG_CLIENT_INFO ClientInfo;
    PTOKEN_USER ClientProcessUser = NULL;
    PTOKEN_USER ClientTokenUser = NULL;
    PSID LocalSystemSid = NULL;
    PSID BuiltinAdministratorsSid = NULL;
    PACL TokenDacl = NULL;
    DWORD dwDaclSize, dwZero = 0;

    RtlZeroMemory(&ClientInfo, sizeof(ClientInfo));

    Status = LsaSpFunctionTable->GetClientInfo(&ClientInfo);
    GSSP_BAIL_ON_ERROR(Status);

    /* Process user */
    Status = QueryProcessOrThreadTokenAlloc(ClientInfo.ProcessID,
                                            0,
                                            TokenUser, &ClientProcessUser);
    GSSP_BAIL_ON_ERROR(Status);

    /* Token user */
    Status = QueryInformationTokenAlloc(ClientInfo.ClientToken,
                                        TokenUser, &ClientTokenUser);
    GSSP_BAIL_ON_ERROR(Status);

    /* Builtin administrators */
    Status = GetLocalSystemSid(&LocalSystemSid);
    GSSP_BAIL_ON_ERROR(Status);

    /* Builtin administrators */
    Status = GetBuiltinAdministratorsSid(&BuiltinAdministratorsSid);
    GSSP_BAIL_ON_ERROR(Status);

    Status = NtQuerySecurityObject(Token, DACL_SECURITY_INFORMATION,
                                   NULL, 0, &dwTokenSDSize);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    Status = GsspAlloc(dwTokenSDSize, &TokenSD);
    GSSP_BAIL_ON_ERROR(Status);

    Status = NtQuerySecurityObject(Token, DACL_SECURITY_INFORMATION,
                                   TokenSD, dwTokenSDSize, &dwTokenSDSize);
    GSSP_BAIL_ON_ERROR(Status);

    Status = RtlGetDaclSecurityDescriptor(TokenSD, &DaclPresent,
                                          &TokenDacl, &DaclDefaulted);
    GSSP_BAIL_ON_ERROR(Status);

    dwTokenAceSize = 0;
    dwTokenAceSize += sizeof(ACCESS_ALLOWED_ACE) -
                      sizeof(DWORD) + RtlLengthSid(ClientProcessUser->User.Sid);
    dwTokenAceSize += sizeof(ACCESS_ALLOWED_ACE) -
                      sizeof(DWORD) + RtlLengthSid(ClientTokenUser->User.Sid);
    dwTokenAceSize += sizeof(ACCESS_ALLOWED_ACE) -
                      sizeof(DWORD) + RtlLengthSid(LocalSystemSid);
    dwTokenAceSize += sizeof(ACCESS_ALLOWED_ACE) -
                      sizeof(DWORD) + RtlLengthSid(BuiltinAdministratorsSid);

    Status = GsspCalloc(1, TokenDacl->AclSize + dwTokenAceSize, &AdjustedDacl);
    GSSP_BAIL_ON_ERROR(Status);

    RtlCopyMemory(AdjustedDacl, TokenDacl, TokenDacl->AclSize);
    AdjustedDacl->AclSize += dwTokenAceSize;

    /* Process user */
    Status = RtlAddAccessAllowedAce(AdjustedDacl, ACL_REVISION,
                                    TOKEN_ALL_ACCESS,
                                    ClientProcessUser->User.Sid);
    GSSP_BAIL_ON_ERROR(Status);

    /* Token user */
    Status = RtlAddAccessAllowedAce(AdjustedDacl, ACL_REVISION,
                                    TOKEN_ALL_ACCESS,
                                    ClientTokenUser->User.Sid);
    GSSP_BAIL_ON_ERROR(Status);

    /* Local system */
    Status = RtlAddAccessAllowedAce(AdjustedDacl, ACL_REVISION,
                                    TOKEN_ALL_ACCESS,
                                    LocalSystemSid);
    GSSP_BAIL_ON_ERROR(Status);

    /* Builtin administrators */
    Status = RtlAddAccessAllowedAce(AdjustedDacl, ACL_REVISION,
                                    TOKEN_ALL_ACCESS,
                                    BuiltinAdministratorsSid);
    GSSP_BAIL_ON_ERROR(Status);

    Status = RtlSelfRelativeToAbsoluteSD(TokenSD,
                                         NULL, &dwAbsoluteSDSize,
                                         NULL, &dwDaclSize,
                                         NULL, &dwZero,
                                         NULL, &dwZero,
                                         NULL, &dwZero);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    Status = GsspAlloc(dwAbsoluteSDSize, &TokenAbsoluteSD);
    GSSP_BAIL_ON_ERROR(Status);

    if (dwDaclSize) {
        Status = GsspAlloc(dwDaclSize, &TokenDacl);
        GSSP_BAIL_ON_ERROR(Status);
    }

    Status = RtlSelfRelativeToAbsoluteSD(TokenSD,
                                         TokenAbsoluteSD, &dwAbsoluteSDSize,
                                         TokenDacl, &dwDaclSize,
                                         NULL, &dwZero,
                                         NULL, &dwZero,
                                         NULL, &dwZero);
    GSSP_BAIL_ON_ERROR(Status);

    Status = RtlSetDaclSecurityDescriptor(TokenAbsoluteSD, DaclPresent,
                                          AdjustedDacl, DaclDefaulted);
    GSSP_BAIL_ON_ERROR(Status);

    Status = NtSetSecurityObject(Token, DACL_SECURITY_INFORMATION,
                                 TokenAbsoluteSD);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    GsspFree(TokenSD);
    GsspFree(TokenAbsoluteSD);
    GsspFree(TokenDacl);
    GsspFree(AdjustedDacl);

    GsspFree(ClientProcessUser);
    GsspFree(ClientTokenUser);
    GsspFree(LocalSystemSid);
    GsspFree(BuiltinAdministratorsSid);

    return Status;
}

static NTSTATUS
CreateTokenFromS4U(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    PDS_NAME_RESULT Princ = NULL;
    HANDLE LsaHandle = NULL;
    LSA_STRING LogonProcessName;
    LSA_STRING PackageName, OriginName;
    LSA_OPERATIONAL_MODE SecurityMode;
    PKERB_S4U_LOGON S4ULogon = NULL;
    ULONG Package;
    TOKEN_SOURCE TokenSource;
    PVOID Profile = NULL;
    ULONG cbProfile = 0, cbLogon;
    ULONG cbUpn, cbRealm;
    QUOTA_LIMITS QuotaLimits;
    LUID LogonId;

    RtlInitString(&LogonProcessName, "eap");
    RtlInitString(&PackageName, MICROSOFT_KERBEROS_NAME_A);
    RtlInitString(&OriginName, EAPSSP_ORIGIN_S4U);

    Status = CrackGssName(GssContext->initiatorName,
                          DS_USER_PRINCIPAL_NAME_FOR_LOGON, &Princ);
    GSSP_BAIL_ON_ERROR(Status);

    GSSP_ASSERT(Princ->rItems[0].pName != NULL);

    cbUpn = wcslen(Princ->rItems[0].pName) * sizeof(WCHAR);
    if (cbUpn > MAXUSHORT) {
        Status = STATUS_INVALID_BUFFER_SIZE;
        goto cleanup;
    }

    if (Princ->rItems[0].pDomain != NULL) {
        cbRealm = wcslen(Princ->rItems[0].pDomain) * sizeof(WCHAR);
        if (cbRealm > MAXUSHORT) {
            Status = STATUS_INVALID_BUFFER_SIZE;
            goto cleanup;
        }
    } else
        cbRealm = 0;

    cbLogon = sizeof(*S4ULogon) + cbUpn + cbRealm;

    Status = GsspCalloc(1, cbLogon, (PVOID *)&S4ULogon);
    GSSP_BAIL_ON_ERROR(Status);

    S4ULogon->MessageType = KerbS4ULogon;

    S4ULogon->ClientUpn.Buffer = (WCHAR *)((PUCHAR)S4ULogon + sizeof(*S4ULogon));
    RtlCopyMemory(S4ULogon->ClientUpn.Buffer, Princ->rItems[0].pName, cbUpn);
    S4ULogon->ClientUpn.Length = cbUpn;
    S4ULogon->ClientUpn.MaximumLength = cbUpn;

    if (cbRealm != 0) {
        S4ULogon->ClientRealm.Buffer = (WCHAR *)((PUCHAR)S4ULogon + sizeof(*S4ULogon) + cbUpn);
        RtlCopyMemory(S4ULogon->ClientRealm.Buffer, Princ->rItems[0].pDomain, cbRealm);
        S4ULogon->ClientRealm.Length = cbRealm;
        S4ULogon->ClientRealm.MaximumLength = cbRealm;
    }

    Status = LsaRegisterLogonProcess(&LogonProcessName, &LsaHandle, &SecurityMode);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &Package);
    GSSP_BAIL_ON_ERROR(Status);

    RtlCopyMemory(TokenSource.SourceName,
                  EAPSSP_TOKEN_SOURCE_S4U, sizeof(EAPSSP_TOKEN_SOURCE_S4U));
    TokenSource.SourceIdentifier = GsspTokenSourceId;

    Status = LsaLogonUser(LsaHandle,
                          &OriginName,
                          Network,
                          Package,
                          S4ULogon,
                          cbLogon,
                          NULL,
                          &TokenSource,
                          &Profile,
                          &cbProfile,
                          &LogonId,
                          &GssContext->TokenHandle,
                          &QuotaLimits,
                          &GssContext->SubStatus);
    if (Status != STATUS_SUCCESS || GssContext->SubStatus != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"CreateTokenFromS4U: failed to create token: %08x.%08x",
                       Status, GssContext->SubStatus);
        if (Status == STATUS_SUCCESS)
            Status = GssContext->SubStatus;
    }

    GsspInterlockedExchangeLuid(&GssContext->LogonId, &LogonId);

    if ((GsspGetCallAttributes() & SECPKG_CALL_KERNEL_MODE) == 0) {
        Status = AdjustTokenSecurity(GssContext->TokenHandle);
        GSSP_BAIL_ON_ERROR(Status);
    }

    if (GssContext->flags & CTX_FLAG_LOGON) {
        /* Save profile buffer */
        GssContext->ProfileBuffer = Profile;
        GssContext->ProfileBufferLength = cbProfile;

        Profile = NULL;
    }

cleanup:
    if (Profile != NULL)
        LsaFreeReturnBuffer(Profile);
    if (LsaHandle != NULL)
        LsaClose(LsaHandle);
    if (Princ != NULL)
        DsFreeNameResult(Princ);
    GsspFree(S4ULogon);

    return Status;
}

static NTSTATUS
GsspCreateToken(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    BOOLEAN bS4U = FALSE;

    GSSP_ASSERT(!CTX_IS_INITIATOR(GssContext));

    /*
     * S4U is only used by workstations, except in the case the
     * S4U_ON_DC flag is set, in which case it will be used on
     * domain controllers. This is for debugging only.
     */
    if (SpParameters.MachineState & SECPKG_STATE_WORKSTATION ||
        ((GsspFlags & GSSP_FLAG_S4U_ON_DC) &&
         (SpParameters.MachineState & SECPKG_STATE_DOMAIN_CONTROLLER)))
        bS4U = TRUE;

    /*
     * Create token from authorziation data in the AAA response or
     * local SAM. If that fails (typically because the user is in
     * another domain) then perform a S4U2Self request.
     */
    Status = CreateTokenFromAuthData(GssContext);
    if (Status == STATUS_NO_SUCH_USER && bS4U)
        Status = CreateTokenFromS4U(GssContext);

    /* Squash error code */
    if (Status != STATUS_SUCCESS)
        Status = SEC_E_LOGON_DENIED;
    if (Status != STATUS_SUCCESS)
        return Status;

    /* Add explicit SIDs from SAML assertion */
    Status = AddTokenSidClaims(GssContext);
    if (Status != STATUS_SUCCESS)
        return Status;

#if 0
    /*
     * Not sure how to set claims. We can't modify an existing token.
     * So we would probably have to expand the token out and then
     * create a new one.
     */
    if (GsspFlags & GSSP_FLAG_TOKEN_CLAIMS) {
        Status = AddTokenClaims(GssContext);
        if (Status != STATUS_SUCCESS)
            return Status;
    }
#endif

    Status = GetLogonSessionData((PLUID)&GssContext->LogonId,
                                 &GssContext->AccountName,
                                 &GssContext->UserFlags);
    if (Status != STATUS_SUCCESS)
        return Status;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspCreateToken: created token for %wZ [%08x.%08x]",
                   &GssContext->AccountName,
                   GssContext->LogonId.LowPart,
                   GssContext->LogonId.HighPart);

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspMapAccountName(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;
    UNICODE_STRING PrincipalName;
    UNICODE_STRING StringBuffer;
    UNICODE_STRING AccountName;
    UNICODE_STRING DnsDomainName;
    PUNICODE_STRING Prefix = NULL;
    PUNICODE_STRING NameInput = NULL;
    WCHAR SamMappedNameBuffer[256];
    ULONG FormatOffered = DS_UNKNOWN_NAME;
    PDS_NAME_RESULT Result = NULL;

    RtlInitUnicodeString(&PrincipalName, NULL);
    RtlInitUnicodeString(&StringBuffer, NULL);
    RtlInitUnicodeString(&AccountName, NULL);
    RtlInitUnicodeString(&DnsDomainName, NULL);

    Status = GsspDisplayGssNameUnicodeString(GssContext->initiatorName,
                                             FALSE,
                                             &PrincipalName);
    GSSP_BAIL_ON_ERROR(Status);

    if ((SpParameters.MachineState & SECPKG_STATE_DOMAIN_CONTROLLER) == 0) {
        StringBuffer.Length         = sizeof(SamMappedNameBuffer);
        StringBuffer.MaximumLength  = sizeof(SamMappedNameBuffer);
        StringBuffer.Buffer         = SamMappedNameBuffer;

        if (GetLocalSamNameMapping(&PrincipalName,
                                   &StringBuffer) == STATUS_SUCCESS) {
            FormatOffered = DS_NT4_ACCOUNT_NAME;
            NameInput = (wcscmp(SamMappedNameBuffer, L"*") == 0) ?
                &PrincipalName : &StringBuffer;
            Prefix = NULL;
        }
    }

    if (FormatOffered == DS_UNKNOWN_NAME) {
        /* No SAM mapping, so try to crack based on AltSecId. */
        RtlInitUnicodeString(&StringBuffer, EAPSSP_ALTSECID_PREFIX_W);
        FormatOffered = DS_ALT_SECURITY_IDENTITIES_NAME;
        NameInput = &PrincipalName;
        Prefix = &StringBuffer;
    }

    if (SpParameters.MachineState & SECPKG_STATE_DOMAIN_CONTROLLER) {
        Status = LsaSpFunctionTable->CrackSingleName(FormatOffered,
                                                     TRUE,
                                                     NameInput,
                                                     Prefix,
                                                     DS_NT4_ACCOUNT_NAME,
                                                     &AccountName,
                                                     &DnsDomainName,
                                                     (PULONG)&GssContext->SubStatus);
        if (Status == STATUS_SUCCESS)
            Status = GssContext->SubStatus;
    } else if (SpParameters.MachineState & SECPKG_STATE_WORKSTATION) {
        ULONG cbName;

        Status = CrackGssName(GssContext->initiatorName,
                              DS_NT4_ACCOUNT_NAME, &Result);
        GSSP_BAIL_ON_ERROR(Status);

        cbName = wcslen(Result->rItems[0].pName) * sizeof(WCHAR);
        if (cbName > MAXUSHORT) {
            Status = STATUS_NAME_TOO_LONG;
            goto cleanup;
        }

        AccountName.Length = cbName;
        AccountName.MaximumLength = cbName;
        AccountName.Buffer = Result->rItems[0].pName;
    } else if (SpParameters.MachineState & SECPKG_STATE_STANDALONE) {
        /* Registry mapping is authoritative */
        if (NameInput != NULL)
            AccountName = *NameInput;
        else
            Status = STATUS_NO_SUCH_USER;
    }

    if (Status == STATUS_SUCCESS) {
        GSSP_ASSERT(AccountName.Buffer != NULL);

        Status = GsspDuplicateUnicodeString(&AccountName, FALSE,
                                            &GssContext->AccountName);
    }

cleanup:
    if (Status != STATUS_SUCCESS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspMapAccountName: no mapping for %wZ",
                       &PrincipalName);
        Status = STATUS_NO_SUCH_USER;
    } else {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspMapAccountName: mapped %wZ to %wZ",
                       &PrincipalName, &GssContext->AccountName);
    }

    if (Result != NULL) {
        DsFreeNameResult(Result);
    } else {
        GsspFreeLsaUnicodeString(&AccountName);
        GsspFreeLsaUnicodeString(&DnsDomainName);
    }

    GsspFreeUnicodeString(&PrincipalName);

    return Status;
}

NTSTATUS
GsspCreateTokenOrMapAccount(gss_ctx_id_t GssContext)
{
    NTSTATUS Status;

    GSSP_ASSERT(GssContext != NULL);
    GSSP_ASSERT(!CTX_IS_INITIATOR(GssContext));

    /*
     * If the context is an identification context, then do not create
     * an impersonation token; simply map the name to a local one.
     */
    if (GssContext->gssFlags & GSS_C_IDENTIFY_FLAG) {
        Status = GsspMapAccountName(GssContext);
    } else {
        Status = GsspCreateToken(GssContext);
    }

    return Status;
}

