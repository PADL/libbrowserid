/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Credential interfaces
 */

#include "gssp.h"

#define GSSP_SEC_WINNT_VALID_FLAGS(Flags) \
    (((Flags) & SEC_WINNT_AUTH_IDENTITY_ANSI) || \
     ((Flags) & SEC_WINNT_AUTH_IDENTITY_UNICODE))

#define CLIENT_HASH_PREFIX              "hash://"
#define CLIENT_HASH_PREFIX_LEN          (sizeof(CLIENT_HASH_PREFIX) - 1)

#define HASH_PREFIX                     "hash://server/sha256/"
#define HASH_PREFIX_LEN                 (sizeof(HASH_PREFIX) - 1)

#define CERT_STORE_PREFIX               "cert_store://"
#define CERT_STORE_PREFIX_LEN           (sizeof(CERT_STORE_PREFIX) - 1)

VOID
GsspCredAddRef(gss_cred_id_t GssCred)
{
    if (GssCred == GSS_C_NO_CREDENTIAL)
        return;

    InterlockedIncrement(&GssCred->RefCount);
}

VOID
GsspCredRelease(gss_cred_id_t GssCred)
{
    OM_uint32 Minor;

    gssEapReleaseCred(&Minor, &GssCred);
}

NTSTATUS
GsspCredAddRefAndLock(gss_cred_id_t GssCred)
{
    if (GssCred == GSS_C_NO_CREDENTIAL)
        return STATUS_INVALID_HANDLE;

    GsspCredAddRef(GssCred);

    /* LogonId is immutable, so no need to acquire lock. */
    if (!GsspValidateClient(&GssCred->LogonId, NULL)) {
        GsspCredRelease(GssCred);
        return SEC_E_NOT_OWNER;
    }

    GsspCredLock(GssCred);

    return STATUS_SUCCESS;
}

VOID
GsspCredUnlockAndRelease(gss_cred_id_t GssCred)
{
    if (GssCred != GSS_C_NO_CREDENTIAL) {
        GsspCredUnlock(GssCred);
        GsspCredRelease(GssCred);
    }
}

/*
 * Look in the registry for a global certificate store name which
 * can be passed to the libeap TLS implementation.
 */
static NTSTATUS
GsspSetCredDefaultCert(gss_cred_id_t GssCred)
{
    DWORD dwResult;
    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;
    HKEY hSspKey = NULL;
    LPSTR szCaCertificate = NULL;

    /* Perhaps it was passed by the credential provider */
    if (GssCred->caCertificate.value != NULL) {
        dwResult = STATUS_SUCCESS;
        goto cleanup;
    }

    dwResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                             "SYSTEM\\CurrentControlSet\\Control\\Lsa\\EapSSP",
                             0, KEY_QUERY_VALUE, &hSspKey);
    if (dwResult != ERROR_SUCCESS) {
        dwResult = STATUS_SUCCESS;
        goto cleanup;
    }

    dwResult = RegQueryValueExA(hSspKey, "DefaultCertStore", NULL,
                                &dwType, NULL, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType != REG_SZ) {
        dwResult = STATUS_SUCCESS;
        goto cleanup;
    }

    dwResult = GsspAlloc(CERT_STORE_PREFIX_LEN + dwSize + 1, &szCaCertificate);
    GSSP_BAIL_ON_ERROR(dwResult);

    RtlCopyMemory(szCaCertificate, CERT_STORE_PREFIX, CERT_STORE_PREFIX_LEN);

    dwResult = RegQueryValueExA(hSspKey, "DefaultCertStore", NULL, &dwType,
                                (PBYTE)szCaCertificate + CERT_STORE_PREFIX_LEN,
                                &dwSize);
    GSSP_BAIL_ON_ERROR(dwResult);

    szCaCertificate[CERT_STORE_PREFIX_LEN + dwSize] = '\0';

    GssCred->caCertificate.value = szCaCertificate;
    GssCred->caCertificate.length = CERT_STORE_PREFIX_LEN + dwSize;

    szCaCertificate = NULL;

cleanup:
    if (hSspKey != NULL)
        RegCloseKey(hSspKey);
    if (szCaCertificate != NULL)
        GsspFree(szCaCertificate);

    return dwResult;
}

static NTSTATUS
ConvertCredStringToGssBuffer(ULONG ulFlags,
    PVOID String,
    ULONG cbString,
    gss_buffer_t GssBuffer)
{
    NTSTATUS Status;

    if (String == NULL &&
        GSSP_SEC_WINNT_VALID_FLAGS(ulFlags)) {
        GSSP_ASSERT(cbString == 0);

        GssBuffer->length = 0;
        GssBuffer->value = NULL;

        return STATUS_SUCCESS;
    }

    if (ulFlags & SEC_WINNT_AUTH_IDENTITY_ANSI) {
        Status = GsspAlloc(cbString + 1, &GssBuffer->value);
        if (Status == STATUS_SUCCESS) {
            GssBuffer->length = cbString;
            RtlCopyMemory(GssBuffer->value, String, cbString);
            ((PSTR)GssBuffer->value)[cbString] = '\0';
        }
    } else if (ulFlags & SEC_WINNT_AUTH_IDENTITY_UNICODE) {
        UNICODE_STRING u;

        if (cbString > MAXUSHORT)
            return STATUS_NAME_TOO_LONG;

        u.Length        = cbString;
        u.MaximumLength = cbString;
        u.Buffer        = String;

        Status = GsspUnicodeStringToGssBuffer(&u, GssBuffer);
    } else {
        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}

static NTSTATUS
ConvertAuthIdentityEx2ToGss(
    PSEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentityHdr,
    PVOID AuthIdentityBuffer,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;
    PSEC_WINNT_AUTH_IDENTITY_EX2 AuthIdentity = NULL;

    GSSP_BAIL_ON_BAD_OFFSET(AuthIdentityHdr->cbStructureLength,
                            AuthIdentity->UserOffset,
                            AuthIdentity->UserLength);
    GSSP_BAIL_ON_BAD_OFFSET(AuthIdentityHdr->cbStructureLength,
                            AuthIdentity->DomainOffset,
                            AuthIdentity->DomainLength);
    GSSP_BAIL_ON_BAD_OFFSET(AuthIdentityHdr->cbStructureLength,
                            AuthIdentity->PackedCredentialsOffset,
                            AuthIdentity->PackedCredentialsLength);

    Status = GsspAlloc(AuthIdentityHdr->cbStructureLength,
                       (PVOID *)&AuthIdentity);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                   AuthIdentityHdr->cbStructureLength,
                   AuthIdentity,
                   AuthIdentityBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ConvertCredStringToGssBuffer(AuthIdentity->Flags,
                   (PUCHAR)AuthIdentity + AuthIdentity->UserOffset,
                   AuthIdentity->UserLength,
                   User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ConvertCredStringToGssBuffer(AuthIdentity->Flags,
                   (PUCHAR)AuthIdentity + AuthIdentity->DomainOffset,
                   AuthIdentity->DomainLength,
                   Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ConvertCredStringToGssBuffer(AuthIdentity->Flags,
                   (PUCHAR)AuthIdentity + AuthIdentity->PackedCredentialsOffset,
                   AuthIdentity->PackedCredentialsLength,
                   Password);
    GSSP_BAIL_ON_ERROR(Status);

    *Flags = AuthIdentity->Flags;

cleanup:
    GsspFree(AuthIdentity);

    return Status;
}

static NTSTATUS
CredStringFromClientBufferA(
    PVOID ClientBufferPtr,
    ULONG cchString,
    PSTR *pString,
    ULONG *pCbString)
{
    NTSTATUS Status;
    PSTR String;
    ULONG cbString = cchString;

    Status = GsspAlloc(cbString + 1, &String);
    if (Status != STATUS_SUCCESS)
        return Status;

    Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                                                      cbString,
                                                      String,
                                                      ClientBufferPtr);
    if (Status != STATUS_SUCCESS) {
        GsspFree(String);
        return Status;
    }

    String[cchString] = '\0';

    *pString = String;
    *pCbString = cbString;

    return STATUS_SUCCESS;
}

static NTSTATUS
CredStringFromClientBufferW(
    PVOID ClientBufferPtr,
    ULONG cchString,
    PWSTR *pString,
    ULONG *pCbString)
{
    NTSTATUS Status;
    PWSTR String;
    ULONG cbString = cchString * sizeof(WCHAR);

    Status = GsspAlloc(cbString + sizeof(WCHAR), &String);
    if (Status != STATUS_SUCCESS)
        return Status;

    Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                                                      cbString,
                                                      String,
                                                      ClientBufferPtr);
    if (Status != STATUS_SUCCESS) {
        GsspFree(String);
        return Status;
    }

    String[cchString] = '\0';

    *pString = String;
    *pCbString = cbString;

    return STATUS_SUCCESS;
}

static NTSTATUS
CredStringFromClientBuffer(
    ULONG ulFlags,
    PVOID ClientBufferPtr,
    ULONG cchString,
    PVOID *pString,
    ULONG *pCbString)
{
    NTSTATUS Status;

    *pString = NULL;
    *pCbString = 0;

    if (ClientBufferPtr == NULL)
        return STATUS_SUCCESS;

    if (ulFlags & SEC_WINNT_AUTH_IDENTITY_ANSI) {
        Status = CredStringFromClientBufferA(ClientBufferPtr,
                                             cchString,
                                             (PSTR *)pString,
                                             pCbString);
    } else if (ulFlags & SEC_WINNT_AUTH_IDENTITY_UNICODE) {
        Status = CredStringFromClientBufferW(ClientBufferPtr,
                                             cchString,
                                             (PWSTR *)pString,
                                             pCbString);
    } else {
        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}

static NTSTATUS
CredStringFromWowClientBufferToGssBuffer(ULONG ulFlags,
    ULONG BufferPtr,
    ULONG cchString,
    gss_buffer_t GssBuffer)
{
    NTSTATUS Status;
    PVOID szLocalBuffer = NULL;
    ULONG cbLocalBuffer;
    ULONG_PTR BufferPtr64 = (ULONG_PTR)BufferPtr;

    GssBuffer->length = 0;
    GssBuffer->value = NULL;

    Status = CredStringFromClientBuffer(ulFlags,
                                        (PVOID)BufferPtr64,
                                        cchString,
                                        &szLocalBuffer,
                                        &cbLocalBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ConvertCredStringToGssBuffer(ulFlags,
                                          szLocalBuffer,
                                          cbLocalBuffer,
                                          GssBuffer);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    GsspFree(szLocalBuffer);

    return Status;
}

static NTSTATUS
CredStringFromClientBufferToGssBuffer(ULONG ulFlags,
    PVOID BufferPtr,
    ULONG cchString,
    gss_buffer_t GssBuffer)
{
    NTSTATUS Status;
    PVOID szLocalBuffer = NULL;
    ULONG cbLocalBuffer;

    GssBuffer->length = 0;
    GssBuffer->value = NULL;

    Status = CredStringFromClientBuffer(ulFlags,
                                        BufferPtr,
                                        cchString,
                                        &szLocalBuffer,
                                        &cbLocalBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ConvertCredStringToGssBuffer(ulFlags,
                                          szLocalBuffer,
                                          cbLocalBuffer,
                                          GssBuffer);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    GsspFree(szLocalBuffer);

    return Status;
}

static NTSTATUS
ConvertAuthIdentityEx32ToGss(
    PSEC_WINNT_AUTH_IDENTITY_EX32 AuthIdentityHdr,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->User,
                                                      AuthIdentityHdr->UserLength,
                                                      User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->Domain,
                                                      AuthIdentityHdr->DomainLength,
                                                      Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->Password,
                                                      AuthIdentityHdr->PasswordLength,
                                                      Password);
    GSSP_BAIL_ON_ERROR(Status);

    *Flags = AuthIdentityHdr->Flags;

cleanup:
    return Status;
}

static NTSTATUS
ConvertAuthIdentityExToGss(
    PSEC_WINNT_AUTH_IDENTITY_EXW AuthIdentityHdr,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->User,
                                                   AuthIdentityHdr->UserLength,
                                                   User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->Domain,
                                                   AuthIdentityHdr->DomainLength,
                                                   Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->Password,
                                                   AuthIdentityHdr->PasswordLength,
                                                   Password);
    GSSP_BAIL_ON_ERROR(Status);

    *Flags = AuthIdentityHdr->Flags;

cleanup:
    return Status;
}

static NTSTATUS
ConvertAuthIdentity32ToGss(
    PSEC_WINNT_AUTH_IDENTITY32 AuthIdentityHdr,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->User,
                                                      AuthIdentityHdr->UserLength,
                                                      User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->Domain,
                                                      AuthIdentityHdr->DomainLength,
                                                      Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromWowClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                      AuthIdentityHdr->Password,
                                                      AuthIdentityHdr->PasswordLength,
                                                      Password);
    GSSP_BAIL_ON_ERROR(Status);

    *Flags = AuthIdentityHdr->Flags;

cleanup:
    return Status;
}

static NTSTATUS
ConvertAuthIdentityToGss(
    PSEC_WINNT_AUTH_IDENTITY_W AuthIdentityHdr,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->User,
                                                   AuthIdentityHdr->UserLength,
                                                   User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->Domain,
                                                   AuthIdentityHdr->DomainLength,
                                                   Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = CredStringFromClientBufferToGssBuffer(AuthIdentityHdr->Flags,
                                                   AuthIdentityHdr->Password,
                                                   AuthIdentityHdr->PasswordLength,
                                                   Password);
    GSSP_BAIL_ON_ERROR(Status);

    *Flags = AuthIdentityHdr->Flags;

cleanup:
    return Status;
}

static NTSTATUS
ConvertAuthIdentityInfoToGss(
    IN PVOID AuthIdentityBuffer,
    gss_buffer_t User,
    gss_buffer_t Domain,
    gss_buffer_t Password,
    ULONG *Flags)
{
    NTSTATUS Status;
    DWORD dwVersion;
    DWORD cbAuthIdentity;
    SEC_WINNT_AUTH_IDENTITY_INFO AuthIdentity = { 0 };
    BOOLEAN bWowClient = GsspIsWowClientCall();

    Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                                                      sizeof(DWORD),
                                                      &dwVersion,
                                                      AuthIdentityBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    switch (dwVersion) {
    case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
        cbAuthIdentity = sizeof(SEC_WINNT_AUTH_IDENTITY_EX2);
        break;
    case SEC_WINNT_AUTH_IDENTITY_VERSION:
        cbAuthIdentity = sizeof(SEC_WINNT_AUTH_IDENTITY_EXW);
        break;
    case SECPKG_CREDENTIAL_VERSION:
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"ConvertAuthIdentityInfoToGss: Got NegoEx credential from non-NegoEx client!");
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
        break;
    default:
        cbAuthIdentity = sizeof(SEC_WINNT_AUTH_IDENTITY_W);
        break;
    }

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"ConvertAuthIdentityInfoToGss: Client %s "
                   L"Version %08x Size %08x",
                   bWowClient ? L"WOW64" : L"Win32",
                   dwVersion, cbAuthIdentity);

    Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                                                      cbAuthIdentity,
                                                      &AuthIdentity.AuthIdExw,
                                                      AuthIdentityBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    switch (dwVersion) {
    case SEC_WINNT_AUTH_IDENTITY_VERSION_2:
        Status = ConvertAuthIdentityEx2ToGss(&AuthIdentity.AuthIdEx2,
                                             AuthIdentityBuffer,
                                             User,
                                             Domain,
                                             Password,
                                             Flags);
        break;
    case SEC_WINNT_AUTH_IDENTITY_VERSION:
        if (bWowClient) {
            Status = ConvertAuthIdentityEx32ToGss((PVOID)&AuthIdentity,
                                                  User,
                                                  Domain,
                                                  Password,
                                                  Flags);
        } else {
            Status = ConvertAuthIdentityExToGss(&AuthIdentity.AuthIdExw,
                                                User,
                                                Domain,
                                                Password,
                                                Flags);
        }
        break;
    default:
        if (bWowClient) {
            Status = ConvertAuthIdentity32ToGss((PVOID)&AuthIdentity,
                                                User,
                                                Domain,
                                                Password,
                                                Flags);
        } else {
            Status = ConvertAuthIdentityToGss(&AuthIdentity.AuthId_w,
                                              User,
                                              Domain,
                                              Password,
                                              Flags);
        }
        break;
    }
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    return Status;
}

NTSTATUS
MaybeAppendDomain(
    gss_buffer_t User,
    gss_buffer_t Domain)
{
    OM_uint32 Minor;
    NTSTATUS Status;

    if (User->length != 0 && Domain->length != 0) {
        gss_buffer_desc UserAndDomain = GSS_C_EMPTY_BUFFER;

        UserAndDomain.length = User->length;
        if (Domain->length != 0)
            UserAndDomain.length += 1 + Domain->length;

        Status = GsspAlloc(UserAndDomain.length + 1, &UserAndDomain.value);
        if (Status != STATUS_SUCCESS)
            return Status;

        RtlCopyMemory(UserAndDomain.value, User->value, User->length);
        if (Domain->value != NULL) {
            PSTR Suffix = (PSTR)UserAndDomain.value + User->length;
            *Suffix++ = '@';
            RtlCopyMemory(Suffix, Domain->value, Domain->length);
        }
        ((PSTR)UserAndDomain.value)[UserAndDomain.length] = '\0';

        GsspReleaseBuffer(&Minor, User);
        *User = UserAndDomain;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
GsspAcquireCredHandle(
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN ULONG CredentialUseFlags,
    IN OPTIONAL PLUID LogonId,
    IN PVOID AuthIdentityBuffer,
    IN gss_OID Oid,
    OUT gss_cred_id_t *pGssCred,
    OUT PTimeStamp ExpirationTime)
{
    OM_uint32 Major, Minor;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc User = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Domain = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Password = GSS_C_EMPTY_BUFFER;
    gss_name_t GssName = GSS_C_NO_NAME;
    gss_OID_set_desc Oids;

    NTSTATUS Status;
    LUID ActualLogonId;
    ULONG ProcessID;
    BOOLEAN bNegoEx = GsspIsNegoExCall();
    PSECPKG_CREDENTIAL pSPCred = NULL;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS pPackedCreds = NULL;
    ULONG AuthIdentityFlags = 0;

    *pGssCred = GSS_C_NO_CREDENTIAL;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspAcquireCredHandle: PrincipalName %wZ "
                   L"UseFlags %08x LogonId %08x.%08x AuthIdBuffer %p ",
                   PrincipalName, CredentialUseFlags,
                   LogonId ? LogonId->LowPart : 0,
                   LogonId ? LogonId->HighPart : 0,
                   AuthIdentityBuffer);

    if (AuthIdentityBuffer != NULL) {
        if (bNegoEx) {
            pSPCred = (PSECPKG_CREDENTIAL)AuthIdentityBuffer;
            Status = ConvertNegoExCredentialToGss(pSPCred, &User, &Domain,
                                                  &pPackedCreds);
        } else {
            Status = ConvertAuthIdentityInfoToGss(AuthIdentityBuffer,
                                                  &User, &Domain, &Password,
                                                  &AuthIdentityFlags);
        }
        GSSP_BAIL_ON_ERROR(Status);
    }

    GSSP_ASSERT(pSPCred != NULL || bNegoEx == FALSE);

    if (!GsspValidateClientEx(LogonId, 0, pSPCred,
                              &ActualLogonId, &ProcessID, NULL)) {
        Status = SEC_E_NOT_OWNER;
        goto cleanup;
    }

    if (PrincipalName != NULL && User.length == 0) {
        Status = GsspUnicodeStringToGssBuffer(PrincipalName, &User);
        GSSP_BAIL_ON_ERROR(Status);
    }

    Status = MaybeAppendDomain(&User, &Domain);
    GSSP_BAIL_ON_ERROR(Status);

    if (bNegoEx)
        CredentialUseFlags = pSPCred->fCredentials;

    if (User.length != 0) {
        gss_OID UserNameType;

#if 0
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspAcquireCredHandle: Credential Name %.*S",
                       User.length, (PSTR)User.value);
#endif

        if (CredentialUseFlags & SECPKG_CRED_INBOUND)
            UserNameType = GSS_EAP_NT_EAP_NAME; /*  no default realm */
        else
            UserNameType = GSS_C_NT_USER_NAME;

        Major = gssEapImportName(&Minor,
                                 &User,
                                 UserNameType,
                                 GSS_C_NO_OID,
                                 &GssName);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    /*
     * If the caller did not specify a password, then look for a default
     * credential. An explicit password indicates that we should allocate
     * a new credential.
     */
    if (bNegoEx ? (pPackedCreds == NULL) : (Password.value == NULL)) {
        ULONG GssCredFlags = 0;

        if (CredentialUseFlags & SECPKG_CRED_INBOUND)
            GssCredFlags |= CRED_FLAG_ACCEPT;
        if (CredentialUseFlags & SECPKG_CRED_OUTBOUND)
            GssCredFlags |= CRED_FLAG_INITIATE;

        Status = GsspFindCred(&ActualLogonId, ProcessID, GssCredFlags,
                              Oid, GssName, NULL, &GssCred);
        if (Status == SEC_E_UNKNOWN_CREDENTIALS &&
            (GsspFlags & GSSP_FLAG_LOGON_CREDS)) {
            /* Try the logon credential list */
            Status = GsspFindCred(&ActualLogonId, CRED_PROCESS_ID_ALL,
                                  GssCredFlags, Oid, GssName, NULL, &GssCred);
        }
        if (Status == STATUS_SUCCESS) {
            *pGssCred = GssCred;
            GssCred = GSS_C_NO_CREDENTIAL;

            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspAcquireCredHandle: returning cached "
                           L"credential handle %p", *pGssCred);

            goto cleanup;
        }
    }

    Oids.count = 1;
    Oids.elements = Oid;

    Major = gssEapAcquireCred(&Minor,
                              GssName,
                              GSS_C_INDEFINITE,
                              &Oids,
                              GsspUnmapCredUsage(CredentialUseFlags),
                              &GssCred,
                              NULL,
                              NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    if (bNegoEx && pPackedCreds != NULL) {
        Status = GsspSetNegoExCred(GssCred, pPackedCreds);
        GSSP_BAIL_ON_ERROR(Status);
    } else if (Password.value != NULL) {
        Major = gssEapSetCredPassword(&Minor,
                                      GssCred,
                                      &Password);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    if (CredentialUseFlags & SECPKG_CRED_AUTOLOGON_RESTRICTED)
        GssCred->SspFlags |= CRED_SSP_FLAG_AUTOLOGON_RESTRICTED;
    if (AuthIdentityFlags & SEC_WINNT_AUTH_IDENTITY_ONLY)
        GssCred->SspFlags |= CRED_SSP_FLAG_IDENTITY_ONLY;

    GssCred->LogonId = ActualLogonId;
    GssCred->ProcessID = ProcessID;

    if (ExpirationTime != NULL)
        GsspMapTime(GssCred->expiryTime, ExpirationTime);

    if (CredentialUseFlags & SECPKG_CRED_PROCESS_POLICY_ONLY) {
        Status = SEC_E_NO_CREDENTIALS;
        goto cleanup;
    }

    Status = GsspSetCredDefaultCert(GssCred);
    GSSP_BAIL_ON_ERROR(Status);

    GsspAddCred(GssCred);

    Status = STATUS_SUCCESS;

    *pGssCred = GssCred;
    GssCred = GSS_C_NO_CREDENTIAL; /* don't double-free */

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspAcquireCredHandle: returning new credential handle %p",
                   *pGssCred);

cleanup:
    GsspSecureZeroAndReleaseGssBuffer(&Password);
    GsspReleaseBuffer(&Minor, &User);
    GsspReleaseBuffer(&Minor, &Domain);
    gssEapReleaseName(&Minor, &GssName);
    GsspCredRelease(GssCred);

    return Status;
}

NTSTATUS NTAPI
SpAcquireCredentialsHandleEapAes128(
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN ULONG CredentialUseFlags,
    IN OPTIONAL PLUID LogonId,
    IN PVOID AuthorizationData,
    IN PVOID GetKeyFunction,
    IN PVOID GetKeyArgument,
    OUT PLSA_SEC_HANDLE CredentialHandle,
    OUT PTimeStamp ExpirationTime)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;

    Status = GsspAcquireCredHandle(PrincipalName,
                                   CredentialUseFlags,
                                   LogonId,
                                   AuthorizationData,
                                   GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM,
                                   &GssCred,
                                   ExpirationTime);

    *CredentialHandle = (LSA_SEC_HANDLE)GssCred;

    return Status;
}

NTSTATUS NTAPI
SpAcquireCredentialsHandleEapAes256(
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN ULONG CredentialUseFlags,
    IN OPTIONAL PLUID LogonId,
    IN PVOID AuthorizationData,
    IN PVOID GetKeyFunction,
    IN PVOID GetKeyArgument,
    OUT PLSA_SEC_HANDLE CredentialHandle,
    OUT PTimeStamp ExpirationTime)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;

    Status = GsspAcquireCredHandle(PrincipalName,
                                   CredentialUseFlags,
                                   LogonId,
                                   AuthorizationData,
                                   GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM,
                                   &GssCred,
                                   ExpirationTime);

    *CredentialHandle = (LSA_SEC_HANDLE)GssCred;

    return Status;
}

NTSTATUS NTAPI
SpFreeCredentialsHandle(
    IN LSA_SEC_HANDLE CredentialHandle)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;
    BOOLEAN Rundown = FALSE;

    if (GssCred == GSS_C_NO_CREDENTIAL)
        return SEC_E_INVALID_HANDLE;

    if (!GsspValidateClientEx(&GssCred->LogonId, GssCred->ProcessID,
                              NULL, NULL, NULL, &Rundown) &&
        !Rundown)
        return SEC_E_NOT_OWNER;

    /*
     * If the only references to the credential are the caller and
     * the global credentials list, remove it from the list.
     */
    GsspMaybeRemoveCred(GssCred);

    Major = gssEapReleaseCred(&Minor, &GssCred);
    Status = GsspMapStatus(Major, Minor);

    return Status;
}

NTSTATUS NTAPI
SpQueryCredentialsAttributes(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN ULONG CredentialAttribute,
    IN OUT PVOID Buffer)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;

    Status = GsspCredAddRefAndLock(GssCred);
    if (Status != STATUS_SUCCESS)
        return Status;

    switch (CredentialAttribute) {
    case SECPKG_CRED_ATTR_NAMES:
        Status = GsspCopyGssNameToClient(GssCred->name,
                                         &((PSecPkgCredentials_NamesW)Buffer)->sUserName);
        break;
    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

    GsspCredUnlockAndRelease(GssCred);

    return Status;
}

NTSTATUS NTAPI
SpSetCredentialsAttributes(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN ULONG CredentialAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpSetCredentialsAttributes unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpAddCredentials(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN PUNICODE_STRING Package,
    IN ULONG CredentialUseFlags,
    IN PVOID AuthorizationData,
    IN PVOID GetKeyFunciton,
    IN PVOID GetKeyArgument,
    OUT PTimeStamp ExpirationTime)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpAddCredentials unsupported");

    GsspMapTime(GSS_C_INDEFINITE, ExpirationTime);

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
SpSaveCredentials(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN PSecBuffer Credentials)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpSaveCredentials unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpGetCredentials(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN OUT PSecBuffer Credentials)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpGetCredentials unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpDeleteCredentials(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN PSecBuffer Key)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpDeleteCredentials unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpAcceptCredentialsEapAes128(
    IN SECURITY_LOGON_TYPE LogonType,
    IN PUNICODE_STRING AccountName,
    IN PSECPKG_PRIMARY_CRED PrimaryCredentials,
    IN PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    if ((GsspFlags & GSSP_FLAG_LOGON_CREDS) == 0)
        return SEC_E_UNSUPPORTED_FUNCTION;

    return GsspAcceptCredentials(LogonType, AccountName,
                                 PrimaryCredentials, SupplementalCredentials,
                                 GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM);
}

NTSTATUS NTAPI
SpAcceptCredentialsEapAes256(
    IN SECURITY_LOGON_TYPE LogonType,
    IN PUNICODE_STRING AccountName,
    IN PSECPKG_PRIMARY_CRED PrimaryCredentials,
    IN PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    /* This is a NOOP because logon credentials are only AES128 */
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/*
 * Return the imported GSS name for a certificate name.
 */
static NTSTATUS
GetCertGssName(
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    gss_name_t *pGssName)
{
    PWSTR NameString;
    DWORD ccNameString;
    NTSTATUS Status;

    *pGssName = GSS_C_NO_NAME;

    ccNameString = CertGetNameString(pCertContext,
                                     dwType,
                                     0,
                                     NULL,
                                     NULL,
                                     0);
    if (ccNameString == 0)
        return GetLastError();
    else if (ccNameString == 1)
        return SEC_E_OK;

    Status = GsspAlloc(sizeof(WCHAR) * ccNameString, &NameString);
    if (Status != STATUS_SUCCESS)
        return Status;

    ccNameString = CertGetNameString(pCertContext,
                                     dwType,
                                     0,
                                     NULL,
                                     NameString,
                                     ccNameString);
    if (ccNameString > 1)
        Status = GsspImportNameW(NameString, pGssName);
    else
        Status = GetLastError();

    GsspFree(NameString);

    return Status;
}

/*
 * Get the certificate subject name from the e-mail or UPN SAN.
 */
static NTSTATUS
GetClientCertificateSubject(
    PCERT_CREDENTIAL_INFO CertCredInfo,
    gss_name_t *pUserName)
{
    NTSTATUS Status, ImpersonationStatus;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT CertContext = NULL;
    CRYPT_HASH_BLOB CertHash;
    PWSTR ClientName = NULL;

    *pUserName = GSS_C_NO_NAME;

    /* Need to be in the user context to do this */
    Status = GsspImpersonateClient();
    if (Status != STATUS_SUCCESS)
        return Status;

    hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                               0,
                               (HCRYPTPROV_LEGACY)0,
                               CERT_SYSTEM_STORE_CURRENT_USER |
                                CERT_STORE_OPEN_EXISTING_FLAG |
                                CERT_STORE_READONLY_FLAG,
                               (const void *)L"MY");
    if (hCertStore == NULL) {
        Status = GetLastError();
        goto cleanup;
    }

    CertHash.cbData = CERT_HASH_LENGTH;
    CertHash.pbData = CertCredInfo->rgbHashOfCert;

    CertContext = CertFindCertificateInStore(hCertStore,
                                             X509_ASN_ENCODING |
                                                PKCS_7_ASN_ENCODING,
                                             0,
                                             CERT_FIND_HASH,
                                             &CertHash,
                                             NULL);
    if (CertContext == NULL) {
        Status = GetLastError();
        goto cleanup;
    }

    Status = GetCertGssName(CertContext, CERT_NAME_UPN_TYPE, pUserName);
    GSSP_BAIL_ON_ERROR(Status);

    if (*pUserName == GSS_C_NO_NAME) {
        Status = GetCertGssName(CertContext, CERT_NAME_EMAIL_TYPE, pUserName);
        GSSP_BAIL_ON_ERROR(Status);
    }

    /*
     * Now, see if SubjectAltName matches ClientName.
     */

cleanup:
    ImpersonationStatus = GsspRevertToSelf();
    if (ImpersonationStatus != STATUS_SUCCESS)
        Status = ImpersonationStatus;

    if (CertContext != NULL)
        CertFreeCertificateContext(CertContext);
    if (hCertStore != NULL)
        CertCloseStore(hCertStore, 0);
    GsspFree(ClientName);

    return Status;
}

static OM_uint32
SetClientCertificate(
    OM_uint32 *Minor,
    gss_cred_id_t GssCred,
    PWSTR MarshaledCredential)
{
    PCERT_CREDENTIAL_INFO pCertCredInfo;
    CRED_MARSHAL_TYPE CredType;
    char CertHashData[CLIENT_HASH_PREFIX_LEN + 2 * CERT_HASH_LENGTH + 1] = CLIENT_HASH_PREFIX;
    gss_buffer_desc GssCertHash;
    OM_uint32 Major;

    if (!CredUnmarshalCredential(MarshaledCredential,
                                 &CredType,
                                 &pCertCredInfo))
        return GSS_S_BAD_NAME;

    if (pCertCredInfo == NULL)
        return GSS_S_FAILURE;

    if (CredType != CertCredential ||
        pCertCredInfo->cbSize < sizeof(*pCertCredInfo)) {
        CredFree(pCertCredInfo);
        *Minor = GSSEAP_WRONG_SIZE;
        return GSS_S_DEFECTIVE_CREDENTIAL;
    }

    GetClientCertificateSubject(pCertCredInfo, &GssCred->name);

    wpa_snprintf_hex(&CertHashData[CLIENT_HASH_PREFIX_LEN],
                     sizeof(CertHashData) - CLIENT_HASH_PREFIX_LEN,
                     pCertCredInfo->rgbHashOfCert,
                     CERT_HASH_LENGTH);

    GssCertHash.length = CLIENT_HASH_PREFIX_LEN + 2 * CERT_HASH_LENGTH;
    GssCertHash.value = CertHashData;

    Major = gssEapSetCredClientCertificate(Minor, GssCred,
                                           GSS_C_NO_BUFFER, &GssCertHash);

    CredFree(pCertCredInfo);

    return Major;
}

static NTSTATUS
CMAttrSetCACert(
    PCREDENTIAL_ATTRIBUTE Attribute,
    gss_cred_id_t GssCred)
{
    NTSTATUS Status;
    UNICODE_STRING CaCertificate;
    OM_uint32 Minor;

    /* Certificate path is stored as a Unicode string */
    CaCertificate.Length        = Attribute->ValueSize;
    CaCertificate.MaximumLength = Attribute->ValueSize;
    CaCertificate.Buffer        = (PWSTR)Attribute->Value;

    GsspReleaseBuffer(&Minor, &GssCred->caCertificate);

    Status = GsspUnicodeStringToGssBuffer(&CaCertificate,
                                          &GssCred->caCertificate);

    return Status;
}

static NTSTATUS
CMAttrSetServerCertHash(
    PCREDENTIAL_ATTRIBUTE Attribute,
    gss_cred_id_t GssCred)
{
    NTSTATUS Status;
    DWORD cchHash;
    LPSTR szHash;
    OM_uint32 Minor;

    /* Server certificate SHA-1 hash */
    cchHash = HASH_PREFIX_LEN + (2 * Attribute->ValueSize);

    Status = GsspAlloc(cchHash + 1, &szHash);
    if (Status != STATUS_SUCCESS)
        return Status;

    RtlCopyMemory(szHash, HASH_PREFIX, HASH_PREFIX_LEN);

    wpa_snprintf_hex(&szHash[HASH_PREFIX_LEN],
                     cchHash + 1 - HASH_PREFIX_LEN,
                     Attribute->Value,
                     Attribute->ValueSize);

    GsspReleaseBuffer(&Minor, &GssCred->caCertificate);

    GssCred->caCertificate.length = cchHash;
    GssCred->caCertificate.value = szHash;

    return STATUS_SUCCESS;
}

static NTSTATUS
CMAttrSetSubjectName(
    PCREDENTIAL_ATTRIBUTE Attribute,
    gss_cred_id_t GssCred)
{
    NTSTATUS Status;
    DWORD cbSize;
    CERT_NAME_BLOB CertNameBlob;
    UNICODE_STRING CertName;

    RtlInitUnicodeString(&CertName, NULL);

    /* Subject name is stored as an encoded certificate name blob */
    CertNameBlob.cbData = Attribute->ValueSize;
    CertNameBlob.pbData = Attribute->Value;

    cbSize = CertNameToStr(X509_ASN_ENCODING,
                           &CertNameBlob,
                           CERT_X500_NAME_STR,
                           NULL,
                           0);

    if (cbSize == 0)
        return GetLastError();
    else if (cbSize == 1)
        return STATUS_SUCCESS;

    Status = GsspAlloc((cbSize + 1) * sizeof(WCHAR), &CertName.Buffer);
    if (Status != STATUS_SUCCESS)
        return Status;

    cbSize = CertNameToStr(X509_ASN_ENCODING,
                           &CertNameBlob,
                           CERT_X500_NAME_STR,
                           CertName.Buffer,
                           cbSize);
    if (cbSize == 0)
        return GetLastError();

    CertName.Length = cbSize * sizeof(WCHAR);
    CertName.MaximumLength = CertName.Length;

    Status = GsspUnicodeStringToGssBuffer(&CertName,
                                          &GssCred->subjectNameConstraint);

    GsspFree(CertName.Buffer);

    return Status;
}

static NTSTATUS
CMAttrSetSubjectAltName(
    PCREDENTIAL_ATTRIBUTE Attribute,
    gss_cred_id_t GssCred)
{
    NTSTATUS Status;
    UNICODE_STRING SubjectAltName;

    /* Subject alt name is stored as a Unicode string */
    SubjectAltName.Length        = Attribute->ValueSize;
    SubjectAltName.MaximumLength = Attribute->ValueSize;
    SubjectAltName.Buffer        = (PWSTR)Attribute->Value;

    Status = GsspUnicodeStringToGssBuffer(&SubjectAltName,
                                          &GssCred->subjectAltNameConstraint);

    return Status;
}

typedef NTSTATUS (*CMAttrSetterFn)(PCREDENTIAL_ATTRIBUTE Attr,
                                   gss_cred_id_t GssCred);

static struct {
    LPWSTR Attribute;
    CMAttrSetterFn Setter;
} CMAttrSetters[] = {
    { L"Moonshot_CACertificate",            CMAttrSetCACert             },
    { L"Moonshot_ServerCertificateHash",    CMAttrSetServerCertHash     },
    { L"Moonshot_SubjectNameConstraint",    CMAttrSetSubjectName        },
    { L"Moonshot_SubjectAltNameConstraint", CMAttrSetSubjectAltName     },
};

static OM_uint32
ConvertCredManCredToGssCred(
    OM_uint32 *Minor,
    PLUID LogonId,
    ULONG ProcessId,
    const gss_name_t NameMatch,
    gss_OID_set Oids,
    PCREDENTIALW Credential,
    gss_cred_id_t *pGssCred)
{
    OM_uint32 Major;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;
    ULONG i;
    NTSTATUS Status;

    *pGssCred = GSS_C_NO_CREDENTIAL;

    switch (Credential->Type) {
    case CRED_TYPE_DOMAIN_PASSWORD:
    case CRED_TYPE_DOMAIN_CERTIFICATE:
    case CRED_TYPE_DOMAIN_EXTENDED:
#if 0
    case CRED_TYPE_GENERIC:
    case CRED_TYPE_GENERIC_CERTIFICATE:
#endif
        break;
    default:
        /* Don't know what to do with these credentials, yet. */
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"ConvertCredManCredToGssCred: unknown credential type %d",
                       Credential->Type);
        Major = GSS_S_NO_CRED;
        *Minor = GSSEAP_NO_DEFAULT_CRED;
        goto cleanup;
    }

    Major = gssEapAllocCred(Minor, &GssCred);
    if (GSS_ERROR(Major))
        goto cleanup;

    GssCred->flags = CRED_FLAG_INITIATE;

    Major = duplicateOidSet(Minor, Oids, &GssCred->mechanisms);
    if (GSS_ERROR(Major))
        goto cleanup;

    if (Credential->Type == CRED_TYPE_DOMAIN_CERTIFICATE) {
        Major = SetClientCertificate(Minor, GssCred,
                                     Credential->UserName);
        if (GSS_ERROR(Major))
            goto cleanup;
    } else {
        Major = gssEapImportNameW(Minor, Credential->UserName,
                                  GSS_C_NT_USER_NAME, GSS_C_NO_OID,
                                  &GssCred->name);
        if (GSS_ERROR(Major))
            goto cleanup;
    }

    if (NameMatch != GSS_C_NO_NAME && GssCred->name != GSS_C_NO_NAME) {
        int IsDesiredName = 0;

        /*
         * In the case we have multiple credentials for the same target,
         * and a qualifying username was passed in, check for a match.
         */
        Major = gssEapCompareName(Minor, GssCred->name,
                                  NameMatch, &IsDesiredName);
        if (GSS_ERROR(Major))
            goto cleanup;

        if (!IsDesiredName) {
            Major = GSS_S_NO_CRED;
            *Minor = GSSEAP_NO_DEFAULT_CRED;
            goto cleanup;
        }
    }

    if (Credential->TargetName != NULL) {
        Major = gssEapImportNameW(Minor, Credential->TargetName,
                                  GSS_EAP_NT_EAP_NAME, GSS_C_NO_OID,
                                  &GssCred->target);
        if (GSS_ERROR(Major))
            goto cleanup;

        GssCred->flags |= CRED_FLAG_TARGET;
    }

    /*
     * This contains the password or the private key passphrase in the
     * case of a certificate.
     * XXX does this actually contain the certificate for generic certs?
     */
    if (Credential->CredentialBlobSize != 0) {
        UNICODE_STRING UnicodePassword;

        UnicodePassword.Length        = Credential->CredentialBlobSize;
        UnicodePassword.MaximumLength = Credential->CredentialBlobSize;
        UnicodePassword.Buffer        = (PWSTR)Credential->CredentialBlob;

        LsaSpFunctionTable->LsaUnprotectMemory(Credential->CredentialBlob,
                                               Credential->CredentialBlobSize);

        Status = GsspUnicodeStringToGssBuffer(&UnicodePassword,
                                              &GssCred->password);

        LsaSpFunctionTable->LsaProtectMemory(Credential->CredentialBlob,
                                             Credential->CredentialBlobSize);

        if (Status != STATUS_SUCCESS) {
            Major = GSS_S_FAILURE;
            *Minor = ENOMEM;
            goto cleanup;
        }

        GsspProtectCred(GssCred);

        GssCred->flags |= CRED_FLAG_PASSWORD;
    }

    /*
     * Use credential attributes to contain CA certificate, subject name
     * constraint, and alt name constraint.
     */
    for (i = 0; i < Credential->AttributeCount; i++) {
        PCREDENTIAL_ATTRIBUTE Attribute = &Credential->Attributes[i];
        DWORD j;

        if (Attribute->Keyword == NULL)
            continue;

        for (j = 0;
             j < sizeof(CMAttrSetters) / sizeof(CMAttrSetters[0]);
             j++) {
            if (wcscmp(Attribute->Keyword, CMAttrSetters[j].Attribute) == 0) {
                Status = CMAttrSetters[j].Setter(Attribute, GssCred);
                if (Status != STATUS_SUCCESS) {
                    Major = GSS_S_FAILURE;
                    *Minor = (Status == STATUS_NO_MEMORY)
                             ? ENOMEM : GSSEAP_BAD_CRED_OPTION;
                    goto cleanup;
                }
                break;
            }
        }
    }

    GssCred->LogonId   = *LogonId;
    GssCred->ProcessID = ProcessId;
    GssCred->SspFlags  = CRED_SSP_FLAG_CREDMAN;

    GssCred->flags |= CRED_FLAG_RESOLVED;

    Major = GSS_S_COMPLETE;
    *Minor = 0;

    *pGssCred = GssCred;
    GssCred = GSS_C_NO_CREDENTIAL;

cleanup:
    GsspCredRelease(GssCred);

    return Major;
}

static VOID
FreeCredTargetInfo(CREDENTIAL_TARGET_INFORMATION *CredTargetInfo)
{
    GsspFree(CredTargetInfo->TargetName);
    GsspFree(CredTargetInfo->NetbiosServerName);
    GsspFree(CredTargetInfo->DnsServerName);
    GsspFree(CredTargetInfo->NetbiosDomainName);
    GsspFree(CredTargetInfo->DnsDomainName);
    GsspFree(CredTargetInfo->DnsTreeName);
    GsspFree(CredTargetInfo->CredTypes);
    RtlZeroMemory(CredTargetInfo, sizeof(*CredTargetInfo));
}

static NTSTATUS
GetCredTargetInfo(
    gss_OID Oid,
    const gss_name_t GssTargetName,
    CREDENTIAL_TARGET_INFORMATION *CredTargetInfo)
{
    NTSTATUS Status;
    SecPkgInfo PackageInfo;
    krb5_principal KrbPrinc = GssTargetName->krbPrincipal;

    RtlZeroMemory(CredTargetInfo, sizeof(*CredTargetInfo));

    if (KRB_PRINC_LENGTH(KrbPrinc) < 2) {
        Status = SEC_E_TARGET_UNKNOWN;
        goto cleanup;
    }

    Status = GsspDisplayGssNameW(GssTargetName, FALSE,
                                 &CredTargetInfo->TargetName);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspUTF8ToWideString(KRB_PRINC_NAME(KrbPrinc)[1], -1,
                                  FALSE, &CredTargetInfo->DnsServerName, NULL);
    GSSP_BAIL_ON_ERROR(Status);

    if (KRB_PRINC_REALM(KrbPrinc) && KRB_PRINC_REALM(KrbPrinc)[0]) {
        Status = GsspUTF8ToWideString(KRB_PRINC_REALM(KrbPrinc), -1,
                                      FALSE,
                                      &CredTargetInfo->DnsDomainName, NULL);
        GSSP_BAIL_ON_ERROR(Status);
    }

    if (Oid != GSS_C_NO_OID) {
        Status = GsspGetInfo(Oid, &PackageInfo);
        GSSP_BAIL_ON_ERROR(Status);

        CredTargetInfo->PackageName = PackageInfo.Name; /* not freed */
    }

    Status = STATUS_SUCCESS;

cleanup:
    if (Status != STATUS_SUCCESS)
        FreeCredTargetInfo(CredTargetInfo);

    return Status;
}

#define BAIL_ON_FATAL_CREDMAN_ERROR(Status) \
    switch ((Status)) {                     \
    case STATUS_INVALID_PARAMETER:          \
    case STATUS_NO_SUCH_LOGON_SESSION:      \
    case STATUS_NOT_FOUND:                  \
    case STATUS_SUCCESS:                    \
        break;                              \
    default:                                \
        GSSP_BAIL_ON_ERROR((Status));       \
    }                                       \

static OM_uint32
CredManResolveInitiatorCred(
    OM_uint32 *Minor,
    PLUID LogonId,
    ULONG ProcessId,
    const gss_cred_id_t GssCred,
    const gss_name_t GssTargetName,
    gss_cred_id_t *pGssCred)
{
    NTSTATUS Status;
    CREDENTIAL_TARGET_INFORMATION CredTargetInfo;
    ULONG CredFlags;
    ULONG Count = 0, i;
    PENCRYPTED_CREDENTIALW *Credentials = NULL;

    OM_uint32 Major;
    gss_name_t CredName = GSS_C_NO_NAME;
    gss_OID_set CredMechs = GSS_C_NO_OID_SET;
    gss_OID CredMech = GSS_C_NO_OID;

    *pGssCred = GSS_C_NO_CREDENTIAL;

    Major = GSS_S_CRED_UNAVAIL;
    *Minor = GSSEAP_NO_DEFAULT_CRED;

    RtlZeroMemory(&CredTargetInfo, sizeof(CredTargetInfo));

    if (GssCred != NULL) {
        CredName = GssCred->name;
        CredMechs = GssCred->mechanisms;

        if (CredMechs != NULL && CredMechs->count == 1)
            CredMech = &CredMechs->elements[0];
    }

    Status = GetCredTargetInfo(CredMech, GssTargetName, &CredTargetInfo);
    GSSP_BAIL_ON_ERROR(Status);

    CredFlags = CREDP_FLAGS_IN_PROCESS;

    Status = LsaSpFunctionTable->CrediReadDomainCredentials(LogonId,
                                                            CredFlags,
                                                            &CredTargetInfo,
                                                            0,
                                                            &Count,
                                                            &Credentials);
    BAIL_ON_FATAL_CREDMAN_ERROR(Status);

#if 0
    if (Status != STATUS_SUCCESS) {
        Status = LsaSpFunctionTable->CrediRead(LogonId,
                                               CredFlags,
                                               CredTargetInfo.TargetName,
                                               CRED_TYPE_GENERIC,
                                               0,
                                               &Credential);
        BAIL_ON_FATAL_CREDMAN_ERROR(Status);
    }
#endif

    if (Status != STATUS_SUCCESS) {
        /* Try without SPN, this is what the Kerberos SSP appears to do */
        CREDENTIAL_TARGET_INFORMATION NoSpnCredTargetInfo = CredTargetInfo;

        NoSpnCredTargetInfo.TargetName = NoSpnCredTargetInfo.DnsServerName;

        Status = LsaSpFunctionTable->CrediReadDomainCredentials(LogonId,
                                                                CredFlags,
                                                                &NoSpnCredTargetInfo,
                                                                0,
                                                                &Count,
                                                                &Credentials);
    }
    GSSP_BAIL_ON_ERROR(Status);

    Major = GSS_S_CRED_UNAVAIL;
    *Minor = GSSEAP_NO_DEFAULT_CRED;

    for (i = 0; i < Count; i++) {
        PENCRYPTED_CREDENTIALW Credential = Credentials[i];

        if (!GSS_ERROR(ConvertCredManCredToGssCred(Minor,
                                                   LogonId,
                                                   ProcessId,
                                                   CredName,
                                                   CredMechs,
                                                   &Credential->Cred,
                                                   pGssCred))) {
            Major = GSS_S_COMPLETE;
            *Minor = 0;
        }
    }

    GSSP_ASSERT(*pGssCred != GSS_C_NO_CREDENTIAL || GSS_ERROR(Major));

    /*
     * Copy default certificate store from unresolved credential, if none
     * was explicitly associated with the CredMan one.
     */
    if (!GSS_ERROR(Major) &&
        (*pGssCred)->caCertificate.value == NULL &&
        GssCred->caCertificate.value != NULL) {
        Major = duplicateBuffer(Minor, &GssCred->caCertificate,
                                &(*pGssCred)->caCertificate);
    }

cleanup:
    FreeCredTargetInfo(&CredTargetInfo);

    if (Credentials != NULL)
        LsaSpFunctionTable->CrediFreeCredentials(Count, Credentials);

    return Major;
}

OM_uint32
gssEapResolveInitiatorCred(
    OM_uint32 *Minor,
    const gss_cred_id_t GssCred,
    const gss_name_t GssTargetName,
    gss_cred_id_t *pResolvedCred)
{
    LUID LogonId;
    ULONG ProcessID;
    OM_uint32 Major;
    gss_OID CredMech = GSS_C_NO_OID;
    gss_name_t InitiatorName = GSS_C_NO_NAME;
    gss_cred_id_t ResolvedCred = GSS_C_NO_CREDENTIAL;

    if (!GsspValidateClientEx(
        GssCred != GSS_C_NO_CREDENTIAL ? &GssCred->LogonId : NULL,
        GssCred != GSS_C_NO_CREDENTIAL ? GssCred->ProcessID : 0,
        NULL,
        &LogonId,
        &ProcessID,
        NULL))
        return GSS_S_UNAUTHORIZED;

    if (GssCred != GSS_C_NO_CREDENTIAL) {
        if ((GssCred->flags & CRED_FLAG_INITIATE) == 0) {
            *Minor = GSSEAP_CRED_USAGE_MISMATCH;
            return GSS_S_NO_CRED;
        }

        if (GsspIsCredResolved(GssCred)) {
            /* If we have a certificate or a password, we can authenticate */
            GssCred->flags |= CRED_FLAG_RESOLVED;
            GsspCredAddRef(GssCred);
            GsspCredUnlock(GssCred); /* caller will relock - race? */
            *pResolvedCred = GssCred;
            return GSS_S_COMPLETE;
        }

        CredMech = gssEapPrimaryMechForCred(GssCred);
        InitiatorName = GssCred->name;
    }

    if (GsspFindCred(&LogonId, ProcessID,
                     CRED_FLAG_INITIATE | CRED_FLAG_RESOLVED,
                     CredMech, InitiatorName,
                     GssTargetName, &ResolvedCred) == SEC_E_OK ||
        ((GsspFlags & GSSP_FLAG_LOGON_CREDS) &&
         GsspFindCred(&LogonId, CRED_PROCESS_ID_ALL,
                      CRED_FLAG_INITIATE | CRED_FLAG_RESOLVED,
                      CredMech, InitiatorName,
                      GssTargetName, &ResolvedCred) == SEC_E_OK)) {
        Major = GSS_S_COMPLETE;
    } else if (GssCred == GSS_C_NO_CREDENTIAL ||
        (GssCred->SspFlags & CRED_SSP_FLAG_AUTOLOGON_RESTRICTED) == 0) {
        Major = CredManResolveInitiatorCred(Minor, &LogonId, ProcessID,
                                            GssCred, GssTargetName,
                                            &ResolvedCred);
    } else {
        Major = GSS_S_CRED_UNAVAIL;
        *Minor = GSSEAP_NO_DEFAULT_CRED;
    }

    *pResolvedCred = ResolvedCred;

    return Major;
}

#define CRED_RESOLVED_MASK          ( CRED_FLAG_PASSWORD        | \
                                      CRED_FLAG_CERTIFICATE     | \
                                      CRED_FLAG_RESOLVED )

BOOLEAN
GsspIsCredResolved(gss_cred_id_t GssCred)
{
    /*
     * Currently return TRUE even if an unresolved credential is presented;
     * this is a policy decision, someday we may require further resolution
     * (e.g. prompting of the user to validate the password).
     */
    return
        (GssCred != GSS_C_NO_CREDENTIAL) &&
        ((GssCred->flags & CRED_RESOLVED_MASK) != 0);
}
