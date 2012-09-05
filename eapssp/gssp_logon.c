/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * LSA Authentication Package
 */

#include "gssp.h"

#define GSSP_UNPACK_UNICODE_STRING(BasePtr, Source, Dest)               \
    do {                                                                \
        (Dest)->Length = (Source)->Length;                              \
        (Dest)->MaximumLength = (Source)->MaximumLength;                \
        if ((Source)->Buffer != NULL)                                   \
            (Dest)->Buffer =                                            \
                (PWSTR)((PBYTE)BasePtr + (ULONG_PTR)(Source)->Buffer);  \
        else                                                            \
            (Dest)->Buffer = NULL;                                      \
    } while (0)

#define GSSP_PACK_UNICODE_STRING(SrcBasePtr, DestBasePtr, String)       \
    do {                                                                \
        ULONG_PTR dwOffset;                                             \
                                                                        \
        if ((String)->Buffer != NULL) {                                 \
            dwOffset = (ULONG_PTR)((PBYTE)((String)->Buffer) -          \
                                   (PBYTE)SrcBasePtr);                  \
            (String)->Buffer = (PWSTR)((PBYTE)DestBasePtr + dwOffset);  \
        }                                                               \
    } while (0)

static ULONG LsaAuthenticationPackageId;
static PLSA_DISPATCH_TABLE LsaDispatchTable;

NTSTATUS NTAPI
LsaApInitializePackage(
    IN ULONG AuthenticationPackageId,
    IN PLSA_DISPATCH_TABLE DispatchTable,
    IN OPTIONAL PLSA_STRING Database,
    IN OPTIONAL PLSA_STRING Confidentiality,
    OUT PLSA_STRING *AuthenticationPackageName)
{
    NTSTATUS Status;

    *AuthenticationPackageName = NULL;

    LsaAuthenticationPackageId = AuthenticationPackageId;
    LsaDispatchTable = DispatchTable;

    Status = GsspStringToLsaString(EAP_AES128_PACKAGE_NAME_A,
                                   AuthenticationPackageName);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    return Status;
}

VOID NTAPI
LsaApLogonTerminated(PLUID LogonId)
{
    if (GsspFlags & GSSP_FLAG_LOGON_CREDS)
        GsspRemoveLogonCred(LogonId);
}

static BOOLEAN
IsValidLogonType(SECURITY_LOGON_TYPE LogonType)
{
    switch (LogonType) {
    case Interactive:
    case Unlock:
    case RemoteInteractive:
        return TRUE;
        break;
    default:
        break;
    }

    return FALSE;
}

static NTSTATUS
AcceptLogonCredentials(
    SECURITY_LOGON_TYPE LogonType,
    PUNICODE_STRING AccountName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc User = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Domain = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Password = GSS_C_EMPTY_BUFFER;
    gss_name_t GssName = GSS_C_NO_NAME;
    OM_uint32 Major, Minor;

    /* Remove any existing credentials */
    GsspRemoveLogonCred(&PrimaryCredentials->LogonId);

    if (PrimaryCredentials->Upn.Length != 0) {
        Status = GsspUnicodeStringToGssBuffer(&PrimaryCredentials->Upn, &User);
        GSSP_BAIL_ON_ERROR(Status);
    } else {
        Status = GsspUnicodeStringToGssBuffer(&PrimaryCredentials->DownlevelName, &User);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GsspUnicodeStringToGssBuffer(&PrimaryCredentials->DnsDomainName, &Domain);
        GSSP_BAIL_ON_ERROR(Status);

        Status = MaybeAppendDomain(&User, &Domain);
        GSSP_BAIL_ON_ERROR(Status);
    }

    Major = gssEapImportName(&Minor, &User, GSS_C_NT_USER_NAME,
                             GSS_C_NO_OID, &GssName);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Major = gssEapAcquireCred(&Minor, GssName, GSS_C_INDEFINITE,
                              GSS_C_NO_OID_SET, GSS_C_INITIATE,
                              &GssCred, NULL, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspUnicodeStringToGssBuffer(&PrimaryCredentials->Password,
                                          &Password);
    GSSP_BAIL_ON_ERROR(Status);

    Major = gssEapSetCredPassword(&Minor, GssCred, &Password);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    GssCred->flags |= CRED_FLAG_RESOLVED;
    if (PrimaryCredentials->Flags & PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON)
        GssCred->flags |= CRED_FLAG_CERTIFICATE;
    GssCred->LogonId = PrimaryCredentials->LogonId;
    GssCred->SspFlags |= CRED_SSP_FLAG_LOGON;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"AcceptLogonCredentials: acquired credential %p "
                   L"(flags %08x/%08x) for %.*S (PC flags %08x)",
                   GssCred, GssCred->flags, GssCred->SspFlags,
                   User.length, (PSTR)User.value,
                   PrimaryCredentials->Flags);

    /* Add credentials to global list */
    GsspAddCred(GssCred);

cleanup:
    GsspReleaseBuffer(&Minor, &User);
    GsspReleaseBuffer(&Minor, &Domain);
    GsspSecureZeroAndReleaseGssBuffer(&Password);
    gssEapReleaseName(&Minor, &GssName);
    GsspCredRelease(GssCred);

    return Status;
}

NTSTATUS
GsspAcceptCredentials(
    SECURITY_LOGON_TYPE LogonType,
    PUNICODE_STRING AccountName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials,
    gss_OID MechOid)
{
    GSSP_ASSERT(GsspFlags & GSSP_FLAG_LOGON_CREDS);

    if (!IsValidLogonType(LogonType))
        return STATUS_INVALID_LOGON_TYPE;

    if (PrimaryCredentials == NULL)
        return STATUS_INVALID_PARAMETER;

    /* Check we have a cleartext password */
    if ((PrimaryCredentials->Flags & PRIMARY_CRED_CLEAR_PASSWORD) == 0 ||
        PrimaryCredentials->Password.Length == 0)
        return STATUS_INVALID_PARAMETER;

    /* Check we have a UPN or username and domain */
    if (PrimaryCredentials->Upn.Length == 0 ||
        (PrimaryCredentials->DownlevelName.Length == 0 &&
         PrimaryCredentials->DnsDomainName.Length == 0))
        return STATUS_INVALID_PARAMETER;

    return AcceptLogonCredentials(LogonType, AccountName,
                                  PrimaryCredentials, SupplementalCredentials);
}

#ifdef GSSEAP_ENABLE_ACCEPTOR
/*
 * Perform ISC/ASC loop internally to establish a security context
 * with a given credential.
 */
static NTSTATUS
GsspInitAcceptSecContext(
    gss_cred_id_t InitiatorCred,
    gss_cred_id_t AcceptorCred,
    gss_ctx_id_t *pGssContext,
    TimeStamp *pExpirationTime)
{
    NTSTATUS Status;
    BOOLEAN MappedContext;
    UNICODE_STRING TargetName;
    OM_uint32 Major, Minor;
    gss_name_t GssTargetName = GSS_C_NO_NAME;

    SecBuffer InitiatorToken;
    SecBufferDesc InitiatorBuffers;
    gss_ctx_id_t InitiatorContext = GSS_C_NO_CONTEXT;
    ULONG InitiatorAttributes = 0;
    TimeStamp InitiatorTime;

    SecBuffer AcceptorToken;
    SecBufferDesc AcceptorBuffers;
    gss_ctx_id_t AcceptorContext = GSS_C_NO_CONTEXT;
    ULONG AcceptorAttributes = 0;
    TimeStamp AcceptorTime = { 0, 0 };

    InitiatorToken.cbBuffer = 0;
    InitiatorToken.BufferType = SECBUFFER_TOKEN;
    InitiatorToken.pvBuffer = NULL;
    InitiatorBuffers.ulVersion = SECBUFFER_VERSION;
    InitiatorBuffers.cBuffers = 1;
    InitiatorBuffers.pBuffers = &InitiatorToken;

    AcceptorToken.cbBuffer = 0;
    AcceptorToken.BufferType = SECBUFFER_TOKEN;
    AcceptorToken.pvBuffer = NULL;
    AcceptorBuffers.ulVersion = SECBUFFER_VERSION;
    AcceptorBuffers.cBuffers = 1;
    AcceptorBuffers.pBuffers = &AcceptorToken;

    *pGssContext = GSS_C_NO_CONTEXT;

    RtlInitUnicodeString(&TargetName, NULL);

    /*
     * XXX using preallocated buffers is necessary to avoid calls to
     * CopyToClientBuffer.
     */
    Status = GsspAlloc(EAPSSP_MAX_TOKEN_SIZE, &InitiatorToken.pvBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspAlloc(EAPSSP_MAX_TOKEN_SIZE, &AcceptorToken.pvBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    /* This is necessary to resolve the target name */
    Major = gssEapInquireCred(&Minor, AcceptorCred, &GssTargetName,
                              NULL, NULL, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspDisplayGssNameUnicodeString(GssTargetName, FALSE, &TargetName);
    GSSP_BAIL_ON_ERROR(Status);

    do {
        InitiatorToken.cbBuffer = EAPSSP_MAX_TOKEN_SIZE;

        Status = GsspInitSecContext((LSA_SEC_HANDLE)InitiatorCred,
                                    (LSA_SEC_HANDLE)InitiatorContext,
                                    &TargetName,
                                    ISC_REQ_MUTUAL_AUTH,
                                    SECURITY_NATIVE_DREP,
                                    &AcceptorBuffers,
                                    (PLSA_SEC_HANDLE)&InitiatorContext,
                                    &InitiatorBuffers,
                                    &InitiatorAttributes,
                                    &InitiatorTime,
                                    &MappedContext,
                                    NULL, /* ContextData */
                                    GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM);
        if (Status != SEC_E_OK && Status != SEC_I_CONTINUE_NEEDED)
            goto cleanup;

        if (InitiatorToken.cbBuffer != 0) {
            AcceptorToken.cbBuffer = EAPSSP_MAX_TOKEN_SIZE;

            Status = GsspAcceptSecContext((LSA_SEC_HANDLE)AcceptorCred,
                                          (LSA_SEC_HANDLE)AcceptorContext,
                                          &InitiatorBuffers,
                                          ASC_REQ_MUTUAL_AUTH,
                                          SECURITY_NATIVE_DREP,
                                          (PLSA_SEC_HANDLE)&AcceptorContext,
                                          &AcceptorBuffers,
                                          &AcceptorAttributes,
                                          &AcceptorTime,
                                          &MappedContext,
                                          NULL);
            if (Status != SEC_E_OK && Status != SEC_I_CONTINUE_NEEDED)
                goto cleanup;

            AcceptorContext->flags |= CTX_FLAG_LOGON;
        }
    } while (Status == SEC_I_CONTINUE_NEEDED);

    GSSP_BAIL_ON_ERROR(Status);

    if ((InitiatorAttributes & ISC_RET_MUTUAL_AUTH) == 0) {
        Status = SEC_E_MUTUAL_AUTH_FAILED;
        goto cleanup;
    }

    *pGssContext = AcceptorContext;
    *pExpirationTime = AcceptorTime;

    AcceptorContext = GSS_C_NO_CONTEXT;

cleanup:
    GsspFree(InitiatorToken.pvBuffer);
    GsspFree(AcceptorToken.pvBuffer);
    GsspFreeUnicodeString(&TargetName);
    GsspContextRelease(InitiatorContext);
    GsspContextRelease(AcceptorContext);
    gssEapReleaseName(&Minor, &GssTargetName);

    return Status;
}

static NTSTATUS
GsspUnpackInteractiveLogon(
    PKERB_INTERACTIVE_LOGON pKILIn,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    PKERB_INTERACTIVE_LOGON pKILOut,
    PLUID LogonId)
{
    NTSTATUS Status;
    DWORD cbLogon;

    RtlZeroMemory(pKILOut, sizeof(*pKILOut));

    pKILOut->MessageType = pKILIn->MessageType;

    if (pKILIn->MessageType == KerbWorkstationUnlockLogon)
        cbLogon = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    else
        cbLogon = sizeof(KERB_INTERACTIVE_LOGON);
    if (SubmitBufferSize < cbLogon)
        return STATUS_BUFFER_TOO_SMALL;

    if (pKILIn->MessageType == KerbWorkstationUnlockLogon) {
        *LogonId = ((PKERB_INTERACTIVE_UNLOCK_LOGON)pKILIn)->LogonId;
    } else {
        LogonId->LowPart = 0;
        LogonId->HighPart = 0;
    }

    GSSP_BAIL_ON_BAD_OFFSET(SubmitBufferSize,
                            (ULONG_PTR)pKILIn->LogonDomainName.Buffer,
                            pKILIn->LogonDomainName.Length);
    GSSP_BAIL_ON_BAD_OFFSET(SubmitBufferSize,
                            (ULONG_PTR)pKILIn->UserName.Buffer,
                            pKILIn->UserName.Length);
    GSSP_BAIL_ON_BAD_OFFSET(SubmitBufferSize,
                            (ULONG_PTR)pKILIn->Password.Buffer,
                            pKILIn->Password.Length);

    GSSP_UNPACK_UNICODE_STRING(pKILIn,
                               &pKILIn->LogonDomainName,
                               &pKILOut->LogonDomainName);
    GSSP_UNPACK_UNICODE_STRING(pKILIn,
                               &pKILIn->UserName,
                               &pKILOut->UserName);
    GSSP_UNPACK_UNICODE_STRING(pKILIn,
                               &pKILIn->Password,
                               &pKILOut->Password);

    Status = STATUS_SUCCESS;

cleanup:
    return Status;
}

static NTSTATUS
GsspUnpackSmartCardLogon(
    PKERB_SMART_CARD_LOGON pKSLIn,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    PKERB_SMART_CARD_LOGON pKSLOut,
    PLUID LogonId)
{
    NTSTATUS Status;
    DWORD cbLogon;

    RtlZeroMemory(pKSLOut, sizeof(*pKSLOut));

    if (pKSLIn->MessageType == KerbSmartCardUnlockLogon)
        cbLogon = sizeof(KERB_SMART_CARD_UNLOCK_LOGON);
    else
        cbLogon = sizeof(KERB_SMART_CARD_LOGON);
    if (SubmitBufferSize < cbLogon)
        return STATUS_BUFFER_TOO_SMALL;

    if (pKSLIn->MessageType == KerbSmartCardUnlockLogon) {
        *LogonId = ((PKERB_SMART_CARD_UNLOCK_LOGON)pKSLIn)->LogonId;
    } else {
        LogonId->LowPart = 0;
        LogonId->HighPart = 0;
    }

    pKSLOut->MessageType = pKSLOut->MessageType;

    GSSP_BAIL_ON_BAD_OFFSET(SubmitBufferSize,
                            (ULONG_PTR)pKSLIn->Pin.Buffer,
                            pKSLIn->Pin.Length);
    GSSP_BAIL_ON_BAD_OFFSET(SubmitBufferSize,
                            (ULONG_PTR)pKSLIn->CspData,
                            pKSLIn->CspDataLength);

    GSSP_UNPACK_UNICODE_STRING(pKSLIn,
                               &pKSLIn->Pin,
                               &pKSLOut->Pin);

    pKSLOut->CspDataLength = pKSLIn->CspDataLength;
    pKSLOut->CspData = (PBYTE)pKSLIn + (ULONG_PTR)pKSLIn->CspData;

    Status = STATUS_SUCCESS;

cleanup:
    return Status;
}

static NTSTATUS
GsspSetCredCspData(
    gss_cred_id_t GssCred,
    PKERB_SMART_CARD_LOGON pKSL)
{
    NTSTATUS Status;
    PKERB_SMARTCARD_CSP_INFO pCspInfo;
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hUserKey = 0;
    CRYPT_KEY_PROV_INFO KeyProvInfo;
    PWSTR wszCardName;
    PWSTR wszReaderName;
    PWSTR wszContainerName;
    PWSTR wszCSPName;
    BYTE *pbCertificate = NULL;
    DWORD cbCertificate;

    if (pKSL->CspDataLength < sizeof(DWORD))
        return STATUS_BUFFER_TOO_SMALL;

    pCspInfo = (PKERB_SMARTCARD_CSP_INFO)pKSL->CspData;

    if (pKSL->CspDataLength < pCspInfo->dwCspInfoLen)
        return STATUS_INVALID_PARAMETER;

    /* XXX do we need to validate this structure? */

    wszCardName      = &pCspInfo->bBuffer + pCspInfo->nCardNameOffset;
    wszReaderName    = &pCspInfo->bBuffer + pCspInfo->nReaderNameOffset;
    wszContainerName = &pCspInfo->bBuffer + pCspInfo->nContainerNameOffset;
    wszCSPName       = &pCspInfo->bBuffer + pCspInfo->nCSPNameOffset;

    if (!CryptAcquireContext(&hCryptProv, wszContainerName,
                             wszCSPName, PROV_RSA_FULL, CRYPT_SILENT)) {
        Status = GetLastError();
        goto cleanup;
    }

    if (!CryptGetUserKey(hCryptProv, pCspInfo->KeySpec, &hUserKey)) {
        Status = GetLastError();
        goto cleanup;
    }

    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, NULL, &cbCertificate, 0)) {
        Status = GetLastError();
        goto cleanup;
    }

    Status = GsspAlloc(cbCertificate, (PVOID *)&pbCertificate);
    GSSP_BAIL_ON_ERROR(Status);

    if (!CryptGetKeyParam(hUserKey, KP_CERTIFICATE, pbCertificate, &cbCertificate, 0)) {
        Status = GetLastError();
        goto cleanup;
    }

    GssCred->CertContext = CertCreateCertificateContext(X509_ASN_ENCODING |
                                                            PKCS_7_ASN_ENCODING,
                                                        pbCertificate,
                                                        cbCertificate);
    if (GssCred->CertContext == NULL) {
        Status = GetLastError();
        goto cleanup;
    }

    RtlZeroMemory(&KeyProvInfo, sizeof(KeyProvInfo));
    KeyProvInfo.pwszContainerName   = wszContainerName;
    KeyProvInfo.pwszProvName        = wszCSPName;
    KeyProvInfo.dwProvType          = PROV_RSA_FULL;
    KeyProvInfo.dwFlags             = CRYPT_SILENT;
    KeyProvInfo.dwKeySpec           = pCspInfo->KeySpec;

    if (!CertSetCertificateContextProperty(GssCred->CertContext,
                                           CERT_KEY_PROV_INFO_PROP_ID,
                                           0,
                                           &KeyProvInfo)) {
        Status = GetLastError();
        goto cleanup;
    }

    Status = STATUS_SUCCESS;

cleanup:
    if (hUserKey != 0)
        CryptDestroyKey(hUserKey);
    if (hCryptProv != 0)
        CryptReleaseContext(hCryptProv, 0);
    GsspFree(pbCertificate);

    return Status;
}

static NTSTATUS
ProtectedUnicodeStringToGssBuffer(
    PUNICODE_STRING ProtectedString,
    gss_buffer_t GssBuffer)
{
    NTSTATUS Status;
    CRED_PROTECTION_TYPE ProtectionType;
    UNICODE_STRING ProtectedString0;
    PWSTR wszUnprotectedString = NULL;
    DWORD cchUnprotectedString = 0;
    UNICODE_STRING UnprotectedString;

    if (pfnCredIsProtected == NULL || pfnCredUnprotect == NULL)
        return GsspUnicodeStringToGssBuffer(ProtectedString, GssBuffer);

    RtlInitUnicodeString(&ProtectedString0, NULL);

    GssBuffer->length = 0;
    GssBuffer->value = NULL;

    Status = GsspDuplicateUnicodeString(ProtectedString, FALSE,
                                        &ProtectedString0);
    GSSP_BAIL_ON_ERROR(Status);

    if (!pfnCredIsProtected(ProtectedString0.Buffer, &ProtectionType)) {
        Status = GetLastError();
        goto cleanup;
    }

    if (ProtectionType != CredUnprotected) {
        if (!pfnCredUnprotect(FALSE, ProtectedString0.Buffer,
                              ProtectedString0.Length / sizeof(WCHAR),
                              NULL, &cchUnprotectedString)) {
            Status = GetLastError();
            if (Status != ERROR_INSUFFICIENT_BUFFER)
                goto cleanup;
        }

        Status = GsspAlloc(cchUnprotectedString * sizeof(WCHAR),
                           (PVOID *)&wszUnprotectedString);
        GSSP_BAIL_ON_ERROR(Status);

        if (!pfnCredUnprotect(FALSE, ProtectedString0.Buffer,
                              ProtectedString0.Length / sizeof(WCHAR),
                              wszUnprotectedString, &cchUnprotectedString)) {
            Status = GetLastError();
            goto cleanup;
        }

        UnprotectedString.Length        = cchUnprotectedString * sizeof(WCHAR);
        UnprotectedString.MaximumLength = UnprotectedString.Length;
        UnprotectedString.Buffer        = wszUnprotectedString;
    } else {
        UnprotectedString = *ProtectedString;
    }

    Status = GsspUnicodeStringToGssBuffer(&UnprotectedString, GssBuffer);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    if (wszUnprotectedString != NULL) {
        RtlSecureZeroMemory(wszUnprotectedString,
                            cchUnprotectedString * sizeof(WCHAR));
        GsspFree(wszUnprotectedString);
    }

    GsspFreeUnicodeString(&ProtectedString0);

    return Status;
}

static NTSTATUS
GsspAcquireInteractiveLogonCred(
    PKERB_INTERACTIVE_LOGON pKIL,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    gss_cred_id_t *pInitiatorCred)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc User = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Domain = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc Password = GSS_C_EMPTY_BUFFER;
    gss_name_t GssName = GSS_C_NO_NAME;
    KERB_INTERACTIVE_LOGON kil;
    OM_uint32 Major, Minor;
    LUID LogonId;

    *pInitiatorCred = NULL;

    Status = GsspUnpackInteractiveLogon(pKIL, ClientBufferBase,
                                        SubmitBufferSize, &kil, &LogonId);
    GSSP_BAIL_ON_ERROR(Status);

    /*
     * Don't try to process local logons; depending on the SSP/AP order,
     * we might lock the user out of the system.
     */
    if (GsspIsLocalHost(&kil.LogonDomainName)) {
        Status = STATUS_NO_LOGON_SERVERS; /* non-critical to LSA */
        goto cleanup;
    }

    Status = GsspUnicodeStringToGssBuffer(&kil.LogonDomainName, &Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspUnicodeStringToGssBuffer(&kil.UserName, &User);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ProtectedUnicodeStringToGssBuffer(&kil.Password, &Password);
    GSSP_BAIL_ON_ERROR(Status);

    Status = MaybeAppendDomain(&User, &Domain);
    GSSP_BAIL_ON_ERROR(Status);

    Major = gssEapImportName(&Minor, &User, GSS_C_NT_USER_NAME,
                             GSS_C_NO_OID, &GssName);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Major = gssEapAcquireCred(&Minor, GssName, GSS_C_INDEFINITE,
                              GSS_C_NO_OID_SET, GSS_C_INITIATE,
                              &GssCred, NULL, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Major = gssEapSetCredPassword(&Minor, GssCred, &Password);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    GssCred->LogonId = LogonId;

    *pInitiatorCred = GssCred;
    GssCred = GSS_C_NO_CREDENTIAL;

cleanup:
    GsspReleaseBuffer(&Minor, &User);
    GsspReleaseBuffer(&Minor, &Domain);
    GsspSecureZeroAndReleaseGssBuffer(&Password);
    gssEapReleaseName(&Minor, &GssName);
    GsspCredRelease(GssCred);

    return Status;
}

static NTSTATUS
GsspAcquireSmartCardLogonCred(
    PKERB_SMART_CARD_LOGON pKSL,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    gss_cred_id_t *pInitiatorCred)
{
    NTSTATUS Status;
    gss_cred_id_t GssCred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc Pin = GSS_C_EMPTY_BUFFER;
    KERB_SMART_CARD_LOGON ksl;
    OM_uint32 Major, Minor;
    LUID LogonId;

    *pInitiatorCred = NULL;

    Status = GsspUnpackSmartCardLogon(pKSL, ClientBufferBase,
                                      SubmitBufferSize, &ksl, &LogonId);
    GSSP_BAIL_ON_ERROR(Status);

    Status = ProtectedUnicodeStringToGssBuffer(&ksl.Pin, &Pin);
    GSSP_BAIL_ON_ERROR(Status);

    Major = gssEapAcquireCred(&Minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                              GSS_C_NO_OID_SET, GSS_C_INITIATE,
                              &GssCred, NULL, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Major = gssEapSetCredPassword(&Minor, GssCred, &Pin);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    GssCred->flags |= CRED_FLAG_CERTIFICATE;

    /* XXX this will require changes to libeap to fetch context */
    Status = GsspSetCredCspData(GssCred, &ksl);
    GSSP_BAIL_ON_ERROR(Status);

    GssCred->LogonId = LogonId;

    *pInitiatorCred = GssCred;
    GssCred = GSS_C_NO_CREDENTIAL;

cleanup:
    GsspSecureZeroAndReleaseGssBuffer(&Pin);
    GsspCredRelease(GssCred);

    return Status;
}

static TOKEN_INFORMATION_CLASS
GsspTokenInfoClasses[] = {
    TokenUser,
    TokenGroups,
    TokenPrimaryGroup,
    TokenPrivileges,
    TokenOwner,
    TokenDefaultDacl,
#if 0
    /* not supported/tested yet */
#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenDeviceGroups,
#endif /* NTDDI_WIN8 */
#endif
};

/*
 * Copy the token identity, privileges, owner and default DACL from
 * the context's token into a contiguous LSA_TOKEN_INFORMATION buffer.
 */
static NTSTATUS
GsspMakeTokenInformation(
    gss_ctx_id_t GssContext,
    PTimeStamp ExpirationTime,
    PVOID *pTokenInformation
    )
{
#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
    PLSA_TOKEN_INFORMATION_V3 TokenInformation = NULL;
#else
    PLSA_TOKEN_INFORMATION_V2 TokenInformation = NULL;
#endif
    NTSTATUS Status;
    DWORD cbTokenInformation = 0;
    DWORD i;
    PBYTE pbTokenBuffer;
    DWORD TokenOffsets[MaxTokenInfoClass] = { 0 };

    cbTokenInformation = sizeof(*TokenInformation);
    cbTokenInformation += TYPE_ALIGNMENT(PVOID) -
                          (cbTokenInformation % TYPE_ALIGNMENT(PVOID));

    for (i = 0; i < sizeof(GsspTokenInfoClasses) / sizeof(GsspTokenInfoClasses[0]); i++) {
        TOKEN_INFORMATION_CLASS InfoClass = GsspTokenInfoClasses[i];
        DWORD cbInfo = 0;

#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
        /*
         * Only propagate claims if the runtime environment supports them.
         */
        if ((GsspFlags & GSSP_FLAG_TOKEN_CLAIMS) == 0 &&
            InfoClass >= TokenUserClaimAttributes)
            break;
#endif /* NTDDI_WIN8 */

        Status = NtQueryInformationToken(GssContext->TokenHandle,
                                         InfoClass, NULL, 0, &cbInfo);
        if (Status == STATUS_BUFFER_TOO_SMALL)
            Status = STATUS_SUCCESS;
        GSSP_BAIL_ON_ERROR(Status);

        TokenOffsets[InfoClass] = cbTokenInformation;

        cbTokenInformation += cbInfo;
        cbTokenInformation += TYPE_ALIGNMENT(PVOID) -
                              (cbInfo % TYPE_ALIGNMENT(PVOID));
    }

    Status = GsspLsaCalloc(1, cbTokenInformation, (PVOID *)&TokenInformation);
    GSSP_BAIL_ON_ERROR(Status);

    pbTokenBuffer = (PBYTE)TokenInformation;

    cbTokenInformation -= TokenOffsets[TokenUser]; /* start at first offset */

    for (i = 0; i < sizeof(GsspTokenInfoClasses) / sizeof(GsspTokenInfoClasses[0]); i++) {
        TOKEN_INFORMATION_CLASS InfoClass = GsspTokenInfoClasses[i];
        DWORD cbInfo = 0;
        PBYTE pbTokenInfo = pbTokenBuffer + TokenOffsets[InfoClass];

#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
        if ((GsspFlags & GSSP_FLAG_TOKEN_CLAIMS) == 0 &&
            InfoClass >= TokenUserClaimAttributes)
            break;
#endif /* NTDDI_WIN8 */

        Status = NtQueryInformationToken(GssContext->TokenHandle,
                                         InfoClass, pbTokenInfo,
                                         cbTokenInformation, &cbInfo);
        GSSP_BAIL_ON_ERROR(Status);

        cbTokenInformation -= cbInfo;
        cbTokenInformation -= TYPE_ALIGNMENT(PVOID) -
                              (cbInfo % TYPE_ALIGNMENT(PVOID));

        GSSP_ASSERT(cbTokenInformation >= 0);
    }

    TokenInformation->ExpirationTime = *ExpirationTime;
    TokenInformation->User =
        *((PTOKEN_USER)(pbTokenBuffer + TokenOffsets[TokenUser]));
    TokenInformation->Groups =
        (PTOKEN_GROUPS)(pbTokenBuffer + TokenOffsets[TokenGroups]);
    TokenInformation->PrimaryGroup =
        *((PTOKEN_PRIMARY_GROUP)(pbTokenBuffer + TokenOffsets[TokenPrimaryGroup]));
    TokenInformation->Privileges =
        (PTOKEN_PRIVILEGES)(pbTokenBuffer + TokenOffsets[TokenPrivileges]);
    TokenInformation->Owner =
        *((PTOKEN_OWNER)(pbTokenBuffer + TokenOffsets[TokenOwner]));
    TokenInformation->DefaultDacl =
        *((PTOKEN_DEFAULT_DACL)(pbTokenBuffer + TokenOffsets[TokenDefaultDacl]));
    /*
     * XXX this is commented out for now because it's not clear how the
     * memory management works, we probably need to fix up the pointers
     * inside the CLAIMS_BLOB.
     */
#if 0 /* defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8) */
    if (GsspFlags & GSSP_FLAG_TOKEN_CLAIMS) {
        TokenInformation->UserClaims =
            *((PTOKEN_USER_CLAIMS)(pbTokenBuffer + TokenOffsets[TokenUserClaimAttributes]));
        TokenInformation->DeviceClaims =
            *((PTOKEN_DEVICE_CLAIMS)(pbTokenBuffer + TokenOffsets[TokenDeviceClaimAttributes]));
        TokenInformation->DeviceGroups =
            ((PTOKEN_GROUPS)(pbTokenBuffer + TokenOffsets[TokenDeviceGroups]));
    }
#endif /* NTDDI_WIN8 */

    /* XXX filter out builtin groups */

    Status = STATUS_SUCCESS;

    *pTokenInformation = (PVOID)TokenInformation;
    TokenInformation = NULL;

cleanup:
    GsspLsaFree(TokenInformation);

    return Status;
}

static NTSTATUS
GsspMakePrimaryCredentials(
    gss_cred_id_t InitiatorCred,
    gss_ctx_id_t AcceptorContext,
    PSECPKG_PRIMARY_CRED PrimaryCredentials)
{
    NTSTATUS Status;
    PSECURITY_LOGON_SESSION_DATA SessionData = NULL;
    LUID LogonId = AcceptorContext->LogonId;

    RtlZeroMemory(PrimaryCredentials, sizeof(*PrimaryCredentials));

    Status = LsaGetLogonSessionData(&LogonId, &SessionData);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDuplicateUnicodeString(&SessionData->UserName, TRUE,
                                        &PrimaryCredentials->DownlevelName);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDuplicateUnicodeString(&SessionData->LogonDomain, TRUE,
                                        &PrimaryCredentials->DomainName);
    GSSP_BAIL_ON_ERROR(Status);

    GsspUnprotectCred(InitiatorCred);
    Status = GsspGssBufferToUnicodeString(&InitiatorCred->password,
                                          TRUE, &PrimaryCredentials->Password);
    GsspProtectCred(InitiatorCred);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDuplicateSid(SessionData->Sid, TRUE,
                              &PrimaryCredentials->UserSid);
    GSSP_BAIL_ON_ERROR(Status);

    PrimaryCredentials->Flags = PRIMARY_CRED_CLEAR_PASSWORD;
    if (InitiatorCred->CertContext != NULL)
        PrimaryCredentials->Flags |= PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON;

    Status = GsspDuplicateUnicodeString(&SessionData->DnsDomainName, TRUE,
                                        &PrimaryCredentials->DnsDomainName);
    GSSP_BAIL_ON_ERROR(Status);

    /* Use the EAP NAI rather than the UPN in the PAC */
    Status = GsspDisplayGssNameUnicodeString(InitiatorCred->name, TRUE,
                                             &PrimaryCredentials->Upn);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDuplicateUnicodeString(&SessionData->LogonServer, TRUE,
                                        &PrimaryCredentials->LogonServer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = STATUS_SUCCESS;

cleanup:
    if (SessionData != NULL)
        LsaFreeReturnBuffer(SessionData);

    return Status;
}

static NTSTATUS
GsspGetProfileBuffer(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN gss_ctx_id_t GssContext,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferSize)
{
    NTSTATUS Status;
    PKERB_INTERACTIVE_PROFILE pKIP;

    *ProfileBuffer = NULL;
    *ProfileBufferSize = 0;

    if (GssContext->ProfileBuffer == NULL) {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    if (GssContext->ProfileBufferLength < sizeof(*pKIP)) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    Status = LsaSpFunctionTable->AllocateClientBuffer(ClientRequest,
                                                      GssContext->ProfileBufferLength,
                                                      ProfileBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    pKIP = (PKERB_INTERACTIVE_PROFILE)GssContext->ProfileBuffer;

    /*
     * EAP doesn't support changing passwords, so we need to make this
     * impossible.
     */
    GsspMapTime(GSS_C_INDEFINITE, &pKIP->PasswordLastSet);
    GsspMapTime(GSS_C_INDEFINITE, &pKIP->PasswordCanChange);
    GsspMapTime(GSS_C_INDEFINITE, &pKIP->PasswordMustChange);

    /*
     * Fix up pointers so that they are relative to the buffer we just
     * allocated in the client's address space.
     */
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->LogonScript);
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->HomeDirectory);
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->FullName);
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->ProfilePath);
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->HomeDirectoryDrive);
    GSSP_PACK_UNICODE_STRING(pKIP, *ProfileBuffer, &pKIP->LogonServer);

    switch (pKIP->MessageType) {
    case KerbSmartCardProfile: {
        PKERB_SMART_CARD_PROFILE pKSCP = *ProfileBuffer;
        DWORD dwOffset;

        dwOffset = pKSCP->CertificateData - (PBYTE)pKSCP;
        pKSCP->CertificateData = (PBYTE)*ProfileBuffer + dwOffset;
        break;
    }
    case KerbTicketProfile: {
        PKERB_TICKET_PROFILE pKTP = *ProfileBuffer;
        DWORD dwOffset;

        dwOffset = pKTP->SessionKey.Value - (PBYTE)pKTP;
        pKTP->SessionKey.Value = (PBYTE)*ProfileBuffer + dwOffset;
        break;
    }
    default:
        break;
    }

    /*
     * Now, copy the buffer with the fixed up pointers to the client's
     * address space.
     */
    Status = LsaSpFunctionTable->CopyToClientBuffer(ClientRequest,
                                                    GssContext->ProfileBufferLength,
                                                    *ProfileBuffer,
                                                    GssContext->ProfileBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    *ProfileBufferSize = GssContext->ProfileBufferLength;

    /*
     * This buffer is now invalid; zero it out for sanity.
     */
    RtlZeroMemory(GssContext->ProfileBuffer, GssContext->ProfileBufferLength);

cleanup:
    /*
     * Defensive programming: don't return a partially initialized buffer.
     */
    if (Status != STATUS_SUCCESS && *ProfileBuffer != NULL) {
        LsaSpFunctionTable->FreeClientBuffer(ClientRequest, *ProfileBuffer);
        *ProfileBuffer = NULL;
    }

    return Status;
}

static NTSTATUS
GsspLogonUser(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PVOID ProtocolSubmitBuffer,
    IN PVOID ClientBufferBase,
    IN ULONG SubmitBufferSize,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferSize,
    OUT PLUID LogonId,
    OUT PNTSTATUS SubStatus,
    OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    OUT PVOID *TokenInformation,
    OUT PUNICODE_STRING *AccountName,
    OUT PUNICODE_STRING *AuthenticatingAuthority,
    OUT PUNICODE_STRING *MachineName,
    OUT PSECPKG_PRIMARY_CRED PrimaryCredentials,
    OUT PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials)
{
    NTSTATUS Status;
    PKERB_INTERACTIVE_LOGON pKIL;
    PUNICODE_STRING pAccountName = NULL;
    gss_cred_id_t InitiatorCred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t AcceptorCred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t AcceptorContext = GSS_C_NO_CONTEXT;
    TimeStamp ExpirationTime;
    OM_uint32 Major, Minor;

    if (SubmitBufferSize < sizeof(KERB_LOGON_SUBMIT_TYPE)) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    pKIL = (PKERB_INTERACTIVE_LOGON)ProtocolSubmitBuffer;

    /*
     * Acquire initiator credentials.
     */
    switch (pKIL->MessageType) {
    case KerbWorkstationUnlockLogon:
    case KerbInteractiveLogon:
        Status = GsspAcquireInteractiveLogonCred(ProtocolSubmitBuffer,
                                                 ClientBufferBase,
                                                 SubmitBufferSize,
                                                 &InitiatorCred);
        if (Status == STATUS_SUCCESS)
            pAccountName = &pKIL->UserName;
        break;
    case KerbSmartCardUnlockLogon:
    case KerbSmartCardLogon:
        Status = GsspAcquireSmartCardLogonCred(ProtocolSubmitBuffer,
                                               ClientBufferBase,
                                               SubmitBufferSize,
                                               &InitiatorCred);
        break;
    default:
        Status = STATUS_BAD_VALIDATION_CLASS;
        break;
    }
    GSSP_BAIL_ON_ERROR(Status);

    /* Allocate now, because it should always be returned */
    Status = GsspLsaCalloc(1, sizeof(UNICODE_STRING), (PVOID *)AccountName);
    GSSP_BAIL_ON_ERROR(Status);

    /*
     * Acquire default acceptor credentials.
     */
    Major = gssEapAcquireCred(&Minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                              GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                              &AcceptorCred, NULL, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    /*
     * Perform InitializeSecurityContext/AcceptSecurityContext exchange.
     */
    Status = GsspInitAcceptSecContext(InitiatorCred, AcceptorCred,
                                      &AcceptorContext, &ExpirationTime);
    GSSP_BAIL_ON_ERROR(Status);

    *SubStatus = AcceptorContext->SubStatus;

    Status = GsspMakePrimaryCredentials(InitiatorCred, AcceptorContext,
                                        PrimaryCredentials);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDuplicateUnicodeString(&PrimaryCredentials->DownlevelName,
                                        TRUE, *AccountName);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspGetProfileBuffer(ClientRequest, AcceptorContext,
                                  ProfileBuffer, ProfileBufferSize);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspMakeTokenInformation(AcceptorContext, &ExpirationTime,
                                      TokenInformation);
    GSSP_BAIL_ON_ERROR(Status);

    if (AuthenticatingAuthority != NULL) {
        Status = GsspLsaCalloc(1, sizeof(UNICODE_STRING),
                               (PVOID *)AuthenticatingAuthority);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GsspDuplicateUnicodeString(&PrimaryCredentials->DomainName,
                                            TRUE, *AuthenticatingAuthority);
        GSSP_BAIL_ON_ERROR(Status);
    }

    if (MachineName != NULL) {
        Status = GsspLsaCalloc(1, sizeof(UNICODE_STRING),
                               (PVOID *)MachineName);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GsspGetLocalHostName(TRUE, *MachineName);
        GSSP_BAIL_ON_ERROR(Status);
    }

    /*
     * Note: the logon session that arose from the actual authentication is
     * discarded, both because we may have an existing logon session, and
     * because there is no way to pass the token handle from the GSS context
     * back to the caller (and when it is deleted, so is the logon session).
     * We could leak the token handle but this would still not handle the
     * unlock case, and it would also leak kernel memory.
     */
    if (SecIsZeroLuid((&InitiatorCred->LogonId))) {
        Status = NtAllocateLocallyUniqueId(LogonId);
        GSSP_BAIL_ON_ERROR(Status);

        Status = LsaSpFunctionTable->CreateLogonSession(LogonId);
        GSSP_BAIL_ON_ERROR(Status);

        InitiatorCred->LogonId = *LogonId;
    } else {
        /* Use existing logon ID from workstation unlock */
        *LogonId = InitiatorCred->LogonId;
    }

    PrimaryCredentials->LogonId = *LogonId;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspLogonUser: logged on user %wZ (logon ID %08x:%08x)",
                   &PrimaryCredentials->Upn,
                   LogonId->LowPart, LogonId->HighPart);

cleanup:
    /* Try to return non-canonical account name for audit purposes */
    if (Status != STATUS_SUCCESS && *AccountName != NULL &&
        (*AccountName)->Buffer == NULL && pAccountName != NULL) {
        GsspDuplicateUnicodeString(pAccountName, TRUE, *AccountName);
    }

    GsspCredRelease(InitiatorCred);
    GsspCredRelease(AcceptorCred);
    GsspContextRelease(AcceptorContext);

    return Status;
}

NTSTATUS NTAPI
LsaApLogonUserEx2(
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PVOID ProtocolSubmitBuffer,
    IN PVOID ClientBufferBase,
    IN ULONG SubmitBufferSize,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferSize,
    OUT PLUID LogonId,
    OUT PNTSTATUS SubStatus,
    OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    OUT PVOID *TokenInformation,
    OUT PUNICODE_STRING *AccountName,
    OUT PUNICODE_STRING *AuthenticatingAuthority,
    OUT PUNICODE_STRING *MachineName,
    OUT PSECPKG_PRIMARY_CRED PrimaryCredentials,
    OUT PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials)
{
    NTSTATUS Status;

    *ProfileBuffer          = NULL;
    *ProfileBufferSize      = 0;
    LogonId->LowPart        = 0;
    LogonId->HighPart       = 0;
    *SubStatus              = STATUS_SUCCESS;
#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
    if (GsspFlags & GSSP_FLAG_TOKEN_CLAIMS)
        *TokenInformationType = LsaTokenInformationV3;
    else
#endif
        *TokenInformationType = LsaTokenInformationV2;
    *AccountName = NULL;
    if (AuthenticatingAuthority != NULL)
        *AuthenticatingAuthority = NULL;
    if (MachineName != NULL)
        *MachineName = NULL;
    RtlZeroMemory(PrimaryCredentials, sizeof(*PrimaryCredentials));
    *SupplementalCredentials = NULL;

    if (!IsValidLogonType(LogonType))
        return STATUS_INVALID_LOGON_TYPE;

    Status = GsspLogonUser(ClientRequest,
                           LogonType,
                           ProtocolSubmitBuffer,
                           ClientBufferBase,
                           SubmitBufferSize,
                           ProfileBuffer,
                           ProfileBufferSize,
                           LogonId,
                           SubStatus,
                           TokenInformationType,
                           TokenInformation,
                           AccountName,
                           AuthenticatingAuthority,
                           MachineName,
                           PrimaryCredentials,
                           SupplementalCredentials);

    /* Map SSPI to NT status code */
    switch (Status) {
    case SEC_E_SECPKG_NOT_FOUND:
        Status = STATUS_NO_SUCH_PACKAGE;
        break;
    case SEC_E_INVALID_PARAMETER:
        Status = STATUS_INVALID_PARAMETER;
        break;
    case SEC_E_INTERNAL_ERROR:
        Status = STATUS_INTERNAL_ERROR;
        break;
    case SEC_E_NO_CREDENTIALS:
    case SEC_E_LOGON_DENIED:
    case SEC_E_CONTEXT_EXPIRED:
        Status = STATUS_LOGON_FAILURE;
        break;
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
        Status = STATUS_NO_LOGON_SERVERS;
        break;
    case SEC_E_UNSUPPORTED_FUNCTION:
        Status = STATUS_NOT_SUPPORTED;
        break;
    default:
        break;
    }

    return Status;
}
#endif /* GSSEAP_ENABLE_ACCEPTOR */
