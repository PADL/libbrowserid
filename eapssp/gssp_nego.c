/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * NegoExts support functions
 */

#include "gssp.h"

NTSTATUS NTAPI
SpValidateTargetInfo(
    __in_opt PLSA_CLIENT_REQUEST ClientRequest,
    __in_bcount(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
    __in PVOID ClientBufferBase,
    __in ULONG SubmitBufferLength,
    __in PSECPKG_TARGETINFO TargetInfo)
{
    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"SpValidateTargetInfo unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpQueryMetaData(
    __in_opt LSA_SEC_HANDLE CredentialHandle,
    __in_opt PUNICODE_STRING TargetName,
    __in ULONG ContextRequirements,
    __out PULONG MetaDataLength,
    __deref_out_bcount(*MetaDataLength) PUCHAR* MetaData,
    __inout PLSA_SEC_HANDLE ContextHandle)
{
    NTSTATUS Status;
    BOOLEAN IsInitiator;

    OM_uint32 Major, Minor;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)*ContextHandle;
    gss_name_t GssTargetName = GSS_C_NO_NAME;
    gss_buffer_desc GssMetaData = GSS_C_EMPTY_BUFFER;

    *MetaDataLength = 0;
    *MetaData = NULL;

    /*
     * Actually, it's fine to have no credentials here; that simply means
     * use the default credentials. In the initiator case, we'll use whatever
     * we get back from gssEapResolveInitiatorCred(); in the acceptor case,
     * that's done inside gssEapAcceptSecContext().
     */
    if (GssCred != GSS_C_NO_CREDENTIAL) {
        Status = GsspCredAddRefAndLock(GssCred);
        if (Status != STATUS_SUCCESS)
            return Status;
    }

    /* Credential is now locked, if present. */

    IsInitiator = (TargetName != NULL);

    if (GssContext == GSS_C_NO_CONTEXT) {
        Status = GsspAllocContext(ContextRequirements, IsInitiator,
                                  GssCred, &GssContext);
        GSSP_BAIL_ON_ERROR(Status);

        *ContextHandle = (LSA_SEC_HANDLE)GssContext;
    }

    if (IsInitiator) {
        Major = gssEapImportNameUnicodeString(&Minor, TargetName,
                                              GSS_EAP_NT_EAP_NAME, GSS_C_NO_OID,
                                              &GssTargetName);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    /*
     * It's a little unclear how much effort we should go to attempting
     * to resolve a credential here, e.g. whether we should contact
     * CredMan. For now, resolve credentials identically to ISC.
     */
    GsspContextAddRefAndLock(GssContext);

    Major = gssEapQueryMetaData(&Minor,
                                GSS_C_NO_OID,
                                GssCred,
                                &GssContext,
                                GssTargetName,
                                GssContext->gssFlags,
                                &GssMetaData);
    if (IsInitiator &&
        Major == GSS_S_CRED_UNAVAIL &&
        Minor == GSSEAP_NO_DEFAULT_CRED)
        Status = SEC_I_INCOMPLETE_CREDENTIALS;
    else
        Status = GsspMapStatus(Major, Minor);

    /* Should be allocated on private heap */
    *MetaDataLength = GssMetaData.length;
    *MetaData = GssMetaData.value;

    GsspContextUnlockAndRelease(GssContext);

cleanup:
    if (GssCred != GSS_C_NO_CREDENTIAL)
        GsspCredUnlockAndRelease(GssCred);

    gssEapReleaseName(&Minor, &GssTargetName);

    return Status;
}

NTSTATUS NTAPI
SpExchangeMetaData(
    __in_opt LSA_SEC_HANDLE CredentialHandle,
    __in_opt PUNICODE_STRING TargetName,
    __in ULONG ContextRequirements,
    __in ULONG MetaDataLength,
    __in_bcount(MetaDataLength) PUCHAR MetaData,
    __inout PLSA_SEC_HANDLE ContextHandle)
{
    NTSTATUS Status;
    BOOLEAN IsInitiator;

    OM_uint32 Major, Minor;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)*ContextHandle;
    gss_name_t GssTargetName = GSS_C_NO_NAME;
    gss_buffer_desc GssMetaData = GSS_C_EMPTY_BUFFER;

    if (GssCred != GSS_C_NO_CREDENTIAL) {
        Status = GsspCredAddRefAndLock(GssCred);
        if (Status != STATUS_SUCCESS)
            return Status;
    }

    IsInitiator = (TargetName != NULL);

    if (GssContext == GSS_C_NO_CONTEXT) {
        Status = GsspAllocContext(ContextRequirements, IsInitiator,
                                  GssCred, &GssContext);
        GSSP_BAIL_ON_ERROR(Status);

        *ContextHandle = (LSA_SEC_HANDLE)GssContext;
    }

    if (IsInitiator) {
        Major = gssEapImportNameUnicodeString(&Minor, TargetName,
                                              GSS_EAP_NT_EAP_NAME, GSS_C_NO_OID,
                                              &GssTargetName);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    GsspContextAddRefAndLock(GssContext);

    GssMetaData.length = MetaDataLength;
    GssMetaData.value = MetaData;

    Major = gssEapExchangeMetaData(&Minor,
                                   GSS_C_NO_OID,
                                   GssCred,
                                   &GssContext,
                                   GssTargetName,
                                   GssContext->gssFlags,
                                   &GssMetaData);
    Status = GsspMapStatus(Major, Minor);

    GsspContextUnlockAndRelease(GssContext);

cleanup:
    if (GssCred != GSS_C_NO_CREDENTIAL)
        GsspCredUnlockAndRelease(GssCred);

    gssEapReleaseName(&Minor, &GssTargetName);

    return Status;
}

NTSTATUS
GsspQueryContextNegoKeys(gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status = SEC_E_INTERNAL_ERROR;
    PSecPkgContext_NegoKeys NegoKeys = (PSecPkgContext_NegoKeys)Buffer;
    DWORD cbKey;

    OM_uint32 Major, Minor;
    gss_buffer_desc InitiatorSalt =
        { NEGOEX_INITIATOR_SALT_LEN, NEGOEX_INITIATOR_SALT };
    gss_buffer_desc AcceptorSalt =
        { NEGOEX_ACCEPTOR_SALT_LEN, NEGOEX_ACCEPTOR_SALT };
    gss_buffer_desc Key = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc VerifyKey = GSS_C_EMPTY_BUFFER;

    RtlZeroMemory(NegoKeys, sizeof(*NegoKeys));

    if (GssContext->encryptionType == ENCTYPE_NULL)
        return STATUS_NOT_FOUND;

    cbKey = KRB_KEY_LENGTH(&GssContext->rfc3961Key);

    Status = GsspLsaAlloc(cbKey, &Key.value);
    GSSP_BAIL_ON_ERROR(Status);

    Key.length = cbKey;

    Major = gssEapPseudoRandom(&Minor, GssContext, GSS_C_PRF_KEY_FULL,
                               CTX_IS_INITIATOR(GssContext) ? &InitiatorSalt : &AcceptorSalt,
                               &Key);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspLsaAlloc(cbKey, &VerifyKey.value);
    GSSP_BAIL_ON_ERROR(Status);

    VerifyKey.length = cbKey;

    Major = gssEapPseudoRandom(&Minor, GssContext, GSS_C_PRF_KEY_FULL,
                               CTX_IS_INITIATOR(GssContext) ? &AcceptorSalt : &InitiatorSalt,
                               &VerifyKey);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    NegoKeys->KeyType = GssContext->encryptionType;
    NegoKeys->KeyLength = Key.length;
    NegoKeys->KeyValue = Key.value;

    NegoKeys->VerifyKeyType = GssContext->encryptionType;
    NegoKeys->VerifyKeyLength = VerifyKey.length;
    NegoKeys->VerifyKeyValue = VerifyKey.value;

    Status = STATUS_SUCCESS;

#if 0
    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspQueryContextNegoKeys: Make Type %d Length %d Value %p / Verify Type %d Length %d Value %p",
                   NegoKeys->KeyType, NegoKeys->KeyLength, NegoKeys->KeyValue,
                   NegoKeys->VerifyKeyType, NegoKeys->VerifyKeyLength, NegoKeys->VerifyKeyValue);
#endif

cleanup:
    if (Status != STATUS_SUCCESS) {
        LsaSpFunctionTable->FreePrivateHeap(Key.value);
        LsaSpFunctionTable->FreePrivateHeap(VerifyKey.value);
    }

    return Status;
}

static NTSTATUS
CredStringFromNegoExCredential(
    PSECPKG_SUPPLIED_CREDENTIAL SuppliedCred,
    PSECPKG_SHORT_VECTOR Vector,
    gss_buffer_t GssBuffer)
{
    UNICODE_STRING u;
    ULONG cbString;
    NTSTATUS Status;

    if (Vector->ShortArrayCount == 0) {
        GssBuffer->length = 0;
        GssBuffer->value = NULL;
        return SEC_E_OK;
    }

    if (Vector->ShortArrayOffset + Vector->ShortArrayCount > SuppliedCred->cbStructureLength)
        return SEC_E_BUFFER_TOO_SMALL;

    cbString = Vector->ShortArrayCount * sizeof(WCHAR);

    if (cbString > MAXUSHORT)
        return STATUS_NAME_TOO_LONG;

    u.Length        = cbString;
    u.MaximumLength = cbString;
    u.Buffer        = (WCHAR *)((PUCHAR)SuppliedCred + Vector->ShortArrayOffset);

    Status = GsspUnicodeStringToGssBuffer(&u, GssBuffer);

    return Status;
}

NTSTATUS
ConvertNegoExCredentialToGss(
    PSECPKG_CREDENTIAL pSPCred,
    gss_buffer_t User,
    gss_buffer_t Domain,
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS *ppPackedCredentials)
{
    NTSTATUS Status;
    PSECPKG_SUPPLIED_CREDENTIAL pSuppliedCred;
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS pPackedCreds;

    *ppPackedCredentials = NULL;

    GSSP_ASSERT(pSPCred != NULL);

    if (pSPCred->Version != SECPKG_CREDENTIAL_VERSION ||
        pSPCred->cbHeaderLength < sizeof(*pSPCred) ||
        pSPCred->cbStructureLength < pSPCred->cbHeaderLength)
        return SEC_E_INVALID_PARAMETER;

    if (pSPCred->MarshaledSuppliedCreds.ByteArrayOffset == 0)
        return SEC_E_OK; /* empty creds */

    if (pSPCred->MarshaledSuppliedCreds.ByteArrayOffset +
        pSPCred->MarshaledSuppliedCreds.ByteArrayLength >
        pSPCred->cbStructureLength)
        return SEC_E_BUFFER_TOO_SMALL;

    pSuppliedCred = (PSECPKG_SUPPLIED_CREDENTIAL)
        ((PUCHAR)pSPCred + pSPCred->MarshaledSuppliedCreds.ByteArrayOffset);

    if (pSuppliedCred->cbHeaderLength < sizeof(*pSuppliedCred) ||
        pSuppliedCred->cbStructureLength < pSuppliedCred->cbHeaderLength)
        return SEC_E_INVALID_PARAMETER;

    if (pSuppliedCred->cbStructureLength < pSPCred->MarshaledSuppliedCreds.ByteArrayLength)
        return SEC_E_BUFFER_TOO_SMALL;

    Status = CredStringFromNegoExCredential(pSuppliedCred,
                                            &pSuppliedCred->UserName,
                                            User);
    if (Status != SEC_E_OK)
        return Status;

    Status = CredStringFromNegoExCredential(pSuppliedCred,
                                            &pSuppliedCred->DomainName,
                                            Domain);
    if (Status != SEC_E_OK)
        return Status;

    if (pSuppliedCred->PackedCredentials.ByteArrayOffset != 0) {
        if (pSuppliedCred->PackedCredentials.ByteArrayOffset +
            pSuppliedCred->PackedCredentials.ByteArrayLength <
            pSuppliedCred->cbStructureLength)
            return SEC_E_BUFFER_TOO_SMALL;

        LsaSpFunctionTable->LsaUnprotectMemory((PUCHAR)pSuppliedCred +
            pSuppliedCred->PackedCredentials.ByteArrayOffset,
            pSuppliedCred->PackedCredentials.ByteArrayLength);

        pPackedCreds = (PSEC_WINNT_AUTH_PACKED_CREDENTIALS)
            ((PUCHAR)pSuppliedCred +
                        pSuppliedCred->PackedCredentials.ByteArrayOffset);

        if (pPackedCreds->cbHeaderLength < sizeof(*pPackedCreds) ||
            pPackedCreds->cbStructureLength < pPackedCreds->cbHeaderLength)
            return SEC_E_BUFFER_TOO_SMALL;

        /* The caller can now figure out what to do with it */
        *ppPackedCredentials = pPackedCreds;
    }

    return SEC_E_OK;
}

static NTSTATUS
GsspSetCredPassword(gss_cred_id_t GssCred,
                    PVOID BasePtr,
                    PSEC_WINNT_AUTH_BYTE_VECTOR CredData)
{
    UNICODE_STRING Password;
    ULONG cbPassword;
    gss_buffer_desc GssPassword = GSS_C_EMPTY_BUFFER;
    NTSTATUS Status;
    OM_uint32 Major, Minor;

    cbPassword = CredData->ByteArrayLength;

    if (cbPassword == 0)
        return SEC_E_OK;
    else if (cbPassword > MAXUSHORT)
        return STATUS_NAME_TOO_LONG;

    Password.Length        = cbPassword;
    Password.MaximumLength = cbPassword;
    Password.Buffer        = (WCHAR *)((PUCHAR)BasePtr + CredData->ByteArrayOffset);

    Status = GsspUnicodeStringToGssBuffer(&Password, &GssPassword);
    if (Status != STATUS_SUCCESS)
        return Status;

    Major = gssEapSetCredPassword(&Minor, GssCred, &GssPassword);
    Status = GsspMapStatus(Major, Minor);

    GsspSecureZeroAndReleaseGssBuffer(&GssPassword);

    return Status;
}

static NTSTATUS
GsspSetCredCertificate(gss_cred_id_t GssCred,
                       PVOID BasePtr,
                       PSEC_WINNT_AUTH_BYTE_VECTOR CredData)
{
    gss_buffer_desc GssCertBlob = GSS_C_EMPTY_BUFFER;
    PSEC_WINNT_AUTH_CERTIFICATE_DATA CertData;
    NTSTATUS Status;
    OM_uint32 Major, Minor;

    CertData = (PSEC_WINNT_AUTH_CERTIFICATE_DATA)
               ((PBYTE)BasePtr + CredData->ByteArrayOffset);

    if (CertData->cbHeaderLength < sizeof(*CertData) ||
        CertData->cbStructureLength < CertData->cbHeaderLength)
        return SEC_E_INVALID_PARAMETER;

    if (CertData->Certificate.ByteArrayOffset +
        CertData->Certificate.ByteArrayLength >
        CredData->ByteArrayLength)
        return SEC_E_BUFFER_TOO_SMALL;

    GssCertBlob.value = (PBYTE)CertData + CertData->Certificate.ByteArrayOffset;
    GssCertBlob.length = CertData->Certificate.ByteArrayLength;

    Major = gssEapSetCredClientCertificate(&Minor, GssCred,
                                           &GssCertBlob, GSS_C_NO_BUFFER);
    Status = GsspMapStatus(Major, Minor);

    GssCred->flags |= CRED_FLAG_CONFIG_BLOB; /* is binary data */

    return Status;
}

static NTSTATUS
GsspSetCredCspData(gss_cred_id_t GssCred,
                   PVOID BasePtr,
                   PSEC_WINNT_AUTH_BYTE_VECTOR CredData)
{
    return SEC_E_UNKNOWN_CREDENTIALS;
}

static struct _GSS_SET_CRED_FUNCTION_TABLE {
    const GUID *CredType;
    NTSTATUS (*SetCred)(gss_cred_id, PVOID, PSEC_WINNT_AUTH_BYTE_VECTOR);
} GsspSetCredFunctionTable[] = {
    {
        &SEC_WINNT_AUTH_DATA_TYPE_PASSWORD,
        GsspSetCredPassword
    },
    {
        &SEC_WINNT_AUTH_DATA_TYPE_CERT,
        GsspSetCredCertificate
    },
    {
        &SEC_WINNT_AUTH_DATA_TYPE_CSP_DATA,
        GsspSetCredCspData
    }
};
 
NTSTATUS
GsspSetNegoExCred(gss_cred_id_t GssCred,
                  PSEC_WINNT_AUTH_PACKED_CREDENTIALS PackedCreds)
{
    PSEC_WINNT_AUTH_DATA AuthData;
    NTSTATUS Status;
    ULONG i;

    GSSP_ASSERT(GssCred != GSS_C_NO_CREDENTIAL);
    GSSP_ASSERT(PackedCreds != NULL);

    /*
     * Right now, the credential is only relevant to the initiator (although
     * I suppose we could use it to bootstrap the shared secret for RADIUS).
     * So if this is an acceptor context, let's just get on with things.
     */
    if ((GssCred->flags & CRED_FLAG_INITIATE) == 0)
        return SEC_E_OK;

    AuthData = &PackedCreds->AuthData;

    if (AuthData->CredData.ByteArrayOffset +
        AuthData->CredData.ByteArrayLength >
        PackedCreds->cbStructureLength)
        return SEC_E_BUFFER_TOO_SMALL;

    /*
     * Choose a SetCred function that matches the supplied credential type.
     */
    Status = SEC_E_UNKNOWN_CREDENTIALS;

    for (i = 0; i < sizeof(GsspSetCredFunctionTable) /
                    sizeof(GsspSetCredFunctionTable[0]); i++) {
        struct _GSS_SET_CRED_FUNCTION_TABLE *scFn;

        scFn = &GsspSetCredFunctionTable[i];

        if (IsEqualGUID(&AuthData->CredType, scFn->CredType)) {
            Status = scFn->SetCred(GssCred, PackedCreds, &AuthData->CredData);
            break;
        }
    }

    return Status;
}

NTSTATUS
GsspQueryContextCredInfo(gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_CredInfo CredInfo = (PSecPkgContext_CredInfo)Buffer;

    RtlZeroMemory(CredInfo, sizeof(*CredInfo));

    /*
     * According to the NegoEx whitepaper, this returns STATUS_SUCCESS
     * if a credentials prompt is needed, otherwise STATUS_NOT_FOUND.
     */

    CredInfo->CredClass = SecPkgCredClass_PersistedSpecific;
    CredInfo->IsPromptingNeeded = 0;

    if (!GsspIsCredResolved(GssContext->cred)) {
        CredInfo->IsPromptingNeeded = 1;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
CopyCredUIContextToClient(
    PSEC_WINNT_CREDUI_CONTEXT_VECTOR CredUIContext,
    PULONG FlatCredUIContextLength,
    PUCHAR* FlatCredUIContext)
{
}

/*
 * We can in theory use this to preset a list of server certificates for
 * leap of faith authentication.
 */
static NTSTATUS
GsspMakeCredUIContext(
    gss_ctx_id_t GssContext,
    PSEC_WINNT_CREDUI_CONTEXT_VECTOR *ppCredUIContext)
{
    NTSTATUS Status;

    GsspContextAddRefAndLock(GssContext);

    Status = SEC_E_UNSUPPORTED_FUNCTION;

    GsspContextUnlockAndRelease(GssContext);

    return Status;
}

NTSTATUS NTAPI
SpGetCredUIContext(
   __in LSA_SEC_HANDLE ContextHandle,
   __in GUID* CredType,
   __out PULONG FlatCredUIContextLength,
   __deref_out_bcount(*FlatCredUIContextLength)  PUCHAR* FlatCredUIContext)
{
    NTSTATUS Status;

    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpGetCredUIContext unsupported");

    Status = SEC_E_UNSUPPORTED_FUNCTION;

    return Status;
}

NTSTATUS NTAPI
SpUpdateCredentials(
  __in LSA_SEC_HANDLE ContextHandle,
  __in GUID* CredType,
  __in ULONG FlatCredUIContextLength,
  __in_bcount(FlatCredUIContextLength) PUCHAR FlatCredUIContext)
{
    GsspDebugTrace(WINEVENT_LEVEL_INFO, L"SpUpdateCredentials unsupported");

    return SEC_E_UNSUPPORTED_FUNCTION;
}

