/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Context interfaces
 */

#include "gssp.h"

#include <eap_peer/eap_i.h>
#include <crypto/tls.h>

static VOID
GsspContextAddRef(gss_ctx_id_t GssContext)
{
    if (GssContext == GSS_C_NO_CONTEXT)
        return;

    InterlockedIncrement(&GssContext->RefCount);
}

VOID
GsspContextRelease(gss_ctx_id_t GssContext)
{
    OM_uint32 Minor;

    gssEapReleaseContext(&Minor, &GssContext);
}

VOID
GsspContextAddRefAndLock(gss_ctx_id_t GssContext)
{
    GSSP_ASSERT(GssContext != GSS_C_NO_CONTEXT);
    GsspContextAddRef(GssContext);
    GsspContextLock(GssContext);
}

VOID
GsspContextUnlockAndRelease(gss_ctx_id_t GssContext)
{
    if (GssContext != GSS_C_NO_CONTEXT) {
        GsspContextUnlock(GssContext);
        GsspContextRelease(GssContext);
    }
}

static NTSTATUS
PackGssKernelContext(
    gss_ctx_id_t GssContext,
    PSecBuffer ContextData)
{
    NTSTATUS Status;
    PGSS_KERNEL_CONTEXT KernelContext;
    ULONG cbKernelContext;
    SecPkgInfo PkgInfo;

    /* Send the RPC ID to the kernel so it can avoid a registry lookup */
    Status = GsspGetInfo(GssContext->mechanismUsed, &PkgInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    cbKernelContext = sizeof(*KernelContext) +
                      KRB_KEY_LENGTH(&GssContext->rfc3961Key) +
                      GssContext->AccountName.MaximumLength;

    KernelContext = LsaSpFunctionTable->AllocateLsaHeap(cbKernelContext);
    if (KernelContext == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    KernelContext->ContextVersion = GSS_KERNEL_CONTEXT_VERSION_1;
    KernelContext->ContextSize = cbKernelContext;
    KernelContext->Flags =
        GsspMapFlags(GssContext->gssFlags, CTX_IS_INITIATOR(GssContext));
    KernelContext->ChecksumType = GssContext->checksumType;
    KernelContext->KeyType = GssContext->encryptionType;
    KernelContext->KeyLength = KRB_KEY_LENGTH(&GssContext->rfc3961Key);
    KernelContext->KeyValue = (PUCHAR)(sizeof(*KernelContext));
    GsspMapTime(GssContext->expiryTime, &KernelContext->ExpirationTime);
    KernelContext->SendSeq = GssContext->sendSeq;
    KernelContext->RecvSeq = GssContext->recvSeq;
    KernelContext->RpcId = GsspQueryPackageRpcId(&PkgInfo);
    KernelContext->LogonId = GssContext->LogonId;
    KernelContext->AccountName = GssContext->AccountName;
    KernelContext->AccountName.Buffer =
        (PWCHAR)((ULONG_PTR)KernelContext->KeyValue + KernelContext->KeyLength);

    KernelContext->UserFlags = GssContext->UserFlags;
    if (GssContext->TokenHandle != NULL) {
        Status = LsaSpFunctionTable->DuplicateHandle(GssContext->TokenHandle,
                                                     &KernelContext->TokenHandle);
        if (Status != STATUS_SUCCESS) {
            LsaSpFunctionTable->FreeLsaHeap(KernelContext);
            return Status;
        }
    }

    KernelContext->LsaHandle = GssContext->LsaHandle;

    RtlCopyMemory((PUCHAR)KernelContext +
                    (ULONG_PTR)KernelContext->KeyValue,
                  KRB_KEY_DATA(&GssContext->rfc3961Key),
                  KRB_KEY_LENGTH(&GssContext->rfc3961Key));

    RtlCopyMemory((PUCHAR)KernelContext +
                    (ULONG_PTR)KernelContext->AccountName.Buffer,
                  GssContext->AccountName.Buffer,
                  GssContext->AccountName.Length);

    ContextData->cbBuffer = cbKernelContext;
    ContextData->pvBuffer = KernelContext;

    return STATUS_SUCCESS;
}

static NTSTATUS
PackGssUserContext(
    gss_ctx_id_t GssContext,
    PSecBuffer ContextData)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_buffer_desc ExportedContext = GSS_C_EMPTY_BUFFER;

    Major = gssEapExportSecContext(&Minor, GssContext, &ExportedContext);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    ContextData->pvBuffer =
        LsaSpFunctionTable->AllocateLsaHeap(ExportedContext.length);
    if (ContextData->pvBuffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    ContextData->BufferType = SECBUFFER_TOKEN;
    ContextData->cbBuffer = ExportedContext.length;

    RtlCopyMemory(ContextData->pvBuffer,
                  ExportedContext.value, ExportedContext.length);

    Status = STATUS_SUCCESS;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"PackGssUserContext: GssContext %p Token %p Length %d",
                   GssContext, GssContext->TokenHandle,
                   ContextData->cbBuffer);

cleanup:
    GsspReleaseBuffer(&Minor, &ExportedContext);

    return Status;
}

NTSTATUS
GsspPackContext(
    gss_ctx_id_t GssContext,
    BOOLEAN bKernelContext,
    PSecBuffer ContextData)
{
    NTSTATUS Status;

    if (ContextData != NULL) {
        if (bKernelContext)
            Status = PackGssKernelContext(GssContext, ContextData);
        else
            Status = PackGssUserContext(GssContext, ContextData);
    } else {
        Status = STATUS_SUCCESS;
    }

    return Status;
}

static NTSTATUS
GsspMakeMechlistMIC(
    gss_ctx_id_t GssContext,
    PSecBufferDesc InputBuffers,
    PSecBufferDesc OutputBuffers,
    BOOLEAN *MadeMIC)
{
    NTSTATUS Status;
    PSecBuffer Mechlist;
    PSecBuffer MechlistMIC;

    OM_uint32 Major, Minor;
    gss_iov_buffer_desc Iov[2];

    *MadeMIC = FALSE;

    Mechlist = GsspLocateSecBuffer(InputBuffers, SECBUFFER_MECHLIST);
    if (Mechlist == NULL)
        return STATUS_SUCCESS;

    MechlistMIC = GsspLocateSecBuffer(OutputBuffers,
                                      SECBUFFER_MECHLIST_SIGNATURE);
    if (MechlistMIC == NULL)
        return SEC_E_INVALID_TOKEN;

    Iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;

    Major = gssEapWrapIovLength(&Minor, GssContext, FALSE,
                                GSS_C_QOP_DEFAULT, NULL, Iov, 1);
    if (GSS_ERROR(Major))
        return GsspMapStatus(Major, Minor);

    Status = GsspLsaAlloc(Iov[0].buffer.length, &MechlistMIC->pvBuffer);
    if (Status != STATUS_SUCCESS)
        return Status;

    MechlistMIC->cbBuffer = Iov[0].buffer.length;
    GsspSecBufferToGssBuffer(MechlistMIC, &Iov[0].buffer);

    Iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    GsspSecBufferToGssBuffer(Mechlist, &Iov[1].buffer);

    Major = gssEapWrapOrGetMIC(&Minor, GssContext, 0, NULL,
                               Iov, 2, TOK_TYPE_MIC);

    Status = GsspMapStatus(Major, Minor);

    *MadeMIC = TRUE;

    return Status;
}

static NTSTATUS
GsspVerifyMechlistMIC(
    gss_ctx_id_t GssContext,
    PSecBufferDesc InputBuffers,
    BOOLEAN *FoundMechList)
{
    NTSTATUS Status;
    PSecBuffer Mechlist;
    PSecBuffer MechlistMIC;

    OM_uint32 Major, Minor;
    gss_iov_buffer_desc Iov[2];

    *FoundMechList = FALSE;

    Mechlist = GsspLocateSecBuffer(InputBuffers, SECBUFFER_MECHLIST);
    if (Mechlist == NULL)
        return STATUS_SUCCESS;

    *FoundMechList = TRUE;

    MechlistMIC = GsspLocateSecBuffer(InputBuffers,
                                      SECBUFFER_MECHLIST_SIGNATURE);
    if (MechlistMIC == NULL)
        return SEC_E_INVALID_TOKEN;

    Iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    GsspSecBufferToGssBuffer(MechlistMIC, &Iov[0].buffer);

    Iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    GsspSecBufferToGssBuffer(Mechlist, &Iov[1].buffer);

    Major = gssEapUnwrapOrVerifyMIC(&Minor, GssContext, NULL,
                                    NULL, Iov, 2, TOK_TYPE_MIC);

    Status = GsspMapStatus(Major, Minor);

    return Status;
}

/*
 * Generate a mechlistMIC.
 */
static NTSTATUS
GsspAcceptorNegoIncomplete(
    gss_ctx_id_t GssContext,
    PSecBufferDesc InputBuffers,
    PSecBufferDesc OutputBuffers)
{
    NTSTATUS Status;
    BOOLEAN MICRequired;

    GSSP_ASSERT(GssContext->state == GSSEAP_STATE_ESTABLISHED);

    Status = GsspMakeMechlistMIC(GssContext, InputBuffers,
                                 OutputBuffers, &MICRequired);
    if (Status != STATUS_SUCCESS || !MICRequired)
        return Status;

    return SEC_I_CONTINUE_NEEDED;
}

/*
 * Verify the mechlistMIC from the acceptor and generate one.
 */
static NTSTATUS
GsspInitiatorNego(
    gss_ctx_id_t GssContext,
    PSecBufferDesc InputBuffers,
    PSecBufferDesc OutputBuffers)
{
    NTSTATUS Status;
    BOOLEAN MICRequired;

    GSSP_ASSERT(GssContext->state == GSSEAP_STATE_ESTABLISHED);

    Status = GsspVerifyMechlistMIC(GssContext, InputBuffers, &MICRequired);
    if (Status != STATUS_SUCCESS || !MICRequired)
        return Status;

    Status = GsspMakeMechlistMIC(GssContext, InputBuffers,
                                 OutputBuffers, &MICRequired);

    return Status;
}

/*
 * Verify the mechlistMIC from the initiator.
 */
static NTSTATUS
GsspAcceptorNegoComplete(
    gss_ctx_id_t GssContext,
    PSecBufferDesc InputBuffers,
    PSecBufferDesc OutputBuffers)
{
    NTSTATUS Status;
    BOOLEAN MICRequired;

    GSSEAP_ASSERT(GssContext->state == GSSEAP_STATE_MECHLIST_MIC);

    Status = GsspVerifyMechlistMIC(GssContext, InputBuffers, &MICRequired);

    return Status;
}

/*
 * Unsupported flags that raise an error (unsupported flags that
 * have a corresponding ISC_RET flag should be silently ignored).
 */
static BOOLEAN
GsspValidateContextFlags(ULONG ContextAttributes)
{
    if (ContextAttributes & ISC_REQ_USE_SUPPLIED_CREDS) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspInitSecContext: unsupported flags %08x",
                       ContextAttributes);
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
GsspAllocContext(
    ULONG ContextRequirements,
    BOOLEAN IsInitiatorContext,
    gss_cred_id_t GssCred,
    gss_ctx_id_t *pGssContext)
{
    OM_uint32 Major, Minor;
    OM_uint32 ReqFlags = GsspUnmapFlags(ContextRequirements, IsInitiatorContext);
    gss_ctx_id_t GssContext = GSS_C_NO_CONTEXT;

    GSSP_ASSERT(*pGssContext == GSS_C_NO_CONTEXT);

    if (!GsspValidateContextFlags(ContextRequirements))
        return SEC_E_UNSUPPORTED_FUNCTION;

    Major = gssEapAllocContext(&Minor, &GssContext);
    if (GSS_ERROR(Major))
        return GsspMapStatus(Major, Minor);

    /* Store the client's LUID so we can validate future contexts */
    GsspValidateClient(NULL, &GssContext->LogonId);

    /* reset GSS flags based on context requirements */
    if (IsInitiatorContext) {
        GssContext->flags |= CTX_FLAG_INITIATOR;
        GssContext->gssFlags = (ReqFlags & GSSP_ISC_REQ_FLAGS_MASK);

        /* If credential requested identity only, set context flag */
        if (GssCred != GSS_C_NO_CREDENTIAL &&
            (GssCred->SspFlags & SEC_WINNT_AUTH_IDENTITY_ONLY))
            GssContext->gssFlags |= GSS_C_IDENTIFY_FLAG;
    } else {
        /* the rest of the flags should be set by the client */
        GssContext->gssFlags |= (ReqFlags & GSSP_ASC_REQ_FLAGS_MASK);
    }

    *pGssContext = GssContext;

    return STATUS_SUCCESS;
}

static SECURITY_STATUS
GsspGetSchannelStatus(gss_ctx_id_t GssContext)
{
    SECURITY_STATUS Status = SEC_E_OK;

    /*
     * If we have a native SSPI status code from SChannel, use that.
     */
    if (GssContext->initiatorCtx.eap != NULL &&
        GssContext->initiatorCtx.eap->ssl_ctx != NULL) {
        Status = tls_get_sspi_error(GssContext->initiatorCtx.eap->ssl_ctx);
    }

    return Status;
}

NTSTATUS
GsspInitSecContext(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN OPTIONAL PUNICODE_STRING TargetName,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    IN PSecBufferDesc InputBuffers,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    IN OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData,
    IN gss_OID Oid)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)ContextHandle;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;
    gss_buffer_desc InputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc OutputToken = GSS_C_EMPTY_BUFFER;
    struct gss_channel_bindings_struct GssChannelBindings;
    gss_name_t GssTargetName = GSS_C_NO_NAME;

    *NewContextHandle = (LSA_SEC_HANDLE)-1;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspInitSecContext: CredHandle %p CtxHandle %p "
                   L"Target %wZ CtxRequirements %08x InputBufferCount %d "
                   L"EncType %d",
                   CredentialHandle, ContextHandle, TargetName,
                   ContextRequirements, InputBuffers->cBuffers, ((PUCHAR)Oid->elements)[Oid->length - 1]);

    GsspGetGssTokenBuffer(InputBuffers, &InputToken);

    if (GssContext == GSS_C_NO_CONTEXT) {
        if (InputToken.length != 0) {
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspInitSecContext: non-empty input token on first call");
            return SEC_E_INVALID_TOKEN;
        }

        Status = GsspAllocContext(ContextRequirements, TRUE,
                                  GssCred, &GssContext);
        if (Status != STATUS_SUCCESS)
            return Status;
    }

    GsspContextAddRefAndLock(GssContext);

    Status = GsspGetGssChannelBindings(InputBuffers, &GssChannelBindings);
    GSSP_BAIL_ON_ERROR(Status);

    if (TargetName != NULL) {
        Major = gssEapImportNameUnicodeString(&Minor, TargetName,
                                              GSS_EAP_NT_EAP_NAME, Oid,
                                              &GssTargetName);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    Major = gssEapInitSecContext(&Minor,
                                 GssCred,
                                 GssContext,
                                 GssTargetName,
                                 Oid,
                                 GssContext->gssFlags,
                                 GSS_C_INDEFINITE,
                                 &GssChannelBindings,
                                 &InputToken,
                                 NULL,
                                 &OutputToken,
                                 NULL,
                                 NULL);
    if (Major == GSS_S_DEFECTIVE_CREDENTIAL)
        GsspRemoveCred(GssContext->cred);

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspInitSecContext: EAP ISC returned %08x.%08x Flags %08x(%08x)",
                   Major, Minor, GssContext->gssFlags, GsspMapFlags(GssContext->gssFlags, TRUE));

    if (GSS_ERROR(Major)) {
        Status = GsspGetSchannelStatus(GssContext);
        GSSP_BAIL_ON_ERROR(Status);
    }
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspCopyGssBuffer(&OutputToken,
                               GsspLocateSecBuffer(OutputBuffers, SECBUFFER_TOKEN),
                               !!(ContextRequirements & ISC_REQ_ALLOCATE_MEMORY));
    GSSP_BAIL_ON_ERROR(Status);

    *NewContextHandle = (LSA_SEC_HANDLE)GssContext;

    if (Major == GSS_S_COMPLETE) {
        Status = GsspInitiatorNego(GssContext, InputBuffers, OutputBuffers);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GsspPackContext(GssContext,
                                ((GsspGetCallAttributes() & SECPKG_CALL_KERNEL_MODE) != 0),
                                ContextData);
        GSSP_BAIL_ON_ERROR(Status);

        *MappedContext = TRUE;

        Status = STATUS_SUCCESS;

        /*
         * If the resolved credential was successfully used to authenticate,
         * cache it for future use by this process.
         */
        GsspAddCred(GssContext->cred);
    } else if (Major == GSS_S_CONTINUE_NEEDED) {
        Status = SEC_I_CONTINUE_NEEDED;
    }

    *ContextAttributes = GsspMapFlags(GssContext->gssFlags, TRUE);
    if (ContextRequirements & ISC_REQ_ALLOCATE_MEMORY)
        *ContextAttributes |= ISC_RET_ALLOCATED_MEMORY;

    GsspMapTime(GssContext->expiryTime, ExpirationTime);

cleanup:
    GsspContextUnlockAndRelease(GssContext);
    gssEapReleaseName(&Minor, &GssTargetName);
    GsspReleaseBuffer(&Minor, &OutputToken);

    return Status;
}

NTSTATUS NTAPI
SpInitLsaModeContextEapAes128(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN OPTIONAL PUNICODE_STRING TargetName,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    IN PSecBufferDesc InputBuffers,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    IN OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData)
{
    return GsspInitSecContext(CredentialHandle,
                              ContextHandle,
                              TargetName,
                              ContextRequirements,
                              TargetDataRep,
                              InputBuffers,
                              NewContextHandle,
                              OutputBuffers,
                              ContextAttributes,
                              ExpirationTime,
                              MappedContext,
                              ContextData,
                              GSS_EAP_AES128_CTS_HMAC_SHA1_96_MECHANISM);
}

NTSTATUS NTAPI
SpInitLsaModeContextEapAes256(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN OPTIONAL PUNICODE_STRING TargetName,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    IN PSecBufferDesc InputBuffers,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    IN OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData)
{
    return GsspInitSecContext(CredentialHandle,
                              ContextHandle,
                              TargetName,
                              ContextRequirements,
                              TargetDataRep,
                              InputBuffers,
                              NewContextHandle,
                              OutputBuffers,
                              ContextAttributes,
                              ExpirationTime,
                              MappedContext,
                              ContextData,
                              GSS_EAP_AES256_CTS_HMAC_SHA1_96_MECHANISM);
}

#ifdef GSSEAP_ENABLE_ACCEPTOR
NTSTATUS
GsspAcceptSecContext(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffers,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    OM_uint32 ReqFlags;
    gss_cred_id_t GssCred = (gss_cred_id_t)CredentialHandle;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)ContextHandle;
    gss_buffer_desc InputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc OutputToken = GSS_C_EMPTY_BUFFER;
    struct gss_channel_bindings_struct GssChannelBindings;

    *NewContextHandle = (LSA_SEC_HANDLE)-1;
    *MappedContext = FALSE;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspAcceptSecContext: CredHandle %p CtxHandle %p "
                   L"CtxRequirements %08x InputBufferCount %d",
                   CredentialHandle, ContextHandle,
                   ContextRequirements, InputBuffers->cBuffers);

    if (!GsspValidateContextFlags(ContextRequirements))
        return SEC_E_UNSUPPORTED_FUNCTION;

    ReqFlags = GsspUnmapFlags(ContextRequirements, FALSE);

    if (GssContext == GSS_C_NO_CONTEXT) {
        Status = GsspAllocContext(ContextRequirements, FALSE,
                                  GssCred, &GssContext);
        if (Status != STATUS_SUCCESS)
            return Status;

        GssContext->gssFlags |= (ReqFlags & GSSP_ASC_REQ_FLAGS_MASK);
    }

    GsspContextAddRefAndLock(GssContext);

    /*
     * Note: the mechlistMIC state management assumes that the underlying
     * mechanism always uses an even number of legs. If this changes, or
     * this code is someday ported to a different GSS mechanism, then you
     * will either need to remove the SPNEGO interoperability code or
     * refactor it to additionally support an odd number of legs.
     */
    if (GssContext->state == GSSEAP_STATE_MECHLIST_MIC) {
        /* This leg only had the mechlistMIC from the iniitiator. */
        Status = GsspAcceptorNegoComplete(GssContext, InputBuffers,
                                          OutputBuffers);
        GSSP_BAIL_ON_ERROR(Status);

        Major = GSS_S_COMPLETE;         /* context established */
    } else {
        Status = GsspGetGssTokenBuffer(InputBuffers, &InputToken);
        GSSP_BAIL_ON_ERROR(Status);

        Status = GsspGetGssChannelBindings(InputBuffers, &GssChannelBindings);
        GSSP_BAIL_ON_ERROR(Status);

        Major = gssEapAcceptSecContext(&Minor,
                                       GssContext,
                                       GssCred,
                                       &InputToken,
                                       &GssChannelBindings,
                                       NULL,
                                       NULL,
                                       &OutputToken,
                                       NULL,
                                       NULL,
                                       NULL);
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspAcceptSecContext: EAP ASC returned %08x.%08x Flags %08x(%08x)",
                       Major, Minor, GssContext->gssFlags, GsspMapFlags(GssContext->gssFlags, FALSE));
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);
    }

    Status = GsspCopyGssBuffer(&OutputToken,
                               GsspLocateSecBuffer(OutputBuffers, SECBUFFER_TOKEN),
                               !!(ContextRequirements & ASC_REQ_ALLOCATE_MEMORY));
    GSSP_BAIL_ON_ERROR(Status);

    *NewContextHandle = (LSA_SEC_HANDLE)GssContext;

    if (Major == GSS_S_COMPLETE) {
        if (GssContext->state == GSSEAP_STATE_MECHLIST_MIC) {
            GssContext->state = GSSEAP_STATE_ESTABLISHED;
        } else {
            Status = GsspAcceptorNegoIncomplete(GssContext, InputBuffers,
                                                OutputBuffers);
            if (Status == SEC_I_CONTINUE_NEEDED)
                GssContext->state = GSSEAP_STATE_MECHLIST_MIC;
        }
        if (Status == STATUS_SUCCESS) {
            Status = GsspPackContext(GssContext,
                                     ((GsspGetCallAttributes() & SECPKG_CALL_KERNEL_MODE) != 0),
                                     ContextData);
            GSSP_BAIL_ON_ERROR(Status);

            *MappedContext = TRUE;
        }
    } else if (Major == GSS_S_CONTINUE_NEEDED) {
        Status = SEC_I_CONTINUE_NEEDED;
    }

    *ContextAttributes = GsspMapFlags(GssContext->gssFlags, FALSE);
    if (ContextRequirements & ASC_REQ_ALLOCATE_MEMORY)
        *ContextAttributes |= ASC_RET_ALLOCATED_MEMORY;

    GsspMapTime(GssContext->expiryTime, ExpirationTime);

cleanup:
    GsspContextUnlockAndRelease(GssContext);
    GsspReleaseBuffer(&Minor, &OutputToken);

    return Status;
}
#endif /* GSSEAP_ENABLE_ACCEPTOR */

NTSTATUS NTAPI
SpAcceptLsaModeContext(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffer,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    OUT PSecBufferDesc OutputBuffer,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData)
{
#ifdef GSSEAP_ENABLE_ACCEPTOR
    return GsspAcceptSecContext(CredentialHandle,
                                ContextHandle,
                                InputBuffer,
                                ContextRequirements,
                                TargetDataRep,
                                NewContextHandle,
                                OutputBuffer,
                                ContextAttributes,
                                ExpirationTime,
                                MappedContext,
                                ContextData);
#else
    return SEC_E_UNSUPPORTED_FUNCTION;
#endif
}

NTSTATUS NTAPI
SpDeleteContext(
    IN LSA_SEC_HANDLE ContextHandle)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)ContextHandle;

    if (GssContext == GSS_C_NO_CONTEXT)
        return STATUS_INVALID_HANDLE;

    GsspContextAddRefAndLock(GssContext);

    /*
     * If the only references to the context credential are the
     * context and the global credentials list, remove it from
     * the list.
     */
    GsspMaybeRemoveCred(GssContext->cred);

    GsspContextUnlockAndRelease(GssContext);

    Major = gssEapReleaseContext(&Minor, &GssContext);
    Status = GsspMapStatus(Major, Minor);

    return Status;
}

NTSTATUS NTAPI
SpApplyControlToken(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc ControlToken)
{
    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpSetContextAttributes(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG ContextAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)ContextHandle;

    Status = GsspSetContextAttributes(GssContext,
                                      ContextAttribute,
                                      Buffer,
                                      BufferSize);

    return Status;
}

NTSTATUS NTAPI
SpQueryContextAttributes(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG ContextAttribute,
    IN OUT PVOID Buffer)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext = (gss_ctx_id_t)ContextHandle;

    Status = GsspQueryContextAttributes(GssContext,
                                        ContextAttribute,
                                        Buffer);
    return Status;
}
