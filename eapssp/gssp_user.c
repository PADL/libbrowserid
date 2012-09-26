/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * User-mode helpers
 */

#include "gssp.h"

static PSECPKG_DLL_FUNCTIONS SpDllFunctions;

static LIST_ENTRY GsspUserContexts;
static CRITICAL_SECTION GsspUserContextsLock;

/*
 * Add a reference to a user context.
 */
static void
GsspUserContextAddRef(gss_ctx_id_t GssContext)
{
    if (GssContext == NULL)
        return;

    InterlockedIncrement(&GssContext->RefCount);
}

/*
 * Remove a reference to a user context; identical to gssEapReleaseContext().
 */
static void
GsspUserContextRelease(gss_ctx_id_t GssContext)
{
    OM_uint32 Minor;
    gssEapReleaseContext(&Minor, &GssContext);
}

/*
 * Unlock context and release.
 */
static void
GsspUserContextUnlockAndRelease(gss_ctx_id_t GssContext)
{
    GsspContextUnlock(GssContext);
    GsspUserContextRelease(GssContext);
}

/*
 * Remove context from user context list.
 */
static void
GsspUserContextPop(gss_ctx_id_t GssContext)
{
    EnterCriticalSection(&GsspUserContextsLock);
    RemoveEntryList(&GssContext->ListEntry);
    GsspUserContextRelease(GssContext);
    LeaveCriticalSection(&GsspUserContextsLock);
}

/*
 * Add context to user context list.
 */
static void
GsspUserContextPush(gss_ctx_id_t GssContext)
{
    EnterCriticalSection(&GsspUserContextsLock);
    GsspUserContextAddRef(GssContext);
    InsertHeadList(&GsspUserContexts, &GssContext->ListEntry);
    LeaveCriticalSection(&GsspUserContextsLock);
}

/*
 * Locate a user context; caller must release.
 */
static NTSTATUS
GsspUserContextLocate(
    LSA_SEC_HANDLE LsaHandle,
    gss_ctx_id_t *pGssContext)
{
    PLIST_ENTRY pListEntry;

    *pGssContext = GSS_C_NO_CONTEXT;

    if (LsaHandle == (LSA_SEC_HANDLE)-1)
        return SEC_E_INVALID_HANDLE;

    EnterCriticalSection(&GsspUserContextsLock);

    for (pListEntry = GsspUserContexts.Flink;
        pListEntry != &GsspUserContexts;
        pListEntry = pListEntry->Flink) {
        gss_ctx_id_t GssContext =
            CONTAINING_RECORD(pListEntry,
                              struct gss_ctx_id_t_desc_struct, ListEntry);

        if (GssContext->LsaHandle == LsaHandle) {
            GsspUserContextAddRef(GssContext);
            *pGssContext = GssContext;
            break;
        }
    }

    LeaveCriticalSection(&GsspUserContextsLock);

    if (*pGssContext == NULL) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspUserContextLocate: invalid handle %p", LsaHandle);
        return SEC_E_INVALID_HANDLE;
    }

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspUserContextLocate: found context %p for handle %p list ref count %d",
                   *pGssContext, LsaHandle, (*pGssContext)->RefCount - 1);

    return SEC_E_OK;
}

static NTSTATUS
GsspUserContextLocateAndLock(
    LSA_SEC_HANDLE LsaHandle,
    gss_ctx_id_t *pGssContext)
{
    NTSTATUS Status = GsspUserContextLocate(LsaHandle, pGssContext);

    if (Status == SEC_E_OK)
        GsspContextLock(*pGssContext);

    return Status;
}

static SECPKG_USER_FUNCTION_TABLE EapUserFunctions[] = {
{
    SpInstanceInit,
    SpInitUserModeContext,
    SpMakeSignature,
    SpVerifySignature,
    SpSealMessage,
    SpUnsealMessage,
    SpGetContextToken,
    SpQueryUserModeContextAttributes,
    SpCompleteAuthToken,
    SpDeleteUserModeContext,
    SpFormatCredentials,
    SpMarshallSupplementalCreds,
    SpExportSecurityContext,
    SpImportSecurityContext
},
{
    SpInstanceInit,
    SpInitUserModeContext,
    SpMakeSignature,
    SpVerifySignature,
    SpSealMessage,
    SpUnsealMessage,
    SpGetContextToken,
    SpQueryUserModeContextAttributes,
    SpCompleteAuthToken,
    SpDeleteUserModeContext,
    SpFormatCredentials,
    SpMarshallSupplementalCreds,
    SpExportSecurityContext,
    SpImportSecurityContext
}
};

NTSTATUS SEC_ENTRY
SpUserModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_USER_FUNCTION_TABLE *ppTables,
    OUT PULONG pcTables)
{
#if 0
    static HMODULE hAdvApi32 = NULL; /* leaks */
#endif

    *PackageVersion = 0;
    *ppTables = NULL;
    *pcTables = 0;

    if (LsaVersion != SECPKG_INTERFACE_VERSION)
        return SEC_E_INVALID_PARAMETER;

    InitializeCriticalSection(&GsspUserContextsLock);
    InitializeListHead(&GsspUserContexts);

#if 0
    hAdvApi32 = LoadLibrary(L"Advapi32.dll");
    if (hAdvApi32 != NULL) {
        /* Event API for tracing */
        GsspInitEvent(hAdvApi32);
    }
#endif

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = EapUserFunctions;
    *pcTables = sizeof(EapUserFunctions) / sizeof(EapUserFunctions[0]);

    return SEC_E_OK;
}

NTSTATUS NTAPI
SpInstanceInit(
    IN ULONG Version,
    IN PSECPKG_DLL_FUNCTIONS FunctionTable,
    OUT PVOID *UserFunctions)
{
    *UserFunctions = NULL;

    if (Version != SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION)
        return SEC_E_INVALID_PARAMETER;

    SpDllFunctions = FunctionTable;
    GsspFlags = GsspGetRegFlags();

    /* Is UserFunctions actually supposed to be set? */
    *UserFunctions = EapUserFunctions;

    GsspSetAllocFree(SpDllFunctions->AllocateHeap, SpDllFunctions->FreeHeap);

    return SEC_E_OK;
}

static NTSTATUS
UnpackGssContext(
    LSA_SEC_HANDLE ContextHandle,
    PSecBuffer PackedContext,
    HANDLE TokenHandle,
    gss_ctx_id_t *pGssContext)
{
    OM_uint32 Major, Minor;
    gss_ctx_id_t GssContext = GSS_C_NO_CONTEXT;
    gss_buffer_desc ExportedContext;

    *pGssContext = GSS_C_NO_CONTEXT;

    if (PackedContext == NULL || PackedContext->cbBuffer == 0)
        return SEC_E_INVALID_TOKEN;

    Major = gssEapAllocContext(&Minor, &GssContext);
    if (GSS_ERROR(Major))
        return GsspMapStatus(Major, Minor);

    ExportedContext.length = PackedContext->cbBuffer;
    ExportedContext.value = PackedContext->pvBuffer;

    Major = gssEapImportContext(&Minor, &ExportedContext, GssContext);
    if (GSS_ERROR(Major)) {
        GsspUserContextRelease(GssContext);
        return GsspMapStatus(Major, Minor);
    }

    if (ContextHandle != (LSA_SEC_HANDLE)-1)
        GssContext->LsaHandle = ContextHandle;
    if (TokenHandle != NULL)
        GssContext->TokenHandle = TokenHandle;

    *pGssContext = GssContext;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"UnpackGssContext: unpacked context %p for handle %p [%08x.%08x]",
                   GssContext, GssContext->LsaHandle,
                   GssContext->LogonId.LowPart, GssContext->LogonId.HighPart);

    return SEC_E_OK;
}

NTSTATUS NTAPI
SpInitUserModeContext(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBuffer PackedContext)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext = GSS_C_NO_CONTEXT;

    Status = UnpackGssContext(ContextHandle, PackedContext, NULL, &GssContext);
    if (Status == SEC_E_OK)
        GsspUserContextPush(GssContext); /* adds reference */

    GsspUserContextRelease(GssContext);

    return Status;
}

static NTSTATUS
GsspWrapOrGetMIC(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG QualityOfProtection,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    IN BOOLEAN bWrap)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    int ConfReqFlag = ((QualityOfProtection & SECQOP_WRAP_NO_ENCRYPT) == 0);
    int ConfState;
    gss_iov_buffer_t Iov = GSS_C_NO_IOV_BUFFER;
    gss_ctx_id_t GssContext;
    enum gss_eap_token_type TokType = bWrap ? TOK_TYPE_WRAP : TOK_TYPE_MIC;

    QualityOfProtection &= ~(SECQOP_WRAP_NO_ENCRYPT | SECQOP_WRAP_OOB_DATA);

    if (QualityOfProtection != GSS_C_QOP_DEFAULT)
        return SEC_E_QOP_NOT_SUPPORTED;

    Status = GsspSecBuffersToIov(MessageBuffers, &Iov, TRUE);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspUserContextLocateAndLock(ContextHandle, &GssContext);
    GSSP_BAIL_ON_ERROR(Status);

    if (MessageSequenceNumber)
        GssContext->sendSeq = MessageSequenceNumber;

    Major = gssEapWrapOrGetMIC(&Minor, GssContext,
                               ConfReqFlag, &ConfState,
                               Iov, MessageBuffers->cBuffers, TokType);

    GsspUserContextUnlockAndRelease(GssContext);

    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspIovToSecBuffers(Iov, MessageBuffers, TRUE);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    gssEapReleaseIov(Iov, MessageBuffers->cBuffers);
    GsspFree(Iov);

    return Status;
}

static NTSTATUS
GsspUnwrapOrVerifyMIC(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    OUT PULONG QualityOfProtection,
    IN BOOLEAN bWrap)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    int ConfState = 0;
    gss_qop_t QopState = GSS_C_QOP_DEFAULT;
    gss_iov_buffer_t Iov = GSS_C_NO_IOV_BUFFER;
    gss_ctx_id_t GssContext;
    enum gss_eap_token_type TokType = bWrap ? TOK_TYPE_WRAP : TOK_TYPE_MIC;

    Status = GsspSecBuffersToIov(MessageBuffers, &Iov, FALSE);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspUserContextLocateAndLock(ContextHandle, &GssContext);
    GSSP_BAIL_ON_ERROR(Status);

    if (MessageSequenceNumber)
        GssContext->sendSeq = MessageSequenceNumber;

    Major = gssEapUnwrapOrVerifyMIC(&Minor, GssContext,
                                    &ConfState, &QopState,
                                    Iov, MessageBuffers->cBuffers, TokType);

    GsspUserContextUnlockAndRelease(GssContext);

    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspIovToSecBuffers(Iov, MessageBuffers, FALSE);
    GSSP_BAIL_ON_ERROR(Status);

    if (QualityOfProtection != NULL) {
        *QualityOfProtection = QopState;
        if (ConfState == 0)
            *QualityOfProtection |= SECQOP_WRAP_NO_ENCRYPT;
    }

cleanup:
    gssEapReleaseIov(Iov, MessageBuffers->cBuffers);
    GsspFree(Iov);

    return Status;
}

NTSTATUS NTAPI
SpMakeSignature(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG QualityOfProtection,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber)
{
    return GsspWrapOrGetMIC(ContextHandle,
                            QualityOfProtection,
                            MessageBuffers,
                            MessageSequenceNumber,
                            FALSE);
}

NTSTATUS NTAPI
SpVerifySignature(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    OUT PULONG QualityOfProtection)
{
    return GsspUnwrapOrVerifyMIC(ContextHandle,
                                 MessageBuffers,
                                 MessageSequenceNumber,
                                 QualityOfProtection,
                                 FALSE);
}

NTSTATUS NTAPI
SpSealMessage(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG QualityOfProtection,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber)
{
    return GsspWrapOrGetMIC(ContextHandle,
                            QualityOfProtection,
                            MessageBuffers,
                            MessageSequenceNumber,
                            TRUE);
}

NTSTATUS NTAPI
SpUnsealMessage(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    OUT PULONG QualityOfProtection)
{
    return GsspUnwrapOrVerifyMIC(ContextHandle,
                                 MessageBuffers,
                                 MessageSequenceNumber,
                                 QualityOfProtection,
                                 TRUE);
}

NTSTATUS NTAPI
SpGetContextToken(
    IN LSA_SEC_HANDLE ContextHandle,
    OUT PHANDLE ImpersonationToken)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext;

    Status = GsspUserContextLocateAndLock(ContextHandle, &GssContext);
    if (Status != SEC_E_OK)
        return Status;

    *ImpersonationToken = GssContext->TokenHandle;

    GsspUserContextUnlockAndRelease(GssContext);

    return (*ImpersonationToken == NULL) ? SEC_E_INVALID_HANDLE : SEC_E_OK;
}

NTSTATUS NTAPI
SpExportSecurityContext(
    IN LSA_SEC_HANDLE phContext,
    IN ULONG fFlags,
    OUT PSecBuffer pPackedContext,
    OUT PHANDLE pToken
    )
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext;

    pPackedContext->cbBuffer = 0;
    pPackedContext->pvBuffer = NULL;
    if (pToken != NULL)
        *pToken = NULL;

    if (fFlags & SECPKG_CONTEXT_EXPORT_RESET_NEW)
        return SEC_E_INVALID_PARAMETER;

    Status = GsspUserContextLocateAndLock(phContext, &GssContext);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspPackContext(GssContext,
                             ((fFlags & SECPKG_CONTEXT_EXPORT_TO_KERNEL) != 0),
                             pPackedContext);
    GSSP_BAIL_ON_ERROR(Status);

    if (pToken != NULL && GssContext->TokenHandle != NULL) {
        if (!DuplicateToken(GssContext->TokenHandle,
                            SecurityImpersonation, pToken)) {
            Status = SEC_E_INVALID_HANDLE;
            goto cleanup;
        }
    }

    if (fFlags & SECPKG_CONTEXT_EXPORT_DELETE_OLD)
        GsspUserContextRelease(GssContext);

cleanup:
    GsspUserContextUnlockAndRelease(GssContext);

    return Status;
}

NTSTATUS NTAPI
SpImportSecurityContext(
    IN PSecBuffer pPackedContext,
    IN HANDLE Token OPTIONAL,
    OUT PLSA_SEC_HANDLE phContext
    )
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext;

    Status = UnpackGssContext((LSA_SEC_HANDLE)-1, pPackedContext, NULL, &GssContext);
    if (Status != SEC_E_OK)
        return Status;

    if (Token != NULL) {
        if (!DuplicateToken(Token, SecurityImpersonation,
                            &GssContext->TokenHandle)) {
            GsspUserContextRelease(GssContext);
            return SEC_E_INVALID_HANDLE;
        }
    }

    GsspUserContextPush(GssContext);

    *phContext = GssContext->LsaHandle;

    GsspUserContextRelease(GssContext);

    return Status;
}

NTSTATUS NTAPI
SpCompleteAuthToken(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffer)
{
    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpFormatCredentials(
    IN PSecBuffer Credentials,
    OUT PSecBuffer FormattedCredentials)
{
    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpMarshallSupplementalCreds(
    IN ULONG CredentialSize,
    IN PUCHAR Credentials,
    OUT PULONG MarshalledCredSize,
    OUT PVOID * MarshalledCreds)
{
    return SEC_E_UNSUPPORTED_FUNCTION;
}

NTSTATUS NTAPI
SpDeleteUserModeContext(
    IN LSA_SEC_HANDLE ContextHandle)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext = GSS_C_NO_CONTEXT;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"SpDeleteUserModeContext: context %p", ContextHandle);

    Status = GsspUserContextLocate(ContextHandle, &GssContext);
    if (Status != SEC_E_OK)
        return Status;

    GsspUserContextPop(GssContext);
    GsspUserContextRelease(GssContext);

    return SEC_E_OK;
}

NTSTATUS NTAPI
SpQueryUserModeContextAttributes(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG ContextAttribute,
    IN OUT PVOID Buffer)
{
    NTSTATUS Status;
    gss_ctx_id_t GssContext = GSS_C_NO_CONTEXT;

    Status = GsspUserContextLocate(ContextHandle, &GssContext);
    if (Status != SEC_E_OK)
        return Status;

    Status = GsspQueryContextAttributes(GssContext, ContextAttribute, Buffer);

    GsspUserContextRelease(GssContext);

    return Status;
}
