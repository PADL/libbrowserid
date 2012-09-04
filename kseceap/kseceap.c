/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Kernel interface to EAP SSP
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_KERNEL
#define SECURITY_KERNEL
#endif

#include <ntifs.h>
#include <ntsecpkg.h>
#include <stdarg.h>

#include "KSecEap.h"

static PSECPKG_KERNEL_FUNCTIONS KspFunctions = NULL;

static PVOID EapPagedList;
static PVOID EapNonPagedList;
static volatile PVOID EapActiveList;
static LONG EapPoolType;

#define KSECEAP_PAGED_CODE()                \
    do {                                    \
        if (EapPoolType)                    \
            PAGED_CODE();                   \
    } while (0)

NTSTATUS
EapReferenceContext(PGSS_KERNEL_CONTEXT KernContext);

VOID
EapDereferenceContext(PGSS_KERNEL_CONTEXT KernContext);

NTSTATUS
EapCreateKernelModeContext(
    __in LSA_SEC_HANDLE ContextId,
    __in PSecBuffer ContextData,
    __in HANDLE TokenHandle,
    __out PLSA_SEC_HANDLE NewContextId);

NTSTATUS
EapQueryContextAttributes(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG Attribute,
    __inout PVOID Buffer,
    __in ULONG RpcId);

NTSTATUS
EapSetPagingMode(__in BOOLEAN PagingMode);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EapReferenceContext)
#pragma alloc_text(PAGE, EapDereferenceContext)
#pragma alloc_text(PAGE, EapCreateKernelModeContext)
#pragma alloc_text(PAGE, EapQueryContextAttributes)
#pragma alloc_text(PAGE, EapSetPagingMode)
#endif

static VOID
EapDebugPrint(PCCHAR DebugMessage, ...)
{
    va_list ap;

    va_start(ap, DebugMessage);
    vDbgPrintEx(DPFLTR_KSECDD_ID, DPFLTR_INFO_LEVEL, DebugMessage, ap);
    va_end(ap);
}

/*
 * Add a reference to a kernel context entry
 */
NTSTATUS
EapReferenceContext(PGSS_KERNEL_CONTEXT KernContext)
{
    if (KernContext == NULL)
        return STATUS_INVALID_HANDLE;

    KSECEAP_PAGED_CODE();

    /*
     * What if we are >=DISPATCH_LEVEL and the context is on the
     * paged list? Do we need to lock it into non-paged memory?
     */

    return KspFunctions->ReferenceListEntry(&KernContext->ListEntry,
                                            KSECEAP_SIGNATURE,
                                            FALSE);
}

/*
 * Release a reference to a kernel context entry
 */
VOID
EapDereferenceContext(PGSS_KERNEL_CONTEXT KernContext)
{
    BOOLEAN Delete = FALSE;

    if (KernContext == NULL)
        return;

    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapDereferenceContext: releasing context %p\n", KernContext);

    KspFunctions->DereferenceListEntry(&KernContext->ListEntry, &Delete);

    if (Delete == TRUE) {
        if (KernContext->AccessToken != NULL)
            ObDereferenceObject(KernContext->AccessToken);
        if (KernContext->TokenHandle != NULL)
            ZwClose(KernContext->TokenHandle);

        RtlSecureZeroMemory(KernContext, KernContext->ContextSize);
        ExFreePoolWithTag(KernContext, KSECEAP_TAG);

        EapDebugPrint("EapDereferenceContext: deleted context %p\n", KernContext);
    }
}

/*
 * Initialize EAP SSP
 */
NTSTATUS
EapInitKernelPackage(PSECPKG_KERNEL_FUNCTIONS FunctionTable)
{
    NTSTATUS Status;

    KSECEAP_PAGED_CODE();

    KspFunctions = FunctionTable;

    EapDebugPrint("EapInitKernelPackage: initialize EAP package\n");

    /* The non-paged list seems to be set on demand by ksecpkg.sys */
    Status = EapSetPagingMode(TRUE);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}

/*
 * Delete EAP SSP context
 */
NTSTATUS
EapDeleteKernelContext(
    __in LSA_SEC_HANDLE ContextId,
    __out PLSA_SEC_HANDLE LsaContextId)
{
    PGSS_KERNEL_CONTEXT KernContext = (PGSS_KERNEL_CONTEXT)ContextId;

    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapDeleteKernelContext: deleting context handle %p for LSA context %p\n", KernContext, KernContext->LsaHandle);

    if (LsaContextId != NULL)
        *LsaContextId = KernContext->LsaHandle;

    EapDereferenceContext(KernContext);

    return STATUS_SUCCESS;
}

/*
 * Initialize EAP SSP context with LSA context handle and serialized
 * context buffer.
 */
NTSTATUS
EapCreateKernelModeContext(
    __in LSA_SEC_HANDLE ContextId,
    __in PSecBuffer ContextData,
    __in HANDLE TokenHandle,
    __out PLSA_SEC_HANDLE NewContextId)
{
    PGSS_KERNEL_CONTEXT MappedContext;
    PGSS_KERNEL_CONTEXT KernelContext;
    ULONG_PTR KeyOffset;
    ULONG_PTR AccountNameOffset;
    NTSTATUS Status;

    *NewContextId = (LSA_SEC_HANDLE)0;

    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapCreateKernelModeContext: ContextId %p, ContextData.pvBuffer %p ContextData.cbLength %lu TokenHandle %p\n",
            ContextId, ContextData->pvBuffer, ContextData->cbBuffer, TokenHandle);

    ASSERT(ContextData != NULL);
    ASSERT(ContextData->pvBuffer != NULL);

    if (ContextData == NULL || ContextData->pvBuffer == NULL) {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    ASSERT(ContextData->cbBuffer >= sizeof(*MappedContext));

    if (ContextData->cbBuffer < sizeof(*MappedContext)) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    MappedContext = (PGSS_KERNEL_CONTEXT)ContextData->pvBuffer;

    ASSERT(MappedContext->ContextVersion == GSS_KERNEL_CONTEXT_VERSION_1);

    if (MappedContext->ContextVersion != GSS_KERNEL_CONTEXT_VERSION_1) {
        Status = STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    ASSERT(ContextData->cbBuffer == MappedContext->ContextSize);

    if (ContextData->cbBuffer != MappedContext->ContextSize) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ASSERT(EapActiveList != NULL);

    /*
     * XXX if we can remove variable length data (account name) then
     * we can use ExAllocateFromPagedLookasideList.
     */
    KernelContext = ExAllocatePoolWithTag(EapPoolType ? PagedPool : NonPagedPool,
                                          MappedContext->ContextSize,
                                          KSECEAP_TAG);
    if (KernelContext == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    RtlCopyMemory(KernelContext, MappedContext, MappedContext->ContextSize);

    KeyOffset = (ULONG_PTR)KernelContext->KeyValue;
    if (KernelContext->KeyLength != 0 && KeyOffset != 0) {
        KSECEAP_BAIL_ON_BAD_OFFSET(KernelContext->ContextSize,
                                   KeyOffset, KernelContext->KeyLength);
        KernelContext->KeyValue = (PUCHAR)KernelContext + KeyOffset;
    } else {
        KernelContext->KeyLength = 0;
        KernelContext->KeyValue = NULL;
    }

    AccountNameOffset = (ULONG_PTR)KernelContext->AccountName.Buffer;
    if (MappedContext->AccountName.Length != 0 && AccountNameOffset != 0) {
        KSECEAP_BAIL_ON_BAD_OFFSET(KernelContext->ContextSize,
                                   AccountNameOffset,
                                   KernelContext->AccountName.MaximumLength);
        KernelContext->AccountName.Buffer =
            (PWSTR)((PUCHAR)KernelContext + AccountNameOffset);

        ASSERT(KernelContext->AccountName.Length <=
               KernelContext->AccountName.MaximumLength);

        if (KernelContext->AccountName.Length >
            KernelContext->AccountName.MaximumLength) {
            Status = STATUS_INVALID_PARAMETER;
            goto cleanup;
        }
    } else {
        RtlInitUnicodeString(&KernelContext->AccountName, NULL);
    }

    if (ContextId != 0)
        KernelContext->LsaHandle = ContextId;

    KsecInitializeListEntry(&KernelContext->ListEntry, KSECEAP_SIGNATURE);

    if (TokenHandle != NULL) {
        Status = ZwDuplicateToken(TokenHandle,
                                  0,                /* DesiredAccess */
                                  NULL,             /* ObjectAttributes */
                                  FALSE,            /* EffectiveOnly */
                                  TokenImpersonation,
                                  &KernelContext->TokenHandle);
        if (!NT_SUCCESS(Status))
            goto cleanup;
    }

    KspFunctions->InsertListEntry(EapActiveList,
                                  &KernelContext->ListEntry);

    *NewContextId = (LSA_SEC_HANDLE)KernelContext;

    Status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(Status))
        ExFreePoolWithTag(KernelContext, KSECEAP_TAG);

    EapDebugPrint("EapCreateKernelModeContext: returning %08x\n", Status);

    return Status;
}

NTSTATUS
EapInitKernelContext(
    __in LSA_SEC_HANDLE ContextId,
    __in PSecBuffer ContextData,
    __out PLSA_SEC_HANDLE NewContextId)
{
    KSECEAP_PAGED_CODE();

    return EapCreateKernelModeContext(ContextId, ContextData,
                                      NULL, NewContextId);
}

/*
 * Message protection services are not implemented.
 */

NTSTATUS
EapMakeSignature(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG fQOP,
    __inout PSecBufferDesc Message,
    __in ULONG MessageSeqNo)
{
    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapMakeSignature: unsupported by EAP SSP\n");

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
EapVerifySignature(
    __in LSA_SEC_HANDLE ContextId,
    __inout PSecBufferDesc Message,
    __in ULONG MessageSeqNo,
    __out PULONG pfQOP)
{
    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapVerifySignature: unsupported by EAP SSP\n");

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
EapSealMessage(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG fQOP,
    __inout PSecBufferDesc Message,
    __in ULONG MessageSeqNo)
{
    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapSealMessage: unsupported by EAP SSP\n");

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
EapUnsealMessage(
    __in LSA_SEC_HANDLE ContextId,
    __inout PSecBufferDesc Message,
    __in ULONG MessageSeqNo,
    __out PULONG pfQOP)
{
    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapUnsealMessage: unsupported by EAP SSP\n");

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
EapGetContextToken(
    __in LSA_SEC_HANDLE ContextId,
    __out PHANDLE ImpersonationToken,
    __out PACCESS_TOKEN *RawToken)
{
    NTSTATUS Status;
    PGSS_KERNEL_CONTEXT KernelContext = (PGSS_KERNEL_CONTEXT)ContextId;

    if (ImpersonationToken != NULL)
        *ImpersonationToken = NULL;
    if (RawToken != NULL)
        *RawToken = (PACCESS_TOKEN)0;

    KSECEAP_PAGED_CODE();

    Status = EapReferenceContext(KernelContext);
    if (!NT_SUCCESS(Status))
        return Status;

    if (KernelContext->TokenHandle == NULL) {
        Status = STATUS_NO_IMPERSONATION_TOKEN;
        goto cleanup;
    }

    if (KernelContext->AccessToken == NULL) {
        PACCESS_TOKEN AccessToken;

        Status = ObReferenceObjectByHandle(KernelContext->TokenHandle,
                                           TOKEN_ALL_ACCESS,
                                           *SeTokenObjectType,
                                           ExGetPreviousMode(),
                                           &AccessToken,
                                           NULL);
        if (!NT_SUCCESS(Status))
            goto cleanup;

        InterlockedExchangePointer(&KernelContext->AccessToken, AccessToken);
    }

    EapDebugPrint("EapGetContextToken: KernelContext %p Token %p RawToken %p\n",
            KernelContext,
            KernelContext->TokenHandle, KernelContext->AccessToken);

    /*
     * Contrary to the interface specification, ImpersonationToken is
     * also an optional parameter.
     */
    if (ImpersonationToken != NULL)
        *ImpersonationToken = KernelContext->TokenHandle;

    if (RawToken != NULL)
        *RawToken = KernelContext->AccessToken;

    Status = STATUS_SUCCESS;

cleanup:
    EapDereferenceContext(KernelContext);

    return Status;
}

NTSTATUS
EapQueryContextAttributes(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG Attribute,
    __inout PVOID Buffer,
    __in ULONG RpcId)
{
    NTSTATUS Status;
    PGSS_KERNEL_CONTEXT KernelContext = (PGSS_KERNEL_CONTEXT)ContextId;

    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapQueryContextAttributes: KernelContext %p Attribute %u\n",
            ContextId, Attribute);

    Status = EapReferenceContext(KernelContext);
    if (!NT_SUCCESS(Status))
        return Status;

    switch (Attribute) {
    case SECPKG_ATTR_NAMES: {
        PSecPkgContext_Names Names = (PSecPkgContext_Names)Buffer;

        if (KernelContext->AccountName.Length == 0) {
            Status = STATUS_NO_SUCH_USER;
            goto cleanup;
        }

        Names->sUserName =
            KspFunctions->AllocateHeap(KernelContext->AccountName.Length +
                                       sizeof(WCHAR));
        if (Names->sUserName == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        RtlCopyMemory(Names->sUserName,
                      KernelContext->AccountName.Buffer,
                      KernelContext->AccountName.Length);
        Names->sUserName[KernelContext->AccountName.Length / sizeof(WCHAR)] = L'\0';
        Status = STATUS_SUCCESS;
        break;
    }
    case SECPKG_ATTR_LIFESPAN: {
        PSecPkgContext_Lifespan Lifespan = (PSecPkgContext_Lifespan)Buffer;

        Lifespan->tsStart.LowPart  = 0;
        Lifespan->tsStart.HighPart = 0;
        Lifespan->tsExpiry = KernelContext->ExpirationTime;
        Status = STATUS_SUCCESS;
        break;
    }
    case SECPKG_ATTR_PACKAGE_INFO: {
        PSecPkgContext_PackageInfo PackageInfo = (PSecPkgContext_PackageInfo)Buffer;
        ULONG cbPkgName = sizeof(EAP_AES128_PACKAGE_NAME_W);
        ULONG cbPkgComment = sizeof(EAPSSP_PACKAGE_COMMENT_W);

        PackageInfo->PackageInfo =
            KspFunctions->AllocateHeap(sizeof(SecPkgInfo) + cbPkgName + cbPkgComment);
        if (PackageInfo->PackageInfo == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        /*
         * The RPC ID is cached in the context as the LSA package may have
         * changed it to workaround application bugs.
         */
        PackageInfo->PackageInfo->fCapabilities = EAPSSP_PACKAGE_CAPABILITIES;
        PackageInfo->PackageInfo->wVersion      = EAPSSP_PACKAGE_VERSION;
        PackageInfo->PackageInfo->wRPCID        = KernelContext->RpcId;
        PackageInfo->PackageInfo->cbMaxToken    = EAPSSP_MAX_TOKEN_SIZE;
        PackageInfo->PackageInfo->Name          = (PWSTR)((PUCHAR)PackageInfo->PackageInfo + sizeof(SecPkgInfo));

        RtlCopyMemory(PackageInfo->PackageInfo->Name,
                      (RpcId == EAP_AES256_RPCID)
                        ? EAP_AES256_PACKAGE_NAME_W
                        : EAP_AES128_PACKAGE_NAME_W,
                      cbPkgName);
        PackageInfo->PackageInfo->Comment       = (PWSTR)((PUCHAR)PackageInfo->PackageInfo + sizeof(SecPkgInfo) + cbPkgName);
        RtlCopyMemory(PackageInfo->PackageInfo->Comment,
                      EAPSSP_PACKAGE_COMMENT_W, cbPkgComment);

        Status = STATUS_SUCCESS;
        break;
    }
    case SECPKG_ATTR_SESSION_KEY: {
        PSecPkgContext_SessionKey SessionKey =
            (PSecPkgContext_SessionKey)Buffer;

        if (KernelContext->KeyLength == 0) {
            Status = STATUS_NO_USER_SESSION_KEY;
            goto cleanup;
        }

        SessionKey->SessionKey = KspFunctions->AllocateHeap(KernelContext->KeyLength);
        if (SessionKey->SessionKey == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        RtlCopyMemory(SessionKey->SessionKey,
                      KernelContext->KeyValue, KernelContext->KeyLength);
        SessionKey->SessionKeyLength = KernelContext->KeyLength;
        Status = STATUS_SUCCESS;
        break;
    }
    case SECPKG_ATTR_USER_FLAGS: {
        PSecPkgContext_UserFlags UserFlags = (PSecPkgContext_UserFlags)Buffer;
        UserFlags->UserFlags = KernelContext->UserFlags;
        Status = STATUS_SUCCESS;
        break;
    }
    case SECPKG_ATTR_FLAGS: {
        PSecPkgContext_Flags Flags = (PSecPkgContext_Flags)Buffer;

        Flags->Flags = KernelContext->Flags;
        Status = STATUS_SUCCESS;
        break;
    }
    default:
        Status = STATUS_NOT_SUPPORTED;
        break;
    }

cleanup:
    EapDereferenceContext(KernelContext);

    EapDebugPrint("EapQueryContextAttributes: returning %08x\n", Status);

    return Status;
}

NTSTATUS
EapAes128QueryContextAttributes(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG Attribute,
    __inout PVOID Buffer)
{
    KSECEAP_PAGED_CODE();

    return EapQueryContextAttributes(ContextId, Attribute, Buffer,
                                     EAP_AES128_RPCID);
}

NTSTATUS
EapAes256QueryContextAttributes(
    __in LSA_SEC_HANDLE ContextId,
    __in ULONG Attribute,
    __inout PVOID Buffer)
{
    KSECEAP_PAGED_CODE();

    return EapQueryContextAttributes(ContextId, Attribute, Buffer,
                                     EAP_AES256_RPCID);
}

NTSTATUS
EapCompleteToken(
    __in LSA_SEC_HANDLE ContextId,
    __in PSecBufferDesc Token)
{
    EapDebugPrint("EapCompleteToken: unsupported by EAP SSP\n");

    KSECEAP_PAGED_CODE();

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
EapMapKernelHandle(
    __in LSA_SEC_HANDLE ContextId,
    __out PLSA_SEC_HANDLE LsaContextId)
{
    PGSS_KERNEL_CONTEXT KernelContext = (PGSS_KERNEL_CONTEXT)ContextId;
    NTSTATUS Status;

    KSECEAP_PAGED_CODE();

    Status = EapReferenceContext(KernelContext);
    if (!NT_SUCCESS(Status))
        return Status;

    EapDebugPrint("EapMapKernelHandle: KernelContext %p LsaHandle %p\n",
            KernelContext, KernelContext->LsaHandle);

    *LsaContextId = KernelContext->LsaHandle;

    EapDereferenceContext(KernelContext);

    return STATUS_SUCCESS;
}

NTSTATUS
EapExportSecurityContext(
    __in LSA_SEC_HANDLE phContext,
    __in ULONG fFlags,
    __out PSecBuffer pPackedContext,
    __out PHANDLE pToken)
{
    NTSTATUS Status;
    PGSS_KERNEL_CONTEXT SrcKernelContext = (PGSS_KERNEL_CONTEXT)phContext;
    PGSS_KERNEL_CONTEXT DstKernelContext = NULL;

    pPackedContext->cbBuffer = 0;
    pPackedContext->pvBuffer = NULL;

    *pToken = (HANDLE)0;

    KSECEAP_PAGED_CODE();

    EapDebugPrint("EapExportSecurityContext: KernelContext %p Flags %08x\n",
            SrcKernelContext, fFlags);

    if ((fFlags & SECPKG_CONTEXT_EXPORT_RESET_NEW) ||
        (fFlags & SECPKG_CONTEXT_EXPORT_TO_KERNEL) == 0)
        return STATUS_INVALID_PARAMETER;

    Status = EapReferenceContext(SrcKernelContext);
    if (!NT_SUCCESS(Status))
        goto cleanup;

    DstKernelContext = KspFunctions->AllocateHeap(SrcKernelContext->ContextSize);
    if (DstKernelContext == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    RtlCopyMemory(DstKernelContext, SrcKernelContext,
                  SrcKernelContext->ContextSize);
    if (SrcKernelContext->KeyValue != NULL) {
        DstKernelContext->KeyValue = (PUCHAR)(sizeof(*DstKernelContext));
        RtlCopyMemory((PUCHAR)DstKernelContext + (ULONG_PTR)DstKernelContext->KeyValue,
                      SrcKernelContext->KeyValue,
                      SrcKernelContext->KeyLength);
    }
    if (SrcKernelContext->AccountName.Buffer != NULL) {
        DstKernelContext->AccountName.Buffer =
            (PWCHAR)((ULONG_PTR)DstKernelContext->KeyValue +
                    DstKernelContext->KeyLength);
        RtlCopyMemory((PUCHAR)DstKernelContext +
                        (ULONG_PTR)DstKernelContext->AccountName.Buffer,
                      SrcKernelContext->AccountName.Buffer,
                      SrcKernelContext->AccountName.Length);
    }

    DstKernelContext->TokenHandle = NULL;

    if (SrcKernelContext->TokenHandle != NULL) {
        Status = ZwDuplicateToken(SrcKernelContext->TokenHandle,
                                  0,                /* DesiredAccess */
                                  NULL,             /* ObjectAttributes */
                                  FALSE,            /* EffectiveOnly */
                                  TokenImpersonation,
                                  pToken);
        if (!NT_SUCCESS(Status))
            goto cleanup;
    }

    pPackedContext->cbBuffer = DstKernelContext->ContextSize;
    pPackedContext->pvBuffer = DstKernelContext;

    if (fFlags & SECPKG_CONTEXT_EXPORT_DELETE_OLD)
        EapDeleteKernelContext(phContext, NULL);

    Status = STATUS_SUCCESS;

cleanup:
    EapDereferenceContext(SrcKernelContext);

    if (!NT_SUCCESS(Status) && DstKernelContext != NULL)
        KspFunctions->FreeHeap(DstKernelContext);

    EapDebugPrint("EapExportSecurityContext: returning %08x\n", Status);

    return Status;
}

NTSTATUS
EapImportSecurityContext(
    __in PSecBuffer pPackedContext,
    __in HANDLE Token,
    __out PLSA_SEC_HANDLE phContext)
{
    KSECEAP_PAGED_CODE();

    return EapCreateKernelModeContext(0, pPackedContext, Token, phContext);
}

NTSTATUS
EapSetPagingMode(__in BOOLEAN PagingMode)
{
    PVOID *pList;

    KSECEAP_PAGED_CODE();

    if (PagingMode == FALSE) {
        pList = &EapNonPagedList;
    } else {
        pList = &EapPagedList;
    }

    if (*pList == NULL) {
        *pList = KspFunctions->CreateContextList(KSecPaged);
        if (*pList == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    InterlockedExchangePointer(&EapActiveList, *pList);
    InterlockedExchange(&EapPoolType, (LONG)PagingMode);

    return STATUS_SUCCESS;
}

NTSTATUS
EapSerializeAuthData(
    __in PVOID pvAuthData,
    __out ULONG *pulSize,
    __out PVOID *pvSerializedData)
{
    KSECEAP_PAGED_CODE();

    return KspFunctions->SerializeWinntAuthData(pvAuthData,
                                                pulSize, pvSerializedData);
}

SECPKG_KERNEL_FUNCTION_TABLE
EapAes128FunctionTable = {
    EapInitKernelPackage,
    EapDeleteKernelContext,
    EapInitKernelContext,
    EapMapKernelHandle,
    EapMakeSignature,
    EapVerifySignature,
    EapSealMessage,
    EapUnsealMessage,
    EapGetContextToken,
    EapAes128QueryContextAttributes,
    EapCompleteToken,
    EapExportSecurityContext,
    EapImportSecurityContext,
    EapSetPagingMode,
    EapSerializeAuthData
};

SECPKG_KERNEL_FUNCTION_TABLE
EapAes256FunctionTable = {
    EapInitKernelPackage,
    EapDeleteKernelContext,
    EapInitKernelContext,
    EapMapKernelHandle,
    EapMakeSignature,
    EapVerifySignature,
    EapSealMessage,
    EapUnsealMessage,
    EapGetContextToken,
    EapAes256QueryContextAttributes,
    EapCompleteToken,
    EapExportSecurityContext,
    EapImportSecurityContext,
    EapSetPagingMode,
    EapSerializeAuthData
};

static UNICODE_STRING
EapAes128Name = RTL_CONSTANT_STRING(EAP_AES128_PACKAGE_NAME_W);
static UNICODE_STRING
EapAes256Name = RTL_CONSTANT_STRING(EAP_AES256_PACKAGE_NAME_W);

NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    Status = KSecRegisterSecurityProvider(&EapAes256Name,
                                          &EapAes256FunctionTable);
    if (NT_SUCCESS(Status)) {
        Status = KSecRegisterSecurityProvider(&EapAes128Name,
                                              &EapAes128FunctionTable);
    }

    /*
     * XXX If we allow the driver to be unloaded, existing contexts
     * will cause the host to BSOD.
     */
#if 0
    DriverObject->DriverUnload = DriverUnload;
#endif

    return Status;
}
