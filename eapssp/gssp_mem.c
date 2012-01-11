/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Memory allocation routines 
 */

#include "gssp.h"

static PLSA_ALLOCATE_LSA_HEAP pfnAllocate;
static PLSA_FREE_LSA_HEAP pfnFree;

void *
GsspAllocPtr(size_t Length)
{
    PVOID Ptr;

    GSSP_ASSERT(Length <= 0xFFFFFFFF);

    if (pfnAllocate == NULL)
        Ptr = HeapAlloc(GetProcessHeap(), 0, Length);   
    else if (LsaSpFunctionTable != NULL)
        Ptr = LsaSpFunctionTable->AllocatePrivateHeap(Length);
    else
        Ptr = pfnAllocate(Length);

    return Ptr;
}

void *
GsspCallocPtr(size_t Nelems, size_t Length)
{
    PVOID Ptr;

    Ptr = GsspAllocPtr(Length * Nelems);
    if (Ptr == NULL)
        return NULL;

    RtlZeroMemory(Ptr, Length * Nelems);

    return Ptr;
}

void
GsspFreePtr(void * Ptr)
{
    if (Ptr == NULL)
        return;

    if (pfnFree == NULL)
        HeapFree(GetProcessHeap(), 0, Ptr);
    else if (LsaSpFunctionTable != NULL)
        LsaSpFunctionTable->FreePrivateHeap(Ptr);
    else
        pfnFree(Ptr);
}

void *
GsspReallocPtr(void *Ptr, size_t Size)
{
    GSSEAP_ASSERT(0 && "GsspReallocPtr not implemented!");
    return NULL;
}

VOID
GsspSetAllocFree(
    PLSA_ALLOCATE_LSA_HEAP Alloc,
    PLSA_FREE_LSA_HEAP Free)
{
    pfnAllocate = Alloc;
    pfnFree = Free;
}

NTSTATUS
GsspAlloc(SIZE_T Length, PVOID *pPtr)
{
    *pPtr = GsspAllocPtr(Length);

    return (*pPtr == NULL) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}

NTSTATUS
GsspCalloc(SIZE_T Length, SIZE_T Nelems, PVOID *pPtr)
{
    NTSTATUS Status = GsspAlloc(Length * Nelems, pPtr);

    if (Status == STATUS_SUCCESS)
        RtlZeroMemory(*pPtr, Length * Nelems);

    return Status;
}

VOID
GsspFree(PVOID Ptr)
{
    GsspFreePtr(Ptr);
}

static __inline BOOLEAN
GsspUsePrivateHeap(void)
{
    return GsspIsNegoExCall();
}

NTSTATUS
GsspLsaAlloc(SIZE_T Length, PVOID *pPtr)
{
    if (LsaSpFunctionTable != NULL && !GsspUsePrivateHeap())
        *pPtr = LsaSpFunctionTable->AllocateLsaHeap(Length);
    else
        *pPtr = GsspAllocPtr(Length);

    return (*pPtr == NULL) ? STATUS_INSUFFICIENT_RESOURCES : STATUS_SUCCESS;
}

NTSTATUS
GsspLsaCalloc(SIZE_T Length, SIZE_T Nelems, PVOID *pPtr)
{
    NTSTATUS Status = GsspLsaAlloc(Length * Nelems, pPtr);

    if (Status == STATUS_SUCCESS)
        RtlZeroMemory(*pPtr, Length * Nelems);

    return Status;
}

VOID
GsspLsaFree(PVOID Ptr)
{
    if (LsaSpFunctionTable != NULL && !GsspUsePrivateHeap())
        LsaSpFunctionTable->FreeLsaHeap(Ptr);
    else
        GsspFreePtr(Ptr);
}

NTSTATUS
GsspDuplicateString(
    PWSTR Src,
    BOOLEAN bLsaAlloc,
    PWSTR *pDst)
{
    NTSTATUS Status;
    ULONG cbSrc;
    PWSTR Dst;

    *pDst = NULL;

    if (Src == NULL)
        return STATUS_SUCCESS;

    cbSrc = wcslen(Src) * sizeof(WCHAR);

    if (bLsaAlloc)
        Status = GsspLsaAlloc(cbSrc + sizeof(WCHAR), &Dst);
    else
        Status = GsspAlloc(cbSrc + sizeof(WCHAR), &Dst);
    if (Status != STATUS_SUCCESS)
        return Status;

    RtlCopyMemory(Dst, Src, cbSrc);
    Dst[cbSrc / sizeof(WCHAR)] = L'\0';

    *pDst = Dst;

    return STATUS_SUCCESS;
}

NTSTATUS
GsspDuplicateUnicodeString(
    PUNICODE_STRING Src,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING Dst)
{
    NTSTATUS Status;

    RtlInitUnicodeString(Dst, NULL);

    if (Src == NULL)
        return STATUS_SUCCESS;

    if (bLsaAlloc)
        Status = GsspLsaAlloc(Src->Length + sizeof(WCHAR), &Dst->Buffer);
    else
        Status = GsspAlloc(Src->Length + sizeof(WCHAR), &Dst->Buffer);
    if (Status != STATUS_SUCCESS)
        return Status;

    Dst->Length        = Src->Length;
    Dst->MaximumLength = Src->Length + sizeof(WCHAR);

    RtlCopyMemory(Dst->Buffer, Src->Buffer, Src->Length);
    Dst->Buffer[Dst->Length / sizeof(WCHAR)] = L'\0';

    return STATUS_SUCCESS;
}

VOID
GsspSecureZeroAndReleaseGssBuffer(gss_buffer_t buffer)
{
    if (buffer != GSS_C_NO_BUFFER) {
        if (buffer->value != NULL) {
            RtlSecureZeroMemory(buffer->value, buffer->length);
            GsspFreePtr(buffer->value);
            buffer->value = NULL;
        }
        buffer->length = 0;
    }
}

void
GsspFreeUnicodeString(PUNICODE_STRING UnicodeString)
{
    if (UnicodeString != NULL) {
        GsspFree(UnicodeString->Buffer);
        RtlInitUnicodeString(UnicodeString, NULL);
    }
}

void
GsspFreeLsaUnicodeString(PUNICODE_STRING UnicodeString)
{
    if (UnicodeString != NULL) {
        if (UnicodeString->Buffer != NULL)
            LsaSpFunctionTable->FreeLsaHeap(UnicodeString->Buffer);
        RtlInitUnicodeString(UnicodeString, NULL);
    }
}
