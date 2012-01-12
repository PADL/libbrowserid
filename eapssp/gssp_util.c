/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Utility functions
 */

#include "gssp.h"

BOOLEAN
GsspValidateClient(
    volatile LUID *ClaimedLuid,
    volatile LUID *ActualLuid)
{
    return GsspValidateClientEx(ClaimedLuid, 0, NULL, ActualLuid, NULL, NULL);
}

VOID
GsspInterlockedExchangeLuid(
    volatile LUID *Dst,
    volatile LUID *Src)
{
    InterlockedExchange(&Dst->HighPart, Src->HighPart);
    InterlockedExchange((PLONG)&Dst->LowPart, (LONG)Src->LowPart);
}

BOOLEAN
GsspValidateClientEx(
    volatile LUID *ClaimedLuid,
    ULONG ClaimedProcessID,
    PSECPKG_CREDENTIAL SPCred,
    volatile LUID *ActualLuid,
    volatile ULONG *ActualProcessID,
    BOOLEAN *Rundown)
{
    SECPKG_CLIENT_INFO ClientInfo;
    NTSTATUS Status;

    if (Rundown != NULL)
        *Rundown = FALSE;

    if (LsaSpFunctionTable == NULL && SPCred == NULL)
        return TRUE; /* We're in user-mode */

    RtlZeroMemory(&ClientInfo, sizeof(ClientInfo));

    if (SPCred != NULL) {
        ClientInfo.LogonId         = SPCred->LogonId;
        ClientInfo.ProcessID       = SPCred->ClientProcess;
        ClientInfo.ThreadID        = SPCred->ClientThread;
        ClientInfo.HasTcbPrivilege = !!(SPCred->Flags & SECPKG_CREDENTIAL_FLAGS_CALLER_HAS_TCB);
    } else {
        Status = LsaSpFunctionTable->GetClientInfo(&ClientInfo);
        if (Rundown != NULL &&
            Status == STATUS_PROCESS_IS_TERMINATING) {
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspValidateClient: Handle rundown");
            /* Automatic rundown */
            *Rundown = TRUE;
        }
        if (Status != STATUS_SUCCESS) {
            if (Rundown == NULL || *Rundown == FALSE) {
                GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                               L"GsspValidateClient: GetClientInfo failed %08x",
                               Status);
            }
            return FALSE;
        }
    }

    /*
     * Check for logon ID match.
     */
    if (ClaimedLuid != NULL &&
        !SecIsZeroLuid(ClaimedLuid) &&
        !SecEqualLuid(ClaimedLuid, &ClientInfo.LogonId)) {
        if (!ClientInfo.HasTcbPrivilege) {
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspValidateClient: non-TCB client process %u denied: Claimed LUID %08x.%08x Actual LUID %08x.%08x",
                           ClientInfo.ProcessID,
                           ClaimedLuid->LowPart, ClaimedLuid->HighPart,
                           ClientInfo.LogonId.LowPart, ClientInfo.LogonId.HighPart);
            return FALSE;
        }
    } else {
        ClaimedLuid = &ClientInfo.LogonId;
    }

    /*
     * Check for process ID match.
     */
    if (ClaimedProcessID != 0 &&
        ClaimedProcessID != ClientInfo.ProcessID) {
        if (!ClientInfo.HasTcbPrivilege)
            return FALSE;
    } else {
        ClaimedProcessID = ClientInfo.ProcessID;
    }

    if (ActualLuid != NULL)
        GsspInterlockedExchangeLuid(ActualLuid, ClaimedLuid);
    if (ActualProcessID != NULL)
        InterlockedExchange((PLONG)ActualProcessID, ClaimedProcessID);

    return TRUE;
}

NTSTATUS
GsspCustomCPToUnicodeString(
    UINT CodePage,
    PSTR Utf8String,
    SSIZE_T cchUtf8String,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString)
{
    NTSTATUS Status;
    int cchUnicodeString, cbUnicodeString;

    if (cchUtf8String != 0) {
        /* Returns size, in characters, including terminate NUL character */
        cchUnicodeString = MultiByteToWideChar(CodePage, 0, Utf8String,
                                               cchUtf8String, NULL, 0);
        if (cchUnicodeString == 0) {
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspCustomCPToUnicodeString: failed to "
                           L"determine UTF-8 Unicode length");
            return STATUS_INVALID_PARAMETER;
        }

        if (cchUtf8String == -1)
            cchUnicodeString--; /* don't include terminator in char count */
    } else {
        cchUnicodeString = 0;
    }

    /* cbUnicodeString includes NUL terminator */
    cbUnicodeString = (cchUnicodeString + 1) * sizeof(WCHAR);

    if (cbUnicodeString > MAXUSHORT) {
        /* can't fit in a UNICODE_STRING */
        return STATUS_NAME_TOO_LONG;
    }

    if (bLsaAlloc)
        Status = GsspLsaAlloc(cbUnicodeString, (PVOID *)&UnicodeString->Buffer);
    else
        Status = GsspAlloc(cbUnicodeString, (PVOID *)&UnicodeString->Buffer);

    if (Status != STATUS_SUCCESS) {
        return Status;
    }

    if (cchUnicodeString != 0) {
        MultiByteToWideChar(CodePage, 0, Utf8String, cchUtf8String,
                            UnicodeString->Buffer, cchUnicodeString);
    }

    UnicodeString->Length = cchUnicodeString * sizeof(WCHAR);
    UnicodeString->MaximumLength = cbUnicodeString;

    UnicodeString->Buffer[cchUnicodeString] = L'\0';

    return STATUS_SUCCESS;
}

NTSTATUS
GsspUTF8ToUnicodeString(
    PSTR Utf8String,
    SSIZE_T cchUtf8String,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString)
{
    return GsspCustomCPToUnicodeString(CP_UTF8, Utf8String, cchUtf8String,
                                       bLsaAlloc, UnicodeString);
}

NTSTATUS
GsspCustomCPToWideString(
    UINT CodePage,
    PSTR Utf8String,
    SSIZE_T cchUtf8String,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchWideString)
{
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;

    RtlInitUnicodeString(&UnicodeString, NULL);

    Status = GsspUTF8ToUnicodeString(Utf8String, cchUtf8String,
                                     bLsaAlloc, &UnicodeString);
    if (Status == STATUS_SUCCESS) {
        *pWideString = UnicodeString.Buffer;
        if (pCchWideString != NULL)
            *pCchWideString = UnicodeString.Length;
    }

    return Status;
}

NTSTATUS
GsspUTF8ToWideString(  
    PSTR Utf8String,
    SSIZE_T cchUtf8String,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchWideString)
{
    return GsspCustomCPToWideString(CP_UTF8,
                                    Utf8String,
                                    cchUtf8String,
                                    bLsaAlloc,
                                    pWideString,
                                    pCchWideString);
}

NTSTATUS
GsspUnicodeStringToCustomCP(
    UINT CodePage,
    PUNICODE_STRING UnicodeString,
    PSTR *pUtf8String,
    SIZE_T *pCchUtf8String)
{
    NTSTATUS Status;
    SIZE_T cchUtf8String;
    SIZE_T cchUnicodeString;

    *pUtf8String = NULL;

    if (UnicodeString->Length % sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    if (UnicodeString->Buffer == NULL) {
        *pUtf8String = NULL;

        if (pCchUtf8String != NULL)
            *pCchUtf8String = 0;
    }

    cchUnicodeString = UnicodeString->Length / sizeof(WCHAR);

    /*
     * In some cases such as CredMan, the UNICODE_STRING Length includes a
     * NUL terminator. In this case, trim it.
     */
    if (cchUnicodeString > 0 &&
        UnicodeString->Buffer[cchUnicodeString - 1] == L'\0')
        cchUnicodeString--;

    if (cchUnicodeString != 0) {
        cchUtf8String = WideCharToMultiByte(CodePage,
                                            0,
                                            UnicodeString->Buffer,
                                            cchUnicodeString,
                                            NULL,
                                            0,
                                            NULL,
                                            NULL);
        if (cchUtf8String == 0) {
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspUnicodeStringToCustomCP: failed to determine UTF-8 Unicode length");
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        cchUtf8String = 0;
    }

    Status = GsspAlloc(cchUtf8String + 1, (PVOID *)pUtf8String);
    if (Status != STATUS_SUCCESS)
        return Status;

    if (cchUtf8String != 0) {
        WideCharToMultiByte(CodePage,
                            0,
                            UnicodeString->Buffer,
                            cchUnicodeString,
                            *pUtf8String,
                            cchUtf8String,
                            NULL,
                            NULL);
    }

    (*pUtf8String)[cchUtf8String] = '\0';

    if (pCchUtf8String != NULL)
        *pCchUtf8String = cchUtf8String;

    return STATUS_SUCCESS;
}

NTSTATUS
GsspUnicodeStringToUTF8(
    PUNICODE_STRING UnicodeString,
    PSTR *pUtf8String,
    SIZE_T *pCchUtf8String)
{
    return GsspUnicodeStringToCustomCP(CP_UTF8,
                                       UnicodeString,
                                       pUtf8String,
                                       pCchUtf8String);
}

NTSTATUS
GsspWideStringToCustomCP(
    UINT CodePage,
    PWSTR WideString,
    SSIZE_T cchWideString,
    PSTR *pUtf8String,
    SIZE_T *pCchUtf8String)
{
    UNICODE_STRING UnicodeString;

    if (cchWideString == -1) {
        RtlInitUnicodeString(&UnicodeString, WideString);
    } else {
        UnicodeString.Length        = cchWideString * sizeof(WCHAR);
        UnicodeString.MaximumLength = UnicodeString.Length;
        UnicodeString.Buffer        = WideString;
    }

    return GsspUnicodeStringToCustomCP(CP_UTF8,
                                       &UnicodeString,
                                       pUtf8String,
                                       pCchUtf8String);
}

NTSTATUS
GsspWideStringToUTF8(PWSTR WideString,
                     SSIZE_T cchWideString,
                     PSTR *pUtf8String,
                     SIZE_T *pCchUtf8String)
{
    return GsspWideStringToCustomCP(CP_UTF8,
                                    WideString,
                                    cchWideString,
                                    pUtf8String,
                                    pCchUtf8String);
}

PSecBuffer
GsspLocateSecBufferEx(
    PSecBufferDesc Buffers,
    ULONG ulBufferType,
    ULONG ulIndex)
{
    ULONG i, j = 0;

    if (Buffers == NULL)
        return NULL;

    for (i = 0; i < Buffers->cBuffers; i++) {
        if ((Buffers->pBuffers[i].BufferType
             & ~(SECBUFFER_ATTRMASK)) == ulBufferType) {
            if (j == ulIndex)
                return &Buffers->pBuffers[i];
            else
                j++;
        }
    }

    return NULL;
}

PSecBuffer
GsspLocateSecBuffer(
    PSecBufferDesc Buffers,
    ULONG BufferType)
{
    return GsspLocateSecBufferEx(Buffers, BufferType, 0);
}

NTSTATUS
GsspGssBufferToUnicodeString(
    gss_buffer_t GssBuffer,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString)
{
    return GsspUTF8ToUnicodeString((PSTR)GssBuffer->value,
                                   GssBuffer->length,
                                   bLsaAlloc, UnicodeString);
}

NTSTATUS
GsspGssBufferToWideString(
    gss_buffer_t GssBuffer,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchWideString)
{
    return GsspUTF8ToWideString((PSTR)GssBuffer->value,
                                GssBuffer->length,
                                bLsaAlloc,
                                pWideString,
                                pCchWideString);
}

NTSTATUS
GsspUnicodeStringToGssBuffer(
    PUNICODE_STRING UnicodeString,
    gss_buffer_t GssBuffer)
{
    NTSTATUS Status;

    GssBuffer->length = 0;
    GssBuffer->value = NULL;

    Status = GsspUnicodeStringToUTF8(UnicodeString,
                                     (PSTR *)&GssBuffer->value,
                                     &GssBuffer->length);

    return Status;
}

NTSTATUS
GsspWideStringToGssBuffer(
    PWSTR WideString,
    gss_buffer_t GssBuffer)
{
    UNICODE_STRING UnicodeString;

    RtlInitUnicodeString(&UnicodeString, WideString);

    return GsspUnicodeStringToGssBuffer(&UnicodeString, GssBuffer);
}

NTSTATUS
GsspCopyGssStringBufferToClientW(
    gss_buffer_t GssBuffer,
    PVOID *ClientBuffer)
{
    NTSTATUS Status;
    UNICODE_STRING UnicodeString;

    RtlInitUnicodeString(&UnicodeString, NULL);

    Status = GsspGssBufferToUnicodeString(GssBuffer, FALSE, &UnicodeString);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaSpFunctionTable->AllocateClientBuffer(NULL,
                                                      UnicodeString.MaximumLength,
                                                      ClientBuffer);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaSpFunctionTable->CopyToClientBuffer(NULL,
                                                    UnicodeString.MaximumLength,
                                                    *ClientBuffer,
                                                    UnicodeString.Buffer);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    GsspFreeUnicodeString(&UnicodeString);

    return Status;
}

NTSTATUS
GsspStringToLsaString(
    LPCSTR String,
    PLSA_STRING *pLsaString)
{
    NTSTATUS Status;
    PLSA_STRING LsaString = NULL;
    DWORD cchString;

    *pLsaString = NULL;

    cchString = strlen(String);

    Status = GsspLsaCalloc(1, sizeof(*LsaString), (PVOID *)&LsaString);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspLsaAlloc(cchString + 1, (PVOID *)&LsaString->Buffer);
    GSSP_BAIL_ON_ERROR(Status);

    LsaString->Length = cchString;
    LsaString->MaximumLength = cchString + 1;

    RtlCopyMemory(LsaString->Buffer, String, cchString + 1);

    *pLsaString = LsaString;

cleanup:
    if (Status != STATUS_SUCCESS) {
        if (LsaString != NULL) {
            GsspLsaFree(LsaString->Buffer);
            GsspLsaFree(LsaString);
        }
    }

    return Status;
}

ULONG
GsspGetCallAttributes(VOID)
{
    SECPKG_CALL_INFO CallInfo;

    if (LsaSpFunctionTable == NULL)
        return 0;

    if (!LsaSpFunctionTable->GetCallInfo(&CallInfo))
        return 0;

    return CallInfo.Attributes;
}

BOOLEAN
GsspIsNegoExCall(VOID)
{
    return ((GsspGetCallAttributes() & SECPKG_CALL_NEGO_EXTENDER) != 0);
}

BOOLEAN
GsspIsWowClientCall(VOID)
{
    return ((GsspGetCallAttributes() & SECPKG_CALL_WOWCLIENT) != 0);
}

NTSTATUS
GsspImpersonateClient(void)
{
    if (LsaSpFunctionTable == NULL)
        return STATUS_CANNOT_IMPERSONATE;

    return LsaSpFunctionTable->ImpersonateClient();
}

NTSTATUS
GsspRevertToSelf(void)
{
    if (LsaSpFunctionTable == NULL ||
        !RevertToSelf())
        return STATUS_CANNOT_IMPERSONATE;

    return STATUS_SUCCESS;
}

NTSTATUS
GsspGetClientLogonId(PLUID pLuid)
{
    NTSTATUS Status;
    SECPKG_CLIENT_INFO ClientInfo;

    Status = LsaSpFunctionTable->GetClientInfo(&ClientInfo);
    if (Status != STATUS_SUCCESS)
        return Status;

    *pLuid = ClientInfo.LogonId;

    return STATUS_SUCCESS;
}

NTSTATUS
GsspDuplicateSid(PSID SourceSid, BOOLEAN bLsaAlloc, PSID *pDestSid)
{
    PSID DestSid;
    ULONG cbSid = RtlLengthSid(SourceSid);
    NTSTATUS Status;

    if (bLsaAlloc)
        Status = GsspLsaAlloc(cbSid, &DestSid);
    else
        Status = GsspAlloc(cbSid, &DestSid);
    if (Status != STATUS_SUCCESS)
        return Status;

    Status = RtlCopySid(cbSid, DestSid, SourceSid);
    if (Status != STATUS_SUCCESS) {
        bLsaAlloc ? GsspLsaFree(DestSid) : GsspFree(DestSid);
    } else {
        *pDestSid = DestSid;
    }

    return Status;
}

BOOLEAN
GsspIsLocalHost(PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName);

    if (!GetComputerName(MachineName, &cchMachineName))
        return FALSE;

    if (HostName->Length != cchMachineName * sizeof(WCHAR))
        return FALSE;

    return (wcsnicmp(HostName->Buffer, MachineName, cchMachineName) == 0);
}

NTSTATUS
GsspGetLocalHostName(BOOLEAN bLsaAlloc, PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName);
    UNICODE_STRING Src;

    if (!GetComputerName(MachineName, &cchMachineName))
        return GetLastError();

    Src.Length        = cchMachineName * sizeof(WCHAR);
    Src.MaximumLength = Src.Length;
    Src.Buffer        = MachineName;

    return GsspDuplicateUnicodeString(&Src, bLsaAlloc, HostName);
}

