/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Credential context interfaces
 */

#include "gssp.h"

/*
 * Currently there is a single list for both default and resolved credentials.
 * It may be more performant to split these into separate lists, or to make
 * the resolved credentials child objects of the default ones.
 */
static LIST_ENTRY GsspCredList;
static CRITICAL_SECTION GsspCredListLock;

VOID
GsspInitializeCredList(VOID)
{
    InitializeCriticalSection(&GsspCredListLock);
    InitializeListHead(&GsspCredList);
}

VOID
GsspDeleteCredList(VOID)
{
    PLIST_ENTRY pListEntry;

    EnterCriticalSection(&GsspCredListLock);

    pListEntry = GsspCredList.Flink;

    while (pListEntry != &GsspCredList) {
        gss_cred_id_t GssCred =
            CONTAINING_RECORD(pListEntry,
                              struct gss_cred_id_t_desc_struct, ListEntry);

        GSSP_ASSERT(GssCred->SspFlags & CRED_SSP_FLAG_SHARED);
        pListEntry = pListEntry->Flink;
        GsspCredRelease(GssCred);
    }

    LeaveCriticalSection(&GsspCredListLock);
    DeleteCriticalSection(&GsspCredListLock);
}

static VOID
GsspRemoveCredLocked(gss_cred_id_t GssCred)
{
    RemoveEntryList(&GssCred->ListEntry);
    InterlockedExchange((LONG *)&GssCred->SspFlags,
                        GssCred->SspFlags & ~(CRED_SSP_FLAG_SHARED));
    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspRemoveCredLocked: removed cred %p (flags %08x/%08x) for "
                   L"process %u, RefCount now %u",
                   GssCred, GssCred->flags, GssCred->SspFlags,
                   GssCred->ProcessID, GssCred->RefCount - 1);
    GsspCredRelease(GssCred);
}

VOID
GsspRemoveCred(gss_cred_id_t GssCred)
{
    GSSP_ASSERT(GssCred->SspFlags & CRED_SSP_FLAG_SHARED);

    EnterCriticalSection(&GsspCredListLock);
    GsspRemoveCredLocked(GssCred);
    LeaveCriticalSection(&GsspCredListLock);
}

/*
 * Cleanup any creds associated with the logon session.
 */
VOID
GsspRemoveLogonCred(PLUID LogonId)
{
    PLIST_ENTRY pListEntry;

    EnterCriticalSection(&GsspCredListLock);

    pListEntry = GsspCredList.Flink;

    while (pListEntry != &GsspCredList) {
        gss_cred_id_t GssCred =
            CONTAINING_RECORD(pListEntry,
                              struct gss_cred_id_t_desc_struct, ListEntry);

        GSSP_ASSERT(GssCred->SspFlags & CRED_SSP_FLAG_SHARED);
        pListEntry = pListEntry->Flink;

        if ((GssCred->SspFlags & CRED_SSP_FLAG_LOGON) &&
            SecEqualLuid(LogonId, &GssCred->LogonId))
            GsspRemoveCredLocked(GssCred);
    }

    LeaveCriticalSection(&GsspCredListLock);
}

VOID
GsspMaybeRemoveCred(gss_cred_id_t GssCred)
{
    if (GssCred == GSS_C_NO_CREDENTIAL)
        return;

    /*
     * Non-shared credentials, or shared credentials associated
     * with all processes in a logon session, should not be
     * removed when a credentials or context handle is destroyed.
     * The latter will be cleaned up by LsaApLogonTerminated().
     */
    if ((GssCred->SspFlags & CRED_SSP_FLAG_SHARED) == 0 ||
        (GssCred->SspFlags & CRED_SSP_FLAG_LOGON))
        return;

    /*
     * The reference count check assumes the caller and the
     * list each hold a reference.
     *
     * Defensive programming: if the process is terminating,
     * always remove the credential. This should never happen.
     */

    if (GssCred->RefCount == 2 ||
        (GsspGetCallAttributes() & SECPKG_CALL_PROCESS_TERM))
        GsspRemoveCred(GssCred);
}

VOID
GsspAddCred(gss_cred_id_t GssCred)
{
    /*
     * Don't add credential if it's already there.
     */
    if (GssCred->SspFlags & CRED_SSP_FLAG_SHARED)
        return;

    EnterCriticalSection(&GsspCredListLock);
    GsspCredAddRef(GssCred);
    InterlockedExchange((LONG *)&GssCred->SspFlags,
                        GssCred->SspFlags | CRED_SSP_FLAG_SHARED);
    InsertHeadList(&GsspCredList, &GssCred->ListEntry);
    LeaveCriticalSection(&GsspCredListLock);

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspAddCred: added cred %p (flags %08x/%08x) for "
                   L"process %u, RefCount now %u",
                   GssCred, GssCred->flags, GssCred->SspFlags,
                   GssCred->ProcessID, GssCred->RefCount);
}

static BOOLEAN
GsspEqualCred(
    PLUID Luid,
    ULONG ProcessID,
    ULONG GssCredFlags,
    gss_OID GssMechanism,
    gss_name_t GssUserName,
    gss_name_t GssTargetName,
    gss_cred_id_t GssCred)
{
    OM_uint32 Major, Minor;
    int bEqual = 0;

    if (!SecEqualLuid(Luid, &GssCred->LogonId))
        return FALSE;

    /*
     * If ProcessID argument is 0, then the caller is looking for
     * logon session credentials. Otherwise, they are associated
     * with a specific process ID.
     */
    if (ProcessID == CRED_PROCESS_ID_ALL &&
        (GssCred->SspFlags & CRED_SSP_FLAG_LOGON) == 0)
        return FALSE;

    if (ProcessID != GssCred->ProcessID)
        return FALSE;

    if ((GssCred->flags & CRED_FLAG_RESOLVED) !=
        (GssCredFlags & CRED_FLAG_RESOLVED))
        return FALSE;

    GssCredFlags &= ~(CRED_FLAG_RESOLVED);

    if ((GssCred->flags & GssCredFlags) == 0)
        return FALSE;

    if (!gssEapCredAvailable(GssCred, GssMechanism))
        return FALSE;

    Major = gssEapCompareName(&Minor, GssCred->name,
                              GssUserName, 0, &bEqual);
    if (GSS_ERROR(Major))
        return FALSE;

    if (bEqual && GssTargetName != GSS_C_NO_NAME) {
        Major = gssEapCompareName(&Minor,
                                  GssCred->target,
                                  GssTargetName,
                                  COMPARE_NAME_FLAG_IGNORE_EMPTY_REALMS,
                                  &bEqual);
        if (GSS_ERROR(Major))
            return FALSE;
    }

    return bEqual;
}

/*
 * Returns TRUE if credential has expired. We don't use gssEapInquireCred
 * as that would involve a system call for each credential, and we are
 * checking a bunch at a time.
 */
static BOOLEAN
GsspIsExpiredCred(gss_cred_id_t GssCred, time_t Now)
{
    time_t Lifetime = GSS_C_INDEFINITE;

    if (GssCred->expiryTime != 0)
        Lifetime = Now - GssCred->expiryTime;

    return (Lifetime <= 0);
}

NTSTATUS
GsspFindCred(
    PLUID Luid,
    ULONG ProcessID,
    ULONG GssCredFlags,
    gss_OID GssMechanism,
    gss_name_t GssUserName,
    gss_name_t GssTargetName,
    gss_cred_id_t *pGssCred)
{
    PLIST_ENTRY pListEntry;
    time_t Now;

    *pGssCred = GSS_C_NO_CREDENTIAL;

    time(&Now);

    EnterCriticalSection(&GsspCredListLock);

    for (pListEntry = GsspCredList.Flink;
        pListEntry != &GsspCredList;
        pListEntry = pListEntry->Flink)
    {
        gss_cred_id_t GssCred =
            CONTAINING_RECORD(pListEntry,
                              struct gss_cred_id_t_desc_struct, ListEntry);

        if (GsspIsExpiredCred(GssCred, Now)) {
            GsspRemoveCredLocked(GssCred);
            continue;
        }
        if (GsspEqualCred(Luid, ProcessID, GssCredFlags,
                          GssMechanism, GssUserName,
                          GssTargetName, GssCred)) {
            GsspCredAddRef(GssCred);
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                           L"GsspFindCred: found cred %p (flags %08x/%08x) "
                           L"for process %u, RefCount now %u",
                           GssCred, GssCred->flags, GssCred->SspFlags,
                           GssCred->ProcessID, GssCred->RefCount);
            *pGssCred = GssCred;
            break;
        }
    }

    LeaveCriticalSection(&GsspCredListLock);

    return (*pGssCred == GSS_C_NO_CREDENTIAL) ?
        SEC_E_UNKNOWN_CREDENTIALS : SEC_E_OK;
}

#ifdef DEBUG
VOID
GsspDumpCredList(VOID)
{
    PLIST_ENTRY pListEntry;
    ULONG i = 0;

    EnterCriticalSection(&GsspCredListLock);

    pListEntry = GsspCredList.Flink;

    while (pListEntry != &GsspCredList) {
        gss_cred_id_t GssCred =
            CONTAINING_RECORD(pListEntry,
                              struct gss_cred_id_t_desc_struct, ListEntry);
        PWSTR wszPrincipal = NULL;
        PWSTR wszTarget = NULL;

        GSSP_ASSERT(GssCred->SspFlags & CRED_SSP_FLAG_SHARED);

        if (GssCred->name != GSS_C_NO_NAME)
            GsspDisplayGssNameW(GssCred->name, FALSE, &wszPrincipal);
        if (GssCred->target != GSS_C_NO_NAME)
            GsspDisplayGssNameW(GssCred->target, FALSE, &wszTarget);

        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspDumpCredList[%u]: cred %p (flags %08x/%08x) "
                       L"principal %s target %s RefCount %u "
                       L"PID %u LUID %08x:%08x",
                       i++, GssCred, GssCred->flags, GssCred->SspFlags,
                       wszPrincipal ? wszPrincipal : L"(null)",
                       wszTarget ? wszTarget : L"(null)",
                       GssCred->RefCount, GssCred->ProcessID,
                       GssCred->LogonId.LowPart, GssCred->LogonId.HighPart);

        pListEntry = pListEntry->Flink;

        GsspFree(wszPrincipal);
        GsspFree(wszTarget);
    }

    LeaveCriticalSection(&GsspCredListLock);
}
#endif /* DEBUG */
