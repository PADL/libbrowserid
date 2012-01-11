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

#ifndef DPFLTR_LSASS_ID
#define DPFLTR_LSASS_ID 138
#endif

/*
 * These functions are lazily bound as they do not exist prior
 * to Windows Vista.
 */
typedef ULONG
(EventRegisterFn)(
    IN LPCGUID ProviderId,
    IN OPTIONAL PENABLECALLBACK EnableCallback,
    IN OPTIONAL PVOID CallbackContext,
    OUT PREGHANDLE RegHandle);

typedef ULONG
(EventUnregisterFn)(
    IN REGHANDLE RegHandle);

typedef ULONG
(EventWriteFn)(
    IN REGHANDLE RegHandle,
    IN PCEVENT_DESCRIPTOR EventDescriptor,
    IN ULONG UserDataCount,
    IN OPTIONAL PEVENT_DATA_DESCRIPTOR UserData);

typedef ULONG
(EventWriteStringFn)(
    IN REGHANDLE RegHandle,
    IN UCHAR Level,
    ULONGLONG Keyword,
    PCWSTR String);

static EventRegisterFn *pfnEventRegister;
static EventUnregisterFn *pfnEventUnregister;
static EventWriteFn *pfnEventWrite;
static EventWriteStringFn *pfnEventWriteString;

static REGHANDLE GsspEventRegHandle;

static GUID
GsspEventProviderId = { /* b85c67ff-f395-4e75-8836-dc395f022125 */
    0xb85c67ff,
    0xf395,
    0x4e75,
    {0x88, 0x36, 0xdc, 0x39, 0x5f, 0x02, 0x21, 0x25}
  };

NTSTATUS
GsspInitEvent(HMODULE hAdvApi32)
{
    ULONG ulStatus;

    pfnEventRegister    = (EventRegisterFn *)
        GetProcAddress(hAdvApi32, "EventRegister");
    pfnEventUnregister  = (EventUnregisterFn *)
        GetProcAddress(hAdvApi32, "EventUnregister");
    pfnEventWrite       = (EventWriteFn *)
        GetProcAddress(hAdvApi32, "EventWrite");
    pfnEventWriteString = (EventWriteStringFn *)
        GetProcAddress(hAdvApi32, "EventWriteString");

    if (pfnEventRegister != NULL) {
        GSSP_ASSERT(pfnEventUnregister != NULL);
        GSSP_ASSERT(pfnEventWrite != NULL);
        GSSP_ASSERT(pfnEventWriteString != NULL);

        ulStatus = (*pfnEventRegister)(&GsspEventProviderId,
                                       NULL,
                                       NULL,
                                       &GsspEventRegHandle);
    } else {
        GsspEventRegHandle = 0;
        ulStatus = STATUS_SUCCESS;
    }

    return ulStatus;
}

NTSTATUS
GsspShutdownEvent(void)
{
    ULONG ulStatus = STATUS_SUCCESS;

    if (GsspEventRegHandle != 0) {
        GSSP_ASSERT(pfnEventUnregister != NULL);

        ulStatus = (*pfnEventUnregister)(GsspEventRegHandle);
    }

    pfnEventRegister    = NULL;
    pfnEventUnregister  = NULL;
    pfnEventWrite       = NULL;
    pfnEventWriteString = NULL;

    GsspEventRegHandle  = 0;

    return ulStatus;
}

void
__cdecl GsspDebugTrace(UCHAR dwLevel, PCWSTR szFormat, ...)
{
#define DEBUG_PREFIX            L"EAP-SSP: "
#define DEBUG_PREFIX_LEN        9               /* character count */

    WCHAR Buffer[DEBUG_PREFIX_LEN + BUFSIZ + 2];
    va_list ap;

    wcscpy(Buffer, DEBUG_PREFIX);

    va_start(ap, szFormat);
    _vsnwprintf_s(&Buffer[DEBUG_PREFIX_LEN], BUFSIZ, _TRUNCATE, szFormat, ap);
    va_end(ap);

    wcscat(Buffer, L"\r\n");

#ifndef DEBUG
    if (GsspFlags & GSSP_FLAG_DEBUG)
#endif
        OutputDebugStringW(Buffer);


    if (GsspEventRegHandle != 0)
        (*pfnEventWriteString)(GsspEventRegHandle, dwLevel, 0, Buffer);
}

