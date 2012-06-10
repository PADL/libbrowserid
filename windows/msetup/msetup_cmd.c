/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * msetup utility
 */

#include <assert.h>
#include "msetup.h"

#define FLAG_WRITE          1
#define FLAG_HIDDEN         2
#define FLAG_NO_KEY         4

static void
DisplayUsage(void);

static void
HandleInvalidArg(LPWSTR Arg);

static DWORD
DoDumpState(HKEY hSspKey, int argc, WCHAR *argv[])
{
    DWORD lResult;
    DWORD dwSspFlags;
    DWORD i;

    lResult = MsQuerySspFlags(hSspKey, &dwSspFlags);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    wprintf(L"Flags = 0x%x ", dwSspFlags);

    if (dwSspFlags == 0) {
        wprintf(L"none\n");
    } else {
        for (i = 0; i < 32; i++) {
            if ((dwSspFlags >> i) & 1) {
                LPCWSTR wszSspFlag = MsSspFlagToString(1 << i);
                if (wszSspFlag != NULL)
                    wprintf(L"%s ", wszSspFlag);
            }
        }
        wprintf(L"\n");
    }

    return ERROR_SUCCESS;
}

static DWORD
DoHelp(HKEY hSspKey, int argc, WCHAR *argv[])
{
    if (argc != 0)
        HandleInvalidArg(argv[1]);

    DisplayUsage();
    return ERROR_SUCCESS;
}

static void
ErrorExit(LPWSTR Message, DWORD lResult)
{
    WCHAR wszMsgBuf[128] = L"";

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  lResult,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPWSTR)wszMsgBuf,
                  sizeof(wszMsgBuf),
                  NULL);

    wprintf(L"%s: %s\n", Message, wszMsgBuf);
    ExitProcess(lResult);
}

static struct _MS_CMD_OPTION {
    LPWSTR Option;
    LPWSTR Usage;
    LPWSTR Description;
    DWORD Flags;
    DWORD (*Callback)(HKEY, int, WCHAR **);
} msCmdOptions[] = {
    {
        L"/DumpState",
        L"(no args)",
        L"Display the EAP SSP configuration on the given machine",
        0,
        DoDumpState,
    },
    {
        L"/Help",
        NULL,
        NULL,
        FLAG_HIDDEN | FLAG_NO_KEY,
        DoHelp,
    },
    {
        L"/?",
        NULL,
        NULL,
        FLAG_HIDDEN | FLAG_NO_KEY,
        DoHelp,
    },
};

static void
DisplayUsage(void)
{
    DWORD i;

    wprintf(L"\nUSAGE:\n");

    for (i = 0; i < sizeof(msCmdOptions) / sizeof(msCmdOptions[0]); i++) {
        struct _MS_CMD_OPTION *Option = &msCmdOptions[i];

        if (Option->Flags & FLAG_HIDDEN)
            continue;

        wprintf(L"%s %s\n\t%s\n",
                Option->Option, Option->Usage, Option->Description);
    }
}

static void
HandleInvalidArg(LPWSTR Arg)
{
    wprintf(L"%s: no such argument.\n");
    wprintf(L"use msetup /? for help.\n");
    ExitProcess(ERROR_INVALID_PARAMETER);
}

int wmain(int argc, WCHAR *argv[])
{
    HKEY hSspKey = NULL;
    DWORD lResult;
    LPWSTR wszServer = NULL;
    struct _MS_CMD_OPTION *Option = NULL;
    DWORD i;

    assert(argc > 0);
    argc--;
    argv++;

    if (argc > 2 && _wcsicmp(argv[1], L"/Server") == 0) {
        wszServer = argv[2];
        argc -= 2;
        argv += 2;
    }

    if (argc != 0) {
        for (i = 0; i < sizeof(msCmdOptions) / sizeof(msCmdOptions[0]); i++) {
            if (_wcsicmp(argv[0], msCmdOptions[i].Option) == 0) {
                Option = &msCmdOptions[i];
                break;
            }
        }
    } else {
        Option = &msCmdOptions[0];  /* /DumpState */
    }

    if (Option == NULL) {
        HandleInvalidArg(argv[0]);
    }

    if (!(Option->Flags & FLAG_NO_KEY)) {
        lResult = MsOpenKey(wszServer, !!(Option->Flags & FLAG_WRITE),
                            &hSspKey);
        if (lResult != 0) {
            wprintf(L"Moonshot SSP is not installed on this machine.\n");
            ErrorExit(L"Failed to open SSP key", lResult);
        }
    }

    lResult = (*Option->Callback)(hSspKey, argc, argv);

    if (hSspKey != NULL)
        MsCloseKey(hSspKey);

    return lResult;
}
