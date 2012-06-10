/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * msetup utility, modelled on ksetup usage
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

static void
DisplayError(LPWSTR Message, DWORD lResult);

static DWORD
DoDumpState(HKEY hSspKey, int argc, WCHAR *argv[])
{
    DWORD lResult;
    DWORD dwSspFlags;
    DWORD i = 0;
    HKEY hUserListKey = NULL;

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

    lResult = MsOpenUserListKey(hSspKey, FALSE, &hUserListKey);
    if (lResult == ERROR_SUCCESS) {
        for (i = 0; lResult == ERROR_SUCCESS; i++) {
            WCHAR wszPrincipal[256];
            WCHAR wszAccount[256];
            DWORD cchPrincipal = sizeof(wszPrincipal) / sizeof(WCHAR);
            DWORD cbAccount = sizeof(wszAccount);
            DWORD dwType = REG_SZ;

            lResult = RegEnumValue(hUserListKey, i, wszPrincipal,
                                   &cchPrincipal, NULL,
                                   &dwType, (PBYTE)wszAccount, &cbAccount);
            if (lResult != ERROR_SUCCESS)
                continue;

            wprintf(L"Mapping ");
            if (_wcsicmp(wszPrincipal, L"*") == 0)
                wprintf(L"all users (*)");
            else
                wprintf(L"%s", wszPrincipal);
            wprintf(L" to ");
            if (dwType != REG_SZ)
                wprintf(L"???");
            else if (_wcsicmp(wszAccount, L"*") == 0)
                wprintf(L"a local account by the same name (*)");
            else
                wprintf(L"%s", wszAccount);
            wprintf(L".\n");
        }
        if (lResult != ERROR_SUCCESS && lResult != ERROR_NO_MORE_ITEMS)
            DisplayError(L"Enumerating UserList registry key", lResult);
        MsCloseKey(hUserListKey);
    } else
        i = 0;

    if (i == 0)
        wprintf(L"No user mappings defined.\n");

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

static DWORD
DoMapUser(HKEY hSspKey, int argc, WCHAR *argv[])
{
    LPWSTR wszPrincipal;
    LPWSTR wszAccount;
    DWORD lResult;

    if (argc == 0)
        DisplayUsage();

    wszPrincipal = argv[0];
    wszAccount = (argc > 1) ? argv[1] : NULL;

    lResult = MsMapUser(hSspKey, wszPrincipal, wszAccount);
    if (lResult != ERROR_SUCCESS)
        DisplayError(L"Failed to create UserList entry", lResult);

    return lResult;
}

static void
DisplayError(LPWSTR Message, DWORD lResult)
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
    DWORD (*Callback)(HKEY, int, WCHAR *[]);
} msCmdOptions[] = {
    {
        L"/DumpState",
        L"(no args)",
        L"\tDisplay the EAP SSP configuration on the given machine\n",
        0,
        DoDumpState,
    },
    {
        L"/MapUser",
        L"<NAI> [Account]",
        L"\tMaps a Network Access Identifier ('*' = any NAI)\n"
        L"\tto an account ('*' = an account by the same name);\n"
        L"\tIf account name is omitted, the mapping for the\n"
        L"\tspecified NAI is deleted.\n",
        FLAG_WRITE,
        DoMapUser
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

        wprintf(L"%s %s\n%s",
                Option->Option, Option->Usage, Option->Description);
    }
}

static void
HandleInvalidArg(LPWSTR Arg)
{
    wprintf(L"%s: no such argument.\n", Arg);
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

        argc--;
        argv++;
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
            if (lResult == ERROR_FILE_NOT_FOUND)
                wprintf(L"Moonshot SSP is not installed on this machine.\n");
            else
                DisplayError(L"Failed to open SSP key", lResult);
            ExitProcess(lResult);
        }
    }

    lResult = (*Option->Callback)(hSspKey, argc, argv);

    if (hSspKey != NULL)
        MsCloseKey(hSspKey);

    ExitProcess(lResult);
    return lResult;
}
