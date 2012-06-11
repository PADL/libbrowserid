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
#define FLAG_USAGE          2
#define FLAG_NO_KEY         4

static void
DisplayUsage(LPCWSTR Command);

static DWORD
HandleInvalidArg(LPCWSTR Arg);

static void
DisplayError(LPCWSTR Message, DWORD lResult);

static DWORD
DoDumpAaaServer(HKEY hRadiusKey, LPCWSTR wszAaaServer)
{
    DWORD lResult;
    HKEY hAaaKey;
    WCHAR wszBuf[256];
    DWORD dwType = REG_SZ;
    DWORD dwSize = sizeof(wszBuf);

    wprintf(L"%s:\n", wszAaaServer);

    lResult = RegOpenKeyEx(hRadiusKey, wszAaaServer,
                           0, KEY_QUERY_VALUE, &hAaaKey);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    lResult = RegQueryValueEx(hAaaKey, L"Service", NULL, &dwType,
                              (PBYTE)wszBuf, &dwSize);
    if (lResult == ERROR_SUCCESS)
        wprintf(L"\tService = %s\n", wszBuf);

    lResult = RegQueryValueEx(hAaaKey, L"Secret", NULL, &dwType,
                              NULL, NULL);
    if (lResult == ERROR_SUCCESS)
        wprintf(L"\tSecret = ********\n");

    RegCloseKey(hAaaKey);

    return ERROR_SUCCESS;
}

/*
 * Dump current configuration to stdout
 */
static DWORD
DoDumpState(HKEY hSspKey, int argc, WCHAR *argv[])
{
    DWORD lResult;
    DWORD dwSspFlags;
    DWORD i = 0;
    HKEY hSubKey = NULL;

    if (argc > 1)
        return HandleInvalidArg(argv[1]);

    lResult = MsQuerySspFlags(hSspKey, &dwSspFlags);
    if (lResult != ERROR_SUCCESS)
        return lResult;

    /* flags */
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

    /* AAA config */
    lResult = MsOpenRadiusKey(hSspKey, FALSE, &hSubKey);
    if (lResult == ERROR_SUCCESS) {
        for (i = 0; lResult == ERROR_SUCCESS; i++) {
            WCHAR wszAaaServer[256];
            DWORD cchAaaServer = sizeof(wszAaaServer) / sizeof(WCHAR);

            lResult = RegEnumKeyEx(hSubKey, i, wszAaaServer, &cchAaaServer,
                                   NULL, NULL, NULL, NULL);
            if (lResult == ERROR_NO_MORE_ITEMS) {
                break;
            } else if (lResult != ERROR_SUCCESS) {
                DisplayError(L"Enumerating Radius registry key", lResult);
                break;
            }

            DoDumpAaaServer(hSubKey, wszAaaServer);
        }
        MsCloseKey(hSubKey);
    }

    /* user mappings */
    lResult = MsOpenUserListKey(hSspKey, FALSE, &hSubKey);
    if (lResult == ERROR_SUCCESS) {
        for (i = 0; lResult == ERROR_SUCCESS; i++) {
            WCHAR wszPrincipal[256];
            WCHAR wszAccount[256];
            DWORD cchPrincipal = sizeof(wszPrincipal) / sizeof(WCHAR);
            DWORD cbAccount = sizeof(wszAccount);
            DWORD dwType = REG_SZ;

            lResult = RegEnumValue(hSubKey, i, wszPrincipal,
                                   &cchPrincipal, NULL,
                                   &dwType, (PBYTE)wszAccount, &cbAccount);
            if (lResult != ERROR_SUCCESS)
                break;

            wprintf(L"Mapping ");
            if (_wcsicmp(wszPrincipal, L"*") == 0)
                wprintf(L"all users (*)");
            else
                wprintf(L"%s", wszPrincipal);
            wprintf(L" to ");
            if (dwType != REG_SZ)
                wprintf(L"<invalid type>");
            else if (_wcsicmp(wszAccount, L"*") == 0)
                wprintf(L"a local account by the same name (*)");
            else
                wprintf(L"%s", wszAccount);
            wprintf(L".\n");
        }
        if (lResult != ERROR_SUCCESS && lResult != ERROR_NO_MORE_ITEMS)
            DisplayError(L"Enumerating UserList registry key", lResult);
        MsCloseKey(hSubKey);
    } else {
        i = 0;
    }

    if (i == 0) {
        wprintf(L"No user mappings defined.\n");
    }

    return ERROR_SUCCESS;
}

/*
 * Modify SSP flags
 */
static DWORD
DoModifySspFlags(HKEY hSspKey, SSP_FLAG_OP fOp, int argc, WCHAR *argv[])
{
    DWORD dwSspFlags = 0;
    DWORD i;

    if (argc < 2) {
        fwprintf(stderr, L"%s requires 2 arguments", argv[0]);
        return ERROR_INVALID_PARAMETER;
    }

    for (i = 1; i < argc; i++) {
        DWORD dwFlag = MsStringToSspFlag(argv[i]);

        if (dwFlag == 0) {
            fwprintf(stderr, L"Unknown realm flag: %s", argv[i]);
            DisplayUsage(argv[0]);
            return ERROR_INVALID_PARAMETER;
        }

        dwSspFlags |= dwFlag;
    }

    return MsModifySspFlags(hSspKey, fOp, dwSspFlags);
}

static DWORD
DoSetSspFlags(HKEY hSspKey, int argc, WCHAR *argv[])
{
    return DoModifySspFlags(hSspKey, SSP_FLAG_SET, argc, argv);
}

static DWORD
DoAddSspFlags(HKEY hSspKey, int argc, WCHAR *argv[])
{
    return DoModifySspFlags(hSspKey, SSP_FLAG_ADD, argc, argv);
}

static DWORD
DoDeleteSspFlags(HKEY hSspKey, int argc, WCHAR *argv[])
{
    return DoModifySspFlags(hSspKey, SSP_FLAG_DELETE, argc, argv);
}

static DWORD
DoHelp(HKEY hSspKey, int argc, WCHAR *argv[])
{
    if (argc > 1)
        return HandleInvalidArg(argv[1]);

    DisplayUsage(NULL);
    return ERROR_SUCCESS;
}

static DWORD
DoMapUser(HKEY hSspKey, int argc, WCHAR *argv[])
{
    LPWSTR wszPrincipal;
    LPWSTR wszAccount;
    DWORD lResult;

    if (argc < 2) {
        DisplayUsage(argv[0]);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    wszPrincipal = argv[1];
    wszAccount = (argc > 2) ? argv[2] : NULL;

    lResult = MsMapUser(hSspKey, wszPrincipal, wszAccount);
    if (lResult != ERROR_SUCCESS)
        DisplayError(L"Failed to create user map entry", lResult);

    return lResult;
}

static DWORD
DoAddAaaServer(HKEY hSspKey, int argc, WCHAR *argv[])
{
    AAA_SERVER_INFO AaaServerInfo = { 0 };
    DWORD lResult;

    if (argc < 2 || argc > 4) {
        DisplayUsage(argv[0]);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    AaaServerInfo.Server = argv[1];
    AaaServerInfo.Service = (argc > 2) ? argv[2] : NULL;
    AaaServerInfo.Secret = (argc > 3) ? argv[3] : NULL;

    lResult = MsAddAaaServer(hSspKey, &AaaServerInfo);
    if (lResult != ERROR_SUCCESS)
        DisplayError(L"Failed to create AAA server entry", lResult);

    return lResult;
}

static DWORD
DoDelAaaServer(HKEY hSspKey, int argc, WCHAR *argv[])
{
    AAA_SERVER_INFO AaaServerInfo = { 0 };
    DWORD lResult;

    if (argc != 2) {
        DisplayUsage(argv[0]);
        ExitProcess(ERROR_INVALID_PARAMETER);
    }

    AaaServerInfo.Server = argv[1];

    lResult = MsDeleteAaaServer(hSspKey, &AaaServerInfo);
    if (lResult != ERROR_SUCCESS)
        DisplayError(L"Failed to delete AAA server entry", lResult);

    return lResult;
}

static DWORD
DoListSspFlags(HKEY hSspKey, int argc, WCHAR *argv[])
{
    if (argc > 1)
        return HandleInvalidArg(argv[1]);

    return MsListSspFlags(stdout);
}

static void
DisplayError(LPCWSTR Message, DWORD lResult)
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
        L"/AddAaa",
        L"<AaaServer> [Service|Port] [Secret]",
        L"\tAdds a AAA server entry\n",
        FLAG_WRITE,
        DoAddAaaServer
    },
    {
        L"/DelAaa",
        L"<AaaServer> [Service|Port] [Secret]",
        L"\tDeletes a AAA server entry\n",
        FLAG_WRITE,
        DoDelAaaServer
    },
    {
        L"/ListSspFlags",
        L"(no args)",
        L"\tLists the available SSP configuration flags\n",
        FLAG_NO_KEY,
        DoListSspFlags
    },
    {
        L"/SetSspFlags",
        L"<flag> [flag] [flag] [...]",
        L"\tSets SSP configuration flags\n",
        FLAG_WRITE,
        DoSetSspFlags
    },
    {
        L"/AddSspFlags",
        L"<flag> [flag] [flag] [...]",
        L"\tAdds additional SSP configuration flags\n",
        FLAG_WRITE,
        DoAddSspFlags
    },
    {
        L"/DelSspFlags",
        L"<flag> [flag] [flag] [...]",
        L"\tDeletes SSP configuration flags\n",
        FLAG_WRITE,
        DoDeleteSspFlags
    },
    {
        L"/Help",
        NULL,
        NULL,
        FLAG_USAGE | FLAG_NO_KEY,
        DoHelp,
    },
    {
        L"/?",
        NULL,
        NULL,
        FLAG_USAGE | FLAG_NO_KEY,
        DoHelp,
    },
};

static void
DisplayUsage(LPCWSTR Command)
{
    DWORD i;

    fwprintf(stderr, L"\nUSAGE:\n");

    for (i = 0; i < sizeof(msCmdOptions) / sizeof(msCmdOptions[0]); i++) {
        struct _MS_CMD_OPTION *Option = &msCmdOptions[i];

        /* don't advertise the usage for the usage command itself */
        if (Option->Flags & FLAG_USAGE)
            continue;

        if (Command != NULL && _wcsicmp(Command, Option->Option) != 0)
            continue;

        fwprintf(stderr, L"%s %s\n%s",
                 Option->Option, Option->Usage, Option->Description);
    }
}

static DWORD
HandleInvalidArg(LPCWSTR Arg)
{
    wprintf(L"%s: no such argument.\n", Arg);
    wprintf(L"use msetup /? for help.\n");
    ExitProcess(ERROR_INVALID_PARAMETER);
    return ERROR_INVALID_PARAMETER;
}

int wmain(int argc, WCHAR *argv[])
{
    HKEY hSspKey = NULL;
    DWORD lResult;
    LPWSTR wszServer = NULL;
    DWORD i;
    struct _MS_CMD_OPTION *Option = NULL;

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
        assert(argc != 0);
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
