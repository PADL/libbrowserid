/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 */

#ifndef _MSETUP_H_
#define _MSETUP_H_ 1

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef _SEC_WINNT_AUTH_TYPES
#define _SEC_WINNT_AUTH_TYPES
#endif
#include <windows.h>
#include <ntdll.h>
#include <ntstatus.h>
#include <NTSecAPI.h>
#include <sspi.h>
#include <NTSecPkg.h>
#include <Evntprov.h>
#include <Sddl.h>

#include "gssp.h"           /* for flags */

#ifdef MSETUP_USEDLL
#define MSETUPDLL _declspec(dllimport)
#elif MSETUP_CREATEDLL
#define MSETUPDLL _declspec(dllexport)
#else
#define MSETUPDLL
#endif

/*
 * msetup_reg.c
 */
/*
 * Opens registry key at SSP configuration root.
 */
MSETUPDLL DWORD
MsOpenKey(LPWSTR wszServer, BOOLEAN fWritable, PHKEY phkResult);

/*
 * Closes SSP configuration registry key.
 */
MSETUPDLL DWORD
MsCloseKey(HKEY hKey);

/*
 * msetup_map.c
 */
/*
 * Add a mapping between a AAA identity and a Windows
 * account. The string "*" may be used to indicate a
 * wildcard mapping. If Account is NULL, then the mapping
 * is deleted.
 */
MSETUPDLL DWORD
MsMapUser(HKEY hKey, LPCWSTR wszPrincipal, LPCWSTR wszAccount);

MSETUPDLL DWORD
MsOpenUserListKey(HKEY hKey, BOOLEAN fWritable, PHKEY hMapKey);

MSETUPDLL DWORD
MsQueryUser(HKEY hKey, DWORD index, LPWSTR *outPrincipal, LPWSTR *outAccount);

#if 0
/*
 * msetup_ssp.c
 */
/*
 * Enable or disable SSP.
 */
MSETUPDLL DWORD
MsSetSspEnabled(HKEY hKey, BOOLEAN fEnableSsp);
#endif

/*
 * msetup_flags.c
 */
/*
 * Get SSP flags
 */
MSETUPDLL DWORD
MsQuerySspFlags(HKEY hKey, DWORD *pdwSspFlags);

typedef enum _SSP_FLAG_OP {
    SSP_FLAG_SET,
    SSP_FLAG_ADD,
    SSP_FLAG_DELETE
} SSP_FLAG_OP;

/*
 * Modify SSP flags
 */
MSETUPDLL DWORD
MsModifySspFlags(
    HKEY hKey,
    DWORD fOp,
    DWORD dwSspFlags);

MSETUPDLL LPCWSTR
MsSspFlagToString(DWORD dwSspFlag);

MSETUPDLL DWORD
MsStringToSspFlag(LPCWSTR wszSspFlag);

MSETUPDLL DWORD
MsListSspFlags(FILE *fp);

/*
 * msetup_aaa.c
 */
/*
 * Add a AAA server tuple.
 */

typedef struct _AAA_SERVER_INFO {
    LPWSTR Server;
    LPWSTR Secret;
    LPWSTR Service;
} AAA_SERVER_INFO;

typedef AAA_SERVER_INFO *PAAA_SERVER_INFO;

MSETUPDLL DWORD
MsOpenRadiusKey(HKEY hKey, BOOLEAN fWritable, PHKEY hRadiusKey);

MSETUPDLL DWORD
MsAddAaaServer(
    HKEY hKey,
    PAAA_SERVER_INFO ServerInfo);

MSETUPDLL DWORD
MsAddAaaServerWrapper(
    HKEY hKey,
    LPWSTR Server,
    LPWSTR Service,
    LPWSTR Secret);

/*
 * Deletes existing AAA server tuple.
 */
MSETUPDLL DWORD
MsDeleteAaaServer(
    HKEY hKey,
    PAAA_SERVER_INFO ServerInfo);

MSETUPDLL DWORD
MsDeleteAaaServerWrapper(
    HKEY hKey,
    LPWSTR Server);

MSETUPDLL DWORD
MsQueryAaaServer(
    HKEY hKey,
    DWORD index,
    LPWSTR *outServer,
    LPWSTR *outService);

/*
 * msetup_cred.c
 */
typedef enum _MS_CRED_ATTR {
    MS_CRED_ATTR_MIN = 1,
    MS_CRED_ATTR_CA_CERTIFICATE = MS_CRED_ATTR_MIN,
    MS_CRED_ATTR_SERVER_HASH,
    MS_CRED_ATTR_SUBJECT_NAME,
    MS_CRED_ATTR_SUBJECT_ALT_NAME,
    MS_CRED_ATTR_MAX = MS_CRED_ATTR_SUBJECT_ALT_NAME
} MS_CRED_ATTR;

MSETUPDLL DWORD
MsSetCredAttribute(
    LPWSTR TargetName,
    LPWSTR UserName,
    DWORD dwAttribute,
    LPWSTR AttributeValue);

MSETUPDLL DWORD
MsGetCredAttribute(
    LPWSTR TargetName,
    LPWSTR UserName,
    LPWSTR **pDisplayNames,
    LPWSTR **pDisplayValues);

MSETUPDLL DWORD
MsSetDefaultCertStore(
    HKEY hSspKey,
    LPWSTR Store);

MSETUPDLL DWORD
MsGetDefaultCertStore(
    HKEY hSspKey,
    LPWSTR *pStore);

#endif /* _MSETUP_H_ */
