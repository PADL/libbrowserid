/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 */

#ifndef _GSSP_H_
#define _GSSP_H_ 1

#ifdef GSSEAP_KERNEL

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_KERNEL
#define SECURITY_KERNEL
#endif

#include <ntifs.h>
#include <ntsecpkg.h>

#else

#include <config.h>

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
#include <Rpc.h>
#include <NtDsAPI.h>
#include <ntstatus.h>
#include <wincred.h>
#include <wincrypt.h>
#include <NTSecAPI.h>
#include <sspi.h>
#include <NTSecPkg.h>
#include <winmeta.h>
#include <Authz.h>
#include <Sddl.h>

#include <gssapi/gssapi.h>

#endif /* GSSEAP_KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAXUSHORT
#define MAXUSHORT                       0xFFFF
#endif

#define EAP_AES128_PACKAGE_NAME_W   L"eap-aes128"
#define EAP_AES128_PACKAGE_NAME_A    "eap-aes128"

#define EAP_AES256_PACKAGE_NAME_W   L"eap-aes256"
#define EAP_AES256_PACKAGE_NAME_A    "eap-aes256"

#define EAPSSP_PACKAGE_COMMENT_W    L"EAP Security Package"

#define EAPSSP_PACKAGE_CAPABILITIES     ( SECPKG_FLAG_INTEGRITY         | \
                                          SECPKG_FLAG_PRIVACY           | \
                                          SECPKG_FLAG_TOKEN_ONLY        | \
                                          SECPKG_FLAG_MULTI_REQUIRED    | \
                                          SECPKG_FLAG_CONNECTION        | \
                                          SECPKG_FLAG_IMPERSONATION     | \
                                          SECPKG_FLAG_ACCEPT_WIN32_NAME | \
                                          SECPKG_FLAG_NEGOTIABLE        | \
                                          SECPKG_FLAG_GSS_COMPATIBLE    | \
                                          SECPKG_FLAG_MUTUAL_AUTH       | \
                                          SECPKG_FLAG_READONLY_WITH_CHECKSUM | \
                                          SECPKG_FLAG_NEGOTIABLE2       )

#define EAPSSP_PACKAGE_VERSION  1
#define EAPSSP_MAX_TOKEN_SIZE   12000
#define EAPSSP_ALTSECID_PREFIX_W        L"EAP"
#define EAPSSP_ALTSECID_PREFIX_LENGTH   3

#define EAPSSP_TOKEN_LOCAL_SAM  "EAP(SAM)"
#define EAPSSP_TOKEN_SOURCE_AAA "EAP(AAA)"
#define EAPSSP_TOKEN_SOURCE_S4U "EAP(S4U)"

#define EAPSSP_ORIGIN_S4U       "EAP - mapped Kerberos user"

/*
 * DCE defines not in public headers
 */
#define EAP_AES128_RPCID                96
#define EAP_AES256_RPCID                97

/*
 * This structure is encoded as-is; pointers are encoded as
 * offsets from the start of the structure.
 */
typedef struct _GSS_KERNEL_CONTEXT {
    ULONG ContextVersion;
    ULONG ContextSize;
    ULONG Flags;
    ULONG ChecksumType;
    ULONG KeyType;
    ULONG KeyLength;
    PUCHAR KeyValue;
    SECURITY_INTEGER ExpirationTime;
    ULONG64 SendSeq;
    ULONG64 RecvSeq;
    LUID LogonId;
    UNICODE_STRING AccountName;
    ULONG UserFlags;
    USHORT RpcId;
    USHORT Reserved;
    HANDLE TokenHandle;
    volatile PVOID AccessToken;
    LSA_SEC_HANDLE LsaHandle;
    KSEC_LIST_ENTRY ListEntry;
} GSS_KERNEL_CONTEXT, *PGSS_KERNEL_CONTEXT;

#define GSS_KERNEL_CONTEXT_VERSION_1    1U
#define GSS_KERNEL_CONTEXT_VERSION      GSS_KERNEL_CONTEXT_VERSION_1

#ifndef GSSEAP_KERNEL

typedef struct _DCE_MSG_SECURITY_INFO {
    unsigned long SendSequenceNumber;
    unsigned long ReceiveSequenceNumber;
    unsigned char PacketType;
} DCE_MSG_SECURITY_INFO, *PDCE_MSG_SECURITY_INFO;

/*
 * Smartcard defines not in public headers
 */
#pragma pack(push, 1)
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union {
        PVOID   ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

/*
 * These functions are not available on Windows XP, so delay
 * loading them.
 */
typedef NTSTATUS
(NTAPI CredIsProtectedFn)(
    IN PWSTR pszProtectedCredentials,
    OUT CRED_PROTECTION_TYPE *pProtectionType);

typedef NTSTATUS
(NTAPI CredProtectFn)(
    IN BOOL fAsSelf,
    IN LPTSTR pszCredentials,
    IN DWORD cchCredentials,
    OUT LPTSTR pszProtectedCredentials,
    IN OUT DWORD *pcchMaxChars,
    OUT CRED_PROTECTION_TYPE *ProtectionType);

typedef NTSTATUS
(NTAPI CredUnprotectFn)(
    IN BOOL fAsSelf,
    IN LPTSTR pszProtectedCredentials,
    IN DWORD cchCredentials,
    IN OUT LPTSTR pszCredentials,
    IN OUT DWORD *pcchMaxChars);

extern CredIsProtectedFn *pfnCredIsProtected;
extern CredProtectFn *pfnCredProtect;
extern CredUnprotectFn *pfnCredUnprotect;

/* gssp_attr.c */
NTSTATUS
GsspQuerySubjectSecurityAttributes(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer);

/* gssp_context.c */

/* set this if context is created from LSA AP */
#define CTX_FLAG_LOGON                      0x00001000

/*
 * LSA-mode context functions
 */
SpInitLsaModeContextFn          SpInitLsaModeContextEapAes128;
SpInitLsaModeContextFn          SpInitLsaModeContextEapAes256;
SpAcceptLsaModeContextFn        SpAcceptLsaModeContext;
SpDeleteContextFn               SpDeleteContext;
SpApplyControlTokenFn           SpApplyControlToken;
SpQueryContextAttributesFn      SpQueryContextAttributes;
SpSetContextAttributesFn        SpSetContextAttributes;

NTSTATUS GsspAllocContext(
    ULONG ContextRequirements,
    BOOLEAN IsInitiatorContext,
    gss_cred_id_t GssCredential,
    gss_ctx_id_t *pGssContext);

NTSTATUS
GsspInitSecContext(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN OPTIONAL PUNICODE_STRING TargetName,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    IN PSecBufferDesc InputBuffers,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    IN OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData,
    IN gss_OID Oid);

NTSTATUS
GsspAcceptSecContext(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffers,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData);

VOID GsspContextRelease(gss_ctx_id_t GssContext);
VOID GsspContextAddRefAndLock(gss_ctx_id_t GssContext);
VOID GsspContextUnlockAndRelease(gss_ctx_id_t GssContext);

NTSTATUS
GsspPackContext(
    gss_ctx_id_t GssContext,
    BOOLEAN bKernelContext,
    PSecBuffer ContextData);


/* gssp_cred.c */
/*
 * LSA-mode credentials functions
 */
SpAcceptCredentialsFn           SpAcceptCredentialsEapAes128;
SpAcceptCredentialsFn           SpAcceptCredentialsEapAes256;
SpAcquireCredentialsHandleFn    SpAcquireCredentialsHandleEapAes128;
SpAcquireCredentialsHandleFn    SpAcquireCredentialsHandleEapAes256;
SpQueryCredentialsAttributesFn  SpQueryCredentialsAttributes;
SpSetCredentialsAttributesFn    SpSetCredentialsAttributes;
SpFreeCredentialsHandleFn       SpFreeCredentialsHandle;
SpSaveCredentialsFn             SpSaveCredentials;
SpGetCredentialsFn              SpGetCredentials;
SpDeleteCredentialsFn           SpDeleteCredentials;
SpAddCredentialsFn              SpAddCredentials;
SpGetCredUIContextFn            SpGetCredUIContext;
SpUpdateCredentialsFn           SpUpdateCredentials;

VOID GsspCredAddRef(gss_cred_id_t GssCred);
VOID GsspCredRelease(gss_cred_id_t GssCred);

NTSTATUS GsspCredAddRefAndLock(gss_cred_id_t GssCred);
VOID GsspCredUnlockAndRelease(gss_cred_id_t GssCred);
BOOLEAN GsspIsCredResolved(gss_cred_id_t GssCred);

NTSTATUS
GsspAcquireCredHandle(
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN ULONG CredentialUseFlags,
    IN OPTIONAL PLUID LogonId,
    IN PVOID AuthIdentityBuffer,
    IN gss_OID Oid,
    OUT gss_cred_id_t *pGssCred,
    OUT PTimeStamp ExpirationTime);

NTSTATUS
MaybeAppendDomain(
    gss_buffer_t User,
    gss_buffer_t Domain);

/* gssp_credlist.c */
#define CRED_SSP_FLAG_SHARED                0x00000001
#define CRED_SSP_FLAG_CREDMAN               0x00000002
#define CRED_SSP_FLAG_AUTOLOGON_RESTRICTED  0x00000004
#define CRED_SSP_FLAG_IDENTITY_ONLY         0x00000008
#define CRED_SSP_FLAG_LOGON                 0x00000010

VOID GsspInitializeCredList(VOID);
VOID GsspDeleteCredList(VOID);

#define CRED_PROCESS_ID_ALL                 0

NTSTATUS
GsspFindCred(
    PLUID Luid,
    ULONG ProcessID,
    ULONG CredentialUseFlags,
    gss_OID GssMechanism,
    gss_name_t GssUserName,
    gss_name_t GssTargetName,
    gss_cred_id_t *pGssCred);

VOID
GsspRemoveCred(gss_cred_id_t GssCred);

VOID
GsspMaybeRemoveCred(gss_cred_id_t GssCred);

VOID
GsspAddCred(gss_cred_id_t GssCred);

VOID
GsspRemoveLogonCred(PLUID LogonId);

/* gssp_ctxattr.c */
NTSTATUS
GsspQueryContextAttributes(IN gss_ctx_id_t ContextHandle,
    IN ULONG ContextAttribute,
    IN OUT PVOID Buffer);

NTSTATUS
GsspSetContextAttributes(
    IN gss_ctx_id_t ContextHandle,
    IN ULONG ContextAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize);

USHORT
GsspQueryPackageRpcId(PSecPkgInfo PkgInfo);

/* gssp_glue.c */
#define GSS_C_ALLOW_MISSING_BINDINGS        0x10000

#define GSSP_ISC_REQ_FLAGS_MASK             (~(GSS_C_DELEG_FLAG))

#define GSSP_ASC_REQ_FLAGS_MASK             ( GSS_C_DCE_STYLE | \
                                              GSS_C_ALLOW_MISSING_BINDINGS )

#define GsspSecBufferToGssBuffer(Sec, Gss)    do {  \
        (Gss)->length = (Sec)->cbBuffer;            \
        (Gss)->value = (Sec)->pvBuffer;             \
    } while (0)

void GsspMapTime(time_t GssTime, TimeStamp *ts);
ULONG GsspMapStatus(OM_uint32 Major, OM_uint32 Minor);

ULONG GsspMapFlags(OM_uint32 GssFlags, BOOLEAN IsInitiator);
OM_uint32 GsspUnmapFlags(ULONG SspiFlags, BOOLEAN IsInitiator);

ULONG GsspMapCredUsage(gss_cred_usage_t GssUsage);
gss_cred_usage_t GsspUnmapCredUsage(ULONG SspiUsage);

NTSTATUS GsspCopyGssNameToClient(gss_name_t GssName, PVOID ClientBuffer);
NTSTATUS GsspDisplayGssNameW(gss_name_t GssName, BOOLEAN bLsaAlloc, PWSTR *pwszGssName);
NTSTATUS GsspDisplayGssNameUnicodeString(gss_name_t GssName, BOOLEAN bLsaAlloc, UNICODE_STRING *pwszGssName);

NTSTATUS GsspImportNameW(PWSTR InputName, gss_name_t *pOutputName);
NTSTATUS GsspImportNameUnicodeString(PUNICODE_STRING InputName, gss_name_t *pOutputName);

OM_uint32
gssEapImportNameW(OM_uint32 *Minor,
                  PWSTR InputNameBuffer,
                  const gss_OID InputNameType,
                  const gss_OID InputMechType,
                  gss_name_t *pOutputName);
OM_uint32
gssEapImportNameUnicodeString(OM_uint32 *Minor,
                              PUNICODE_STRING InputNameBuffer,
                              const gss_OID InputNameType,
                              const gss_OID InputMechType,
                              gss_name_t *pOutputName);

NTSTATUS GsspGetGssTokenBuffer(
    PSecBufferDesc Buffers,
    gss_buffer_t GssTokenBuffer);
NTSTATUS GsspCopyGssBuffer(
    gss_buffer_t GssBuffer,
    PSecBuffer Buffer,
    BOOLEAN bAllocate);
#if 0
NTSTATUS GsspCopyGssBufferToClientBuffer(
    gss_buffer_t GssBuffer,
    PSecBuffer ClientBuffer,
    BOOLEAN bAllocate);
#endif
NTSTATUS GsspGetGssChannelBindings(
    PSecBufferDesc Buffers,
    gss_channel_bindings_t GssChannelBindings);

NTSTATUS GsspSecBuffersToIov(
    PSecBufferDesc Buffers,
    gss_iov_buffer_t *pIov,
    BOOLEAN bWrap);

NTSTATUS GsspIovToSecBuffers(
    gss_iov_buffer_t Iov,
    PSecBufferDesc Buffers,
    BOOLEAN bWrap);

/* gssp_info.c */
SpGetUserInfoFn                 SpGetUserInfo;
SpSetExtendedInformationFn      SpSetExtendedInformation;
SpGetExtendedInformationFn      SpGetExtendedInformationEapAes128;
SpGetExtendedInformationFn      SpGetExtendedInformationEapAes256;

/* gssp_init.c */
extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;
extern SECPKG_PARAMETERS SpParameters;

/*
 * Registry settable flags
 */
#define GSSP_FLAG_DEBUG             0x00000001  /* Logging on free build */
#define GSSP_FLAG_DISABLE_SPNEGO    0x00000002  /* Don't register with SPNEGO */
#define GSSP_FLAG_DISABLE_NEGOEX    0x00000004  /* Don't register with NegoEx */
#define GSSP_FLAG_S4U_ON_DC         0x00000008  /* Use S4U2Self on DCs */
#define GSSP_FLAG_FORCE_KERB_RPCID  0x00000010  /* Fake RpcID for Exchange */
#define GSSP_FLAG_LOGON             0x00000020  /* Support interactive logon */
#define GSSP_FLAG_LOGON_CREDS       0x00000040  /* Store domain logon credentials */
#define GSSP_FLAG_REG_MASK          0x0000FFFF  /* Settable through registry */

/*
 * Internal feature flags
 */
#define GSSP_FLAG_UPLEVEL           0x00010000  /* Vista or greater */
#define GSSP_FLAG_TOKEN_CLAIMS      0x00020000  /* LSA supports claims */

extern ULONG GsspFlags;
extern LUID GsspTokenSourceId;

SpInitializeFn                  SpInitialize;
SpShutdownFn                    SpShutdown;
SpGetInfoFn                     SpGetInfo;

NTSTATUS NTAPI
GsspGetInfo(IN gss_OID Oid, OUT PSecPkgInfo PackageInfo);

DWORD
GsspGetRegFlags(void);

NTSTATUS SEC_ENTRY
SpLsaModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_FUNCTION_TABLE * ppTables,
    OUT PULONG pcTables);

/* gssp_logon.c */

NTSTATUS
GsspAcceptCredentials(
    SECURITY_LOGON_TYPE LogonType,
    PUNICODE_STRING AccountName,
    PSECPKG_PRIMARY_CRED PrimaryCredentials,
    PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials,
    gss_OID MechOid);

NTSTATUS NTAPI
LsaApInitializePackage(
    IN ULONG AuthenticationPackageId,
    IN PLSA_DISPATCH_TABLE LsaDispatchTable,
    IN OPTIONAL PLSA_STRING Database,
    IN OPTIONAL PLSA_STRING Confidentiality,
    OUT PLSA_STRING *AuthenticationPackageName);

VOID NTAPI
LsaApLogonTerminated(PLUID LogonId);

NTSTATUS NTAPI
LsaApLogonUserEx2(
  IN PLSA_CLIENT_REQUEST ClientRequest,
  IN SECURITY_LOGON_TYPE LogonType,
  IN PVOID ProtocolSubmitBuffer,
  IN PVOID ClientBufferBase,
  IN ULONG SubmitBufferSize,
  OUT PVOID *ProfileBuffer,
  OUT PULONG ProfileBufferSize,
  OUT PLUID LogonId,
  OUT PNTSTATUS SubStatus,
  OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  OUT PVOID *TokenInformation,
  OUT PUNICODE_STRING *AccountName,
  OUT PUNICODE_STRING *AuthenticatingAuthority,
  OUT PUNICODE_STRING *MachineName,
  OUT PSECPKG_PRIMARY_CRED PrimaryCredentials,
  OUT PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials);

/* gssp_mem.c */

/*
 * Use these functions for private memory.
 */
void *GsspAllocPtr(size_t Length);
void *GsspCallocPtr(size_t Nelems, size_t Size);
void GsspFreePtr(void *Ptr);
void *GsspReallocPtr(void *Ptr, size_t Size);

VOID GsspFreeUnicodeString(PUNICODE_STRING UnicodeString);

NTSTATUS GsspAlloc(SIZE_T Length, PVOID *pPtr);
NTSTATUS GsspCalloc(SIZE_T Length, SIZE_T Nelems, PVOID *pPtr);
VOID GsspFree(PVOID Ptr);

NTSTATUS
GsspDuplicateString(
    PWSTR Src,
    BOOLEAN bLsaAlloc,
    PWSTR *pDst);

NTSTATUS
GsspDuplicateUnicodeString(
    PUNICODE_STRING Src,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING Dst);

/*
 * Use these functions if you are returning memory to the LSA.
 */
NTSTATUS GsspLsaAlloc(SIZE_T Length, PVOID *pPtr);
NTSTATUS GsspLsaCalloc(SIZE_T Length, SIZE_T Nelems, PVOID *pPtr);
VOID GsspLsaFree(PVOID Ptr);

/* This *always* frees the LSA heap */
VOID GsspFreeLsaUnicodeString(PUNICODE_STRING UnicodeString);

VOID GsspSetAllocFree(PLSA_ALLOCATE_LSA_HEAP Alloc, PLSA_FREE_LSA_HEAP Free);

/*
 * Zero and release a buffer allocated with GsspAllocPtr.
 */
VOID GsspSecureZeroAndReleaseGssBuffer(gss_buffer_t buffer);

/*
 * Return attributes for this thread's currently executing call.
 */
ULONG GsspGetCallAttributes(VOID);
BOOLEAN GsspIsNegoExCall(VOID);
BOOLEAN GsspIsWowClientCall(VOID);

/* gssp_nego.c */
SpQueryMetaDataFn               SpQueryMetaData;
SpExchangeMetaDataFn            SpExchangeMetaData;
SpValidateTargetInfoFn          SpValidateTargetInfo;

NTSTATUS
GsspQueryContextNegoKeys(gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer);

NTSTATUS
GsspQueryContextCredInfo(gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer);

NTSTATUS
ConvertNegoExCredentialToGss(
    PSECPKG_CREDENTIAL pSPCred,
    gss_buffer_t User,
    gss_buffer_t Domain,
    PSEC_WINNT_AUTH_PACKED_CREDENTIALS *ppPackedCredentials);

NTSTATUS
GsspSetNegoExCred(gss_cred_id_t GssCred,
                  PSEC_WINNT_AUTH_PACKED_CREDENTIALS PackedCreds);

/* gssp_stubs.c */

/* gssp_token.c */
NTSTATUS
QueryInformationTokenAlloc(
    HANDLE Token,
    TOKEN_INFORMATION_CLASS InfoClass,
    PVOID *ppInfo);

NTSTATUS GsspCreateTokenOrMapAccount(gss_ctx_id_t GssContext);

/* gssp_trace.c */
NTSTATUS
GsspInitEvent(HMODULE hAdvApi32);

NTSTATUS
GsspShutdownEvent(void);

void __cdecl
GsspDebugTrace(UCHAR dwLevel, PCWSTR szFormat, ...);

/* gssp_user.c */
NTSTATUS SEC_ENTRY
SpUserModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_USER_FUNCTION_TABLE *ppTables,
    OUT PULONG pcTables);

SpInstanceInitFn                SpInstanceInit;
SpInitUserModeContextFn         SpInitUserModeContext;
SpMakeSignatureFn               SpMakeSignature;
SpVerifySignatureFn             SpVerifySignature;
SpSealMessageFn                 SpSealMessage;
SpUnsealMessageFn               SpUnsealMessage;
SpGetContextTokenFn             SpGetContextToken;
SpQueryContextAttributesFn      SpQueryUserModeContextAttributes;
SpCompleteAuthTokenFn           SpCompleteAuthToken;
SpDeleteContextFn               SpDeleteUserModeContext;
SpFormatCredentialsFn           SpFormatCredentials;
SpMarshallSupplementalCredsFn   SpMarshallSupplementalCreds;
SpExportSecurityContextFn       SpExportSecurityContext;
SpImportSecurityContextFn       SpImportSecurityContext;

extern SECPKG_USER_FUNCTION_TABLE   EapUserModeFunctions;

/* gssp_util.c */
NTSTATUS
GsspImpersonateClient(void);

NTSTATUS
GsspRevertToSelf(void);

NTSTATUS
GsspGetClientLogonId(PLUID pLuid);

VOID
GsspInterlockedExchangeLuid(volatile LUID *Dst, volatile LUID *Src);

/* These are marked volatile so they can be used without acquiring lock */
BOOLEAN
GsspValidateClient(
    volatile LUID *ClaimedLuid,
    volatile LUID *ActualLuid);
BOOLEAN
GsspValidateClientEx(
    volatile LUID *ClaimedLuid,
    ULONG ProcessId,
    PSECPKG_CREDENTIAL SPCred,
    volatile LUID *ActualLuid,
    volatile ULONG *ActualProcessID,
    BOOLEAN *Rundown);

NTSTATUS
GsspUTF8ToUnicodeString(
    PSTR Utf8String,
    SSIZE_T Utf8Length,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString);
NTSTATUS
GsspUTF8ToWideString(
    PSTR Utf8String,
    SSIZE_T Utf8Length,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchString);
NTSTATUS
GsspUnicodeStringToUTF8(
    PUNICODE_STRING UnicodeString,
    PSTR *pUtf8String,
    SIZE_T *pCchString);
NTSTATUS
GsspWideStringToUTF8(
    PWSTR WideString,
    SSIZE_T WideStringLength,
    PSTR *pUtf8String,
    SIZE_T *pCchString);

NTSTATUS
GsspWideStringToCustomCP(
    UINT CodePage,
    PWSTR WideString,
    SSIZE_T WideStringLength,
    PSTR *pUtf8String,
    SIZE_T *pCchString);
NTSTATUS
GsspCustomCPToWideString(
    UINT CodePage,
    PSTR Utf8String,
    SSIZE_T Utf8StringLength,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchString);
NTSTATUS
GsspCustomCPToUnicodeString(
    UINT CodePage,
    PSTR Utf8String,
    SSIZE_T Utf8StringLength,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString);
NTSTATUS
GsspUnicodeStringToCustomCP(
    UINT CodePage,
    PUNICODE_STRING UnicodeString,
    PSTR *pUtf8String,
    SIZE_T *pCchString);

NTSTATUS
GsspGssBufferToUnicodeString(
    gss_buffer_t GssBuffer,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString);
NTSTATUS
GsspGssBufferToWideString(
    gss_buffer_t GssBuffer,
    BOOLEAN bLsaAlloc,
    PWSTR *pWideString,
    SIZE_T *pCchString);
NTSTATUS
GsspUnicodeStringToGssBuffer(
    PUNICODE_STRING UnicodeString,
    gss_buffer_t GssBuffer);
NTSTATUS
GsspWideStringToGssBuffer(
    PWSTR WideString,
    gss_buffer_t GssBuffer);

NTSTATUS
GsspCopyGssStringBufferToClientW(
    gss_buffer_t GssBuffer,
    PVOID *ClientBuffer);

PSecBuffer GsspLocateSecBuffer(
    PSecBufferDesc Buffers,
    ULONG BufferType);
PSecBuffer GsspLocateSecBufferEx(
    PSecBufferDesc Buffers,
    ULONG ulBufferType,
    ULONG ulIndex);

NTSTATUS
GsspStringToLsaString(
    LPCSTR String,
    PLSA_STRING *pLsaString);

NTSTATUS
GsspDuplicateSid(PSID SourceSid, BOOLEAN bLsaAlloc, PSID *pDestSid);

BOOLEAN
GsspIsLocalHost(PUNICODE_STRING HostName);

NTSTATUS
GsspGetLocalHostName(BOOLEAN bLsaAlloc, PUNICODE_STRING HostName);

#if 0
#define GSSP_ASSERT(Condition)     \
    if (!(Condition)) { \
	RtlAssert(#Condition, __FILE__, __LINE__, ""); \
    }
#else
#define GSSP_ASSERT(Condition)      assert((Condition))
#endif

#define GSSEAP_ASSERT(Condition)    GSSP_ASSERT((Condition))

#define GSSP_BAIL_ON_ERROR(Status) \
    do { \
        if ((Status) != STATUS_SUCCESS) { \
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"%ws: Bailing with status %08x", \
                           TEXT(__FUNCTION__), (Status)); \
            goto cleanup; \
        } \
    } while (0)

#define GSSP_BAIL_ON_GSS_ERROR(Major, Minor) \
    do { \
        if (GSS_ERROR((Major))) { \
            Status = GsspMapStatus((Major), (Minor)); \
            goto cleanup; \
        } \
    } while (0)

#define GSSP_BAIL_ON_BAD_OFFSET(StructSize, Offset, Length)  \
    do { \
        if ((Offset) + (Length) > (StructSize)) { \
            GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"%ws: Invalid Offset %d Length %d StructSize %d", \
                           TEXT(__FUNCTION__), (Offset), (Length), (StructSize)); \
            Status = STATUS_BUFFER_TOO_SMALL; \
            goto cleanup; \
        } \
    } while (0)

#define GsspContextLock(Ctx)                                    \
    do {                                                        \
        GSSP_ASSERT(&(Ctx) != NULL);                            \
        GSSEAP_MUTEX_LOCK(&(Ctx)->mutex);                       \
    } while (0)

#define GsspContextUnlock(Ctx)                                  \
    do {                                                        \
        if ((Ctx) != NULL)                                      \
            GSSEAP_MUTEX_UNLOCK(&(Ctx)->mutex);                 \
    } while (0)

#define GsspCredLock(Cred)                  GsspContextLock(Cred)
#define GsspCredUnlock(Cred)                GsspContextUnlock(Cred)

#define GsspProtectCred(GssCred)                                               \
    do {                                                                       \
        if (LsaSpFunctionTable != NULL && (GssCred)->password.value != NULL)   \
            LsaSpFunctionTable->LsaProtectMemory((GssCred)->password.value,    \
                                                 (GssCred)->password.length);  \
    } while (0)

#define GsspUnprotectCred(GssCred)                                             \
    do {                                                                       \
        if (LsaSpFunctionTable != NULL && (GssCred)->password.value != NULL)   \
            LsaSpFunctionTable->LsaUnprotectMemory((GssCred)->password.value,  \
                                                   (GssCred)->password.length);\
    } while (0)

#endif /* !GSSEAP_KERNEL */

#ifdef __cplusplus
}
#endif

#ifndef GSSEAP_KERNEL
#include <gssapiP_eap.h>
#endif /* !GSSEAP_KERNEL */

#endif /* _GSSP_H_ */
