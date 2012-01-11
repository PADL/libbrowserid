/*
 * Ntdll private APIs from MSDN
 *
 * Copyright (c) Microsoft Corporation.
 * All rights reserved.
 */

#ifndef _NTDLL_H_
#define _NTDLL_H_ 1

#ifndef NTDDI_WIN8
/*
 * Experimental support for claims-in-token
 */
#define TokenUserClaimAttributes                33
#define TokenDeviceClaimAttributes              34
#define TokenRestrictedUserClaimAttributes      35
#define TokenRestrictedDeviceClaimAttributes    36

#endif /* !NTDDI_WIN8 */

#include <winternl.h>

typedef UNICODE_STRING LSA_UNICODE_STRING;
typedef PUNICODE_STRING PLSA_UNICODE_STRING;

typedef LONG NTSTATUS, *PNTSTATUS;

#define _NTDEF_ 1

#include <LsaLookup.h>  /* for LSA_OBJECT_ATTRIBUTES */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CLIENT_ID {
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

ULONG __cdecl
DbgPrintEx(
  __in  ULONG ComponentId,
  __in  ULONG Level,
  __in  PCSTR Format,
  ...
);

ULONG __cdecl
vDbgPrintEx(
  __in  ULONG ComponentId,
  __in  ULONG Level,
  __in  PCCH Format,
  __in  va_list arglist
);

NTSTATUS NTAPI
NtAllocateLocallyUniqueId(
  __out  PLUID LUID
);

NTSTATUS NTAPI
NtAdjustGroupsToken(
  __in   HANDLE TokenHandle,
  __in   BOOLEAN ResetToDefault,
  __in   PTOKEN_GROUPS TokenGroups,
  __in   ULONG PreviousGroupsLength,
  __out  PTOKEN_GROUPS PreviousGroups OPTIONAL,
  __out  PULONG RequiredLength OPTIONAL);

NTSTATUS NTAPI
NtQuerySecurityObject(
  __in       HANDLE ObjectHandle,
  __in       SECURITY_INFORMATION SecurityInformationClass,
  __out      PSECURITY_DESCRIPTOR DescriptorBuffer,
  __in       ULONG DescriptorBufferLength,
  __out      PULONG RequiredLength);

NTSTATUS NTAPI
NtSetSecurityObject(
  __in       HANDLE ObjectHandle,
  __in       SECURITY_INFORMATION SecurityInformationClass,
  __in       PSECURITY_DESCRIPTOR DescriptorBuffer);

NTSTATUS NTAPI
NtQueryInformationToken(
  __in   HANDLE TokenHandle,
  __in   TOKEN_INFORMATION_CLASS TokenInformationClass,
  __out  PVOID TokenInformation,
  __in   ULONG TokenInformationLength,
  __out  PULONG ReturnLength
);

NTSTATUS NTAPI
NtSetInformationToken(
  __in   HANDLE TokenHandle,
  __in   TOKEN_INFORMATION_CLASS TokenInformationClass,
  __in   PVOID TokenInformation,
  __in   ULONG TokenInformationLength
);

NTSTATUS NTAPI
NtFilterToken(
  __in   HANDLE ExistingTokenHandle,  
  __in   ULONG Flags,  
  __in   PTOKEN_GROUPS SidsToDisable,  
  __in   PTOKEN_PRIVILEGES PrivilegesToDelete,  
  __in   PTOKEN_GROUPS RestrictedSids,  
  __out  PHANDLE NewTokenHandle
);

NTSTATUS NTAPI
NtOpenProcess(
  __out     PHANDLE ProcessHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
  __in_opt  PCLIENT_ID ClientId
);

NTSTATUS NTAPI
NtOpenProcessToken(
  __in      HANDLE ProcessHandle,
  __in      ACCESS_MASK DesiredAccess,
  __out     PHANDLE TokenHandle);

NTSTATUS NTAPI
NtOpenThread(
  __out  PHANDLE ThreadHandle,
  __in   ACCESS_MASK DesiredAccess,
  __in   PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
  __in   PCLIENT_ID ClientId
);

NTSTATUS NTAPI
NtOpenThreadToken(
  __in      HANDLE ThreadHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      BOOLEAN OpenAsSelf,
  __out     PHANDLE TokenHandle);

#if 0
NTSTATUS NTAPI
RtlUnicodeToUTF8N(
  __out      PCHAR UTF8StringDestination,
  __in       ULONG UTF8StringMaxByteCount,
  __out_opt  PULONG UTF8StringActualByteCount,
  __in       PCWSTR UnicodeStringSource,
  __in       ULONG UnicodeStringWCharCount
);

NTSTATUS NTAPI
RtlUTF8ToUnicodeN(
  __out      PWSTR UnicodeStringDestination,
  __in       ULONG UnicodeStringMaxWCharCount,
  __out_opt  PULONG UnicodeStringActualWCharCount,
  __in       PCCH UTF8StringSource,
  __in       ULONG UTF8StringByteCount
);
#endif

VOID NTAPI
RtlSecondsSince1970ToTime(
  __in   ULONG ElapsedSeconds,
  __out  PLARGE_INTEGER Time
);

NTSTATUS NTAPI
RtlGetDaclSecurityDescriptor(
  __in   PSECURITY_DESCRIPTOR SecurityDescriptor,
  __out  PBOOLEAN DaclPresent,
  __out  PACL *Dacl,
  __out  PBOOLEAN DaclDefaulted
);

NTSTATUS NTAPI
RtlSetDaclSecurityDescriptor(
  __inout   PSECURITY_DESCRIPTOR SecurityDescriptor,
  __in      BOOLEAN DaclPresent,
  __in_opt  PACL Dacl,
  __in_opt  BOOLEAN DaclDefaulted
);

NTSTATUS NTAPI
RtlSetOwnerSecurityDescriptor(
  __inout   PSECURITY_DESCRIPTOR SecurityDescriptor,
  __in_opt  PSID Owner,
  __in_opt  BOOLEAN OwnerDefaulted
);

NTSTATUS NTAPI
RtlSetGroupSecurityDescriptor(
  __inout   PSECURITY_DESCRIPTOR SecurityDescriptor,
  __in_opt  PSID Group,
  __in_opt  BOOLEAN GroupDefaulted
);

ULONG NTAPI
RtlLengthSecurityDescriptor(
  __in  PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSTATUS NTAPI
RtlSelfRelativeToAbsoluteSD(
  __in     PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
  __out    PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
  __inout  PULONG AbsoluteSecurityDescriptorSize,
  __out    PACL Dacl,
  __inout  PULONG DaclSize,
  __out    PACL Sacl,
  __inout  PULONG SaclSize,
  __out    PSID Owner,
  __inout  PULONG OwnerSize,
  __out    PSID PrimaryGroup,
  __inout  PULONG PrimaryGroupSize
);

NTSTATUS NTAPI
RtlSetInformationAcl(
  __in     PACL Acl,
  __in     PVOID Information,
  __in     ULONG InformationLength,
  __in     ACL_INFORMATION_CLASS InformationClass);

NTSTATUS NTAPI
RtlAddAce(
  __inout  PACL Acl,
  __in     ULONG AceRevision,
  __in     ULONG StartingAceIndex,
  __in     PVOID AceList,
  __in     ULONG AceListLength
);

NTSTATUS NTAPI
RtlAddAccessAllowedAce(
  __inout  PACL Acl,
  __in     ULONG AceRevision,
  __in     ACCESS_MASK AccessMask,
  __in     PSID Sid
);

NTSTATUS NTAPI
RtlGetAce(
  __in   PACL Acl,
  __in   ULONG AceIndex,
  __out  PVOID *Ace
);

ULONG NTAPI
RtlLengthRequiredSid(
  __in  ULONG SubAuthorityCount
);

PULONG NTAPI
RtlSubAuthoritySid(
  __in  PSID Sid,
  __in  ULONG SubAuthorityCount
);

ULONG NTAPI
RtlLengthSid(
  __in  PSID Sid
);

NTSTATUS NTAPI
RtlCopySid(
  __in  ULONG DestinationSidLength,
  __in  PSID DestinationSid,
  __in  PSID SourceSid
);

NTSTATUS NTAPI
RtlInitializeSid(
  __out  PSID Sid,
  __in   PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
  __in   UCHAR SubAuthorityCount
);

NTSTATUS NTAPI
RtlConvertSidToUnicodeString(
  __out  PUNICODE_STRING UnicodeString,
  __in   PSID Sid,
  __in   BOOLEAN AllocateDestinationString
);

NTSTATUS NTAPI
RtlGetVersion(
    __inout PRTL_OSVERSIONINFOW  lpVersionInformation
);

/*++

LINK list:

    Definitions for a double link list.

--*/

//
// Calculate the address of the base of the structure given its type, and an
// address of a field within the structure.
//
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif

//
//  VOID
//  InitializeListHead(
//      PLIST_ENTRY ListHead
//      );
//

#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

//
//  BOOLEAN
//  IsListEmpty(
//      PLIST_ENTRY ListHead
//      );
//

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

//
//  PLIST_ENTRY
//  RemoveHeadList(
//      PLIST_ENTRY ListHead
//      );
//

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

//
//  PLIST_ENTRY
//  RemoveTailList(
//      PLIST_ENTRY ListHead
//      );
//

#define RemoveTailList(ListHead) \
    (ListHead)->Blink;\
    {RemoveEntryList((ListHead)->Blink)}

//
//  VOID
//  RemoveEntryList(
//      PLIST_ENTRY Entry
//      );
//

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

//
//  VOID
//  InsertTailList(
//      PLIST_ENTRY ListHead,
//      PLIST_ENTRY Entry
//      );
//

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

//
//  VOID
//  InsertHeadList(
//      PLIST_ENTRY ListHead,
//      PLIST_ENTRY Entry
//      );
//

#define InsertHeadList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Flink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Flink = _EX_ListHead->Flink;\
    (Entry)->Flink = _EX_Flink;\
    (Entry)->Blink = _EX_ListHead;\
    _EX_Flink->Blink = (Entry);\
    _EX_ListHead->Flink = (Entry);\
    }

BOOL IsNodeOnList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);

#ifdef __cplusplus
}
#endif

#endif /* _NTDLL_H_ */
