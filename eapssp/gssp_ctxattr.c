/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Context attributes
 */

#include "gssp.h"

static NTSTATUS
GsspQueryContextSizes(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    PSecPkgContext_Sizes Sizes = (PSecPkgContext_Sizes)Buffer;
    gss_iov_buffer_desc Iov[2];

    RtlZeroMemory(Sizes, sizeof(*Sizes));

    Sizes->cbMaxToken = EAPSSP_MAX_TOKEN_SIZE;
    Sizes->cbBlockSize = 1;

    /* Signature length with no confidentiality */
    Iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    Iov[0].buffer.value = NULL;
    Iov[0].buffer.length = 0;

    Major = gssEapWrapIovLength(&Minor, GssContext, FALSE,
                                GSS_C_QOP_DEFAULT, NULL, Iov, 1);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Sizes->cbMaxSignature = Iov[0].buffer.length;

    /* Signature length with confidentiality */
    Iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    Iov[0].buffer.value = NULL;
    Iov[0].buffer.length = 0;

    /* Include some data so it is not treated as sign-only */
    Iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    Iov[1].buffer.value = "";
    Iov[1].buffer.length = 1;

    Major = gssEapWrapIovLength(&Minor, GssContext, TRUE,
                                GSS_C_QOP_DEFAULT, NULL, Iov, 2);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Sizes->cbSecurityTrailer = Iov[0].buffer.length;

    Status = STATUS_SUCCESS;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspQueryContextSizes: cbMaxToken %08x cbBlockSize %08x "
                   L"cbMaxSignature %08x cbSecurityTrailer %08x",
                   Sizes->cbMaxToken, Sizes->cbBlockSize,
                   Sizes->cbMaxSignature, Sizes->cbSecurityTrailer);

cleanup:
    return Status;
}

static NTSTATUS
GsspQueryContextNames(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_Names Names = (PSecPkgContext_Names)Buffer;
    NTSTATUS Status = SEC_E_NO_CONTEXT;

    if (CTX_IS_INITIATOR(GssContext)) {
        if (GssContext->initiatorName != GSS_C_NO_NAME)
            Status = GsspDisplayGssNameW(GssContext->initiatorName,
                                         TRUE, &Names->sUserName);
    } else {
        if (GssContext->AccountName.Length != 0) {
            UNICODE_STRING UnicodeString;

            Status = GsspDuplicateUnicodeString(&GssContext->AccountName,
                                                TRUE, &UnicodeString);

            Names->sUserName = UnicodeString.Buffer;
        }
    }

    if (Status != SEC_E_OK) {
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                       L"GsspQueryContextNames: no initiator name for context");
    }

    return Status;
}

static NTSTATUS
GsspQueryContextLifespan(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_Lifespan Lifespan = (PSecPkgContext_Lifespan)Buffer;

    Lifespan->tsStart.LowPart  = 0;
    Lifespan->tsStart.HighPart = 0;
    GsspMapTime(GssContext->expiryTime, &Lifespan->tsExpiry);

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspQueryContextDceInfo(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_DceInfo DceInfo = (PSecPkgContext_DceInfo)Buffer;

    DceInfo->AuthzSvc = 1; /* RPC_C_AUTHZ_NAME */

    return GsspDisplayGssNameW(GssContext->initiatorName, TRUE, (PWSTR *)&DceInfo->pPac);
}

static OM_uint32
GsspEnctypeToString(
    ULONG EncryptionType,
    BOOLEAN bTruncateEnc,
    ULONG *KeySizeBits,
    PWSTR *pEncryptionAlgorithmName)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    krb5_context KrbContext;
    gss_buffer_desc LongName;
    gss_buffer_desc Name = GSS_C_EMPTY_BUFFER;
    ULONG i, cHyphen = 0, iHyphen = 0;

    *pEncryptionAlgorithmName = NULL,

    Major = gssEapKerberosInit(&Minor, &KrbContext);
    if (GSS_ERROR(Major))
        return GsspMapStatus(Major, Minor);

    if (KeySizeBits != NULL) {
        size_t KeySize;

        Minor = krb5_enctype_keysize(KrbContext, EncryptionType, &KeySize);
        if (Minor == 0)
            *KeySizeBits = KeySize * 8;
    }

    Minor = krbEnctypeToString(KrbContext, EncryptionType,
                               bTruncateEnc ? NULL : "EAP ", &LongName);
    if (GSS_ERROR(Major))
        return GsspMapStatus(Major, Minor);

    for (i = 0; i < LongName.length; i++) {
        PSTR p = ((PSTR)LongName.value) + i;

        *p = toupper(*p);
        if (bTruncateEnc) {
            if (*p == '-')
                cHyphen++;
            if (iHyphen == 0 && cHyphen == 2)
                iHyphen = i + 1;
        }
    }

    if (iHyphen) {
        Name.value = ((PSTR)LongName.value) + iHyphen;
        Name.length = LongName.length - iHyphen;
    } else
        Name = LongName;

    Status = GsspGssBufferToWideString(&Name, TRUE,
                                       pEncryptionAlgorithmName, NULL);

    GsspReleaseBuffer(&Minor, &LongName);

    return Status;
}

static NTSTATUS
GsspQueryContextKeyInfo(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    PSecPkgContext_KeyInfo KeyInfo = (PSecPkgContext_KeyInfo)Buffer;

    Status = GsspEnctypeToString(GssContext->encryptionType, TRUE, NULL,
                                 &KeyInfo->sSignatureAlgorithmName);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspEnctypeToString(GssContext->encryptionType, FALSE,
                                 &KeyInfo->KeySize,
                                 &KeyInfo->sEncryptAlgorithmName);
    GSSP_BAIL_ON_ERROR(Status);

    KeyInfo->SignatureAlgorithm = GssContext->checksumType;
    KeyInfo->EncryptAlgorithm = GssContext->encryptionType;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspQueryContextKeyInfo: SigAlg %s[%d] EncAlg %s[%d] KeySize %d",
                   KeyInfo->sSignatureAlgorithmName, KeyInfo->SignatureAlgorithm,
                   KeyInfo->sEncryptAlgorithmName, KeyInfo->EncryptAlgorithm,
                   KeyInfo->KeySize);

cleanup:
    return Status;
}

static NTSTATUS
GsspQueryContextSessionKey(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    PSecPkgContext_SessionKey SessionKey = (PSecPkgContext_SessionKey)Buffer;

    if (GssContext->encryptionType == ENCTYPE_NULL) {
        Status = SEC_E_NO_KERB_KEY;
        GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"GsspQueryContextSessionKey: no session key");
        goto cleanup;
    }

    Status = GsspLsaAlloc(KRB_KEY_LENGTH(&GssContext->rfc3961Key), (PVOID *)&SessionKey->SessionKey);
    GSSP_BAIL_ON_ERROR(Status);

    SessionKey->SessionKeyLength = KRB_KEY_LENGTH(&GssContext->rfc3961Key);

    RtlCopyMemory(SessionKey->SessionKey, KRB_KEY_DATA(&GssContext->rfc3961Key), SessionKey->SessionKeyLength);

cleanup:
    return Status;
}

USHORT
GsspQueryPackageRpcId(PSecPkgInfo PkgInfo)
{
    USHORT wRPCID;

    /*
     * This workaround is necessary for unpatched Exchange interop.
     */
    if (GsspFlags & GSSP_FLAG_FORCE_KERB_RPCID)
        wRPCID = RPC_C_AUTHN_GSS_KERBEROS;
    else
        wRPCID = PkgInfo->wRPCID;

    return wRPCID;
}

static NTSTATUS
GsspQueryContextPackageInfo(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    PSecPkgContext_PackageInfo PackageInfo = (PSecPkgContext_PackageInfo)Buffer;
    SecPkgInfo PkgInfo;
    DWORD cbPkgName;
    DWORD cbPkgComment;

    Status = GsspGetInfo(GssContext->mechanismUsed, &PkgInfo);
    GSSP_BAIL_ON_ERROR(Status);

    cbPkgName    = wcslen(PkgInfo.Name) + sizeof(WCHAR);
    cbPkgComment = wcslen(PkgInfo.Comment) + sizeof(WCHAR);

    /* return elements as a single contiguous buffer */
    Status = GsspLsaCalloc(1, sizeof(PkgInfo) + cbPkgName + cbPkgComment,
                           &PackageInfo->PackageInfo);
    GSSP_BAIL_ON_ERROR(Status);

    PackageInfo->PackageInfo->fCapabilities = PkgInfo.fCapabilities;
    PackageInfo->PackageInfo->wVersion      = PkgInfo.wVersion;
    PackageInfo->PackageInfo->wRPCID        = GsspQueryPackageRpcId(&PkgInfo);
    PackageInfo->PackageInfo->cbMaxToken    = PkgInfo.cbMaxToken;
    PackageInfo->PackageInfo->Name          =
        (PWSTR)((PUCHAR)PackageInfo->PackageInfo + sizeof(SecPkgInfo));
    RtlCopyMemory(PackageInfo->PackageInfo->Name, PkgInfo.Name, cbPkgName);

    PackageInfo->PackageInfo->Comment       =
        (PWSTR)((PUCHAR)PackageInfo->PackageInfo + sizeof(SecPkgInfo) + cbPkgName);
    RtlCopyMemory(PackageInfo->PackageInfo->Comment, PkgInfo.Comment, cbPkgComment);

cleanup:
    if (Status != STATUS_SUCCESS) {
        if (PackageInfo->PackageInfo != NULL) {
            GsspFree(PackageInfo->PackageInfo->Name);
            GsspFree(PackageInfo->PackageInfo->Comment);
            GsspFree(PackageInfo->PackageInfo);
            PackageInfo->PackageInfo = NULL;
        }
    }

    return Status;
}

static NTSTATUS
GsspQueryContextUserFlags(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_UserFlags UserFlags = (PSecPkgContext_UserFlags)Buffer;

    UserFlags->UserFlags = GssContext->UserFlags;

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspQueryContextFlags(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_Flags Flags = (PSecPkgContext_Flags)Buffer;

    Flags->Flags = GsspMapFlags(GssContext->gssFlags,
                                CTX_IS_INITIATOR(GssContext));

    return STATUS_SUCCESS;
}

static NTSTATUS
GsspQueryContextNativeNames(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    PSecPkgContext_NativeNames NativeNames = (PSecPkgContext_NativeNames)Buffer;

    Status = GsspDisplayGssNameW(GssContext->initiatorName, TRUE, &NativeNames->sClientName);
    GSSP_BAIL_ON_ERROR(Status);

    Status = GsspDisplayGssNameW(GssContext->acceptorName, TRUE, &NativeNames->sServerName);
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    return Status;
}

static NTSTATUS
GsspQueryContextCredentialName(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status = SEC_E_INTERNAL_ERROR;
    PSecPkgContext_CredentialName CredentialName = (PSecPkgContext_CredentialName)Buffer;

    CredentialName->CredentialType = CRED_TYPE_DOMAIN_PASSWORD;
    CredentialName->sCredentialName = NULL;

    if (GssContext->cred != GSS_C_NO_CREDENTIAL) {
        Status = GsspDisplayGssNameW(GssContext->cred->name, TRUE, &CredentialName->sCredentialName);
        GSSP_BAIL_ON_ERROR(Status);
    }

cleanup:
    return Status;
}

static NTSTATUS
GsspQueryContextNegotiationInfo(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    NTSTATUS Status;
    PSecPkgContext_NegotiationInfo NegotiationInfo = (PSecPkgContext_NegotiationInfo)Buffer;

    switch (GssContext->state) {
    case GSSEAP_STATE_ESTABLISHED:
        NegotiationInfo->NegotiationState = SECPKG_NEGOTIATION_COMPLETE;
        break;
    case GSSEAP_STATE_MECHLIST_MIC:
        NegotiationInfo->NegotiationState = SECPKG_NEGOTIATION_IN_PROGRESS;
        break;
    default:
        NegotiationInfo->NegotiationState = SECPKG_NEGOTIATION_OPTIMISTIC;
        break;
    }

    Status = GsspQueryContextPackageInfo(GssContext,
                                         SECPKG_ATTR_PACKAGE_INFO,
                                         &NegotiationInfo->PackageInfo);

    return Status;
}

static NTSTATUS
GsspQueryContextAccessToken(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_AccessToken AccessToken = (PSecPkgContext_AccessToken)Buffer;

    /* Not duplicated according to the MSDN documentation. */
    if (GssContext->TokenHandle == NULL)
        return SEC_E_NO_IMPERSONATION;

    AccessToken->AccessToken = GssContext->TokenHandle;

    return SEC_E_OK;
}

static NTSTATUS
GsspQueryContextClientSpecifiedTarget(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_ClientSpecifiedTarget Target = (PSecPkgContext_ClientSpecifiedTarget)Buffer;

    return GsspDisplayGssNameW(GssContext->acceptorName, TRUE, &Target->sTargetName);
}

static NTSTATUS
GsspQueryContextLastClientTokenStatus(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_LastClientTokenStatus LCT = (PSecPkgContext_LastClientTokenStatus)Buffer;

    switch (GssContext->state) {
    case GSSEAP_STATE_MECHLIST_MIC:
    case GSSEAP_STATE_ESTABLISHED:
        LCT->LastClientTokenStatus = SecPkgAttrLastClientTokenYes;
        break;
    case GSSEAP_STATE_ACCEPTOR_EXTS:
        LCT->LastClientTokenStatus = SecPkgAttrLastClientTokenMaybe;
        break;
    default:
        LCT->LastClientTokenStatus = SecPkgAttrLastClientTokenNo;
        break;
    }

    return STATUS_SUCCESS;
}

static struct _GSS_CONTEXT_ATTRIBUTE_FUNCTION_TABLE {
    ULONG Attribute;
    NTSTATUS (*Query)(gss_ctx_id_t, ULONG, PVOID);
} GsspContextAttributes[] = {
    { SECPKG_ATTR_SIZES,                        GsspQueryContextSizes               },
    { SECPKG_ATTR_NAMES,                        GsspQueryContextNames               },
    { SECPKG_ATTR_LIFESPAN,                     GsspQueryContextLifespan            },
    { SECPKG_ATTR_DCE_INFO,                     GsspQueryContextDceInfo             },
    { SECPKG_ATTR_KEY_INFO,                     GsspQueryContextKeyInfo             },
#if 0
    { SECPKG_ATTR_AUTHORITY,                    GsspQueryContextAuthority           },
    { SECPKG_ATTR_PROTO_INFO,                   GsspQueryContextProtoInfo           },
    { SECPKG_ATTR_PASSWORD_EXPIRY,              GsspQueryContextPasswordExpiry      },
#endif
    { SECPKG_ATTR_SESSION_KEY,                  GsspQueryContextSessionKey          },
    { SECPKG_ATTR_PACKAGE_INFO,                 GsspQueryContextPackageInfo         },
    { SECPKG_ATTR_USER_FLAGS,                   GsspQueryContextUserFlags           },
    { SECPKG_ATTR_NEGOTIATION_INFO,             GsspQueryContextNegotiationInfo     },
    { SECPKG_ATTR_NATIVE_NAMES,                 GsspQueryContextNativeNames         },
    { SECPKG_ATTR_FLAGS,                        GsspQueryContextFlags               },
    { SECPKG_ATTR_CREDENTIAL_NAME,              GsspQueryContextCredentialName      },
#if 0
    { SECPKG_ATTR_USE_VALIDATED,                GsspQueryContextUseValidated        },
    { SECPKG_ATTR_TARGET_INFORMATION,           GsspQueryContextTargetInformation   },
#endif
    { SECPKG_ATTR_ACCESS_TOKEN,                 GsspQueryContextAccessToken         },
#if 0
    { SECPKG_ATTR_TARGET,                       GsspQueryContextTarget              },
    { SECPKG_ATTR_AUTHENTICATION_ID,            GsspQueryContextAuthenticationId    },
    { SECPKG_ATTR_LOGOFF_TIME,                  GsspQueryContextLogoffTime          },
#endif
    { SECPKG_ATTR_NEGO_KEYS,                    GsspQueryContextNegoKeys            },
    { SECPKG_ATTR_PROMPTING_NEEDED,             GsspQueryContextCredInfo            },
#if 0
    { SECPKG_ATTR_UNIQUE_BINDINGS,              GsspQueryContextUniqueBindings      },
    { SECPKG_ATTR_ENDPOINT_BINDINGS,            GsspQueryContextEndpointBindings    },
#endif
    { SECPKG_ATTR_CLIENT_SPECIFIED_TARGET,      GsspQueryContextClientSpecifiedTarget },
#if 0
    { SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS,     GsspQueryContextLastClientTokenStatus },
    { SECPKG_ATTR_NEGO_PKG_INFO,                GsspQueryContextNegoPackageInfo     },
    { SECPKG_ATTR_NEGO_STATUS,                  GsspQueryContextNegoStatus          },
    { SECPKG_ATTR_CONTEXT_DELETED,              GsspQueryContextDeleted             },
#endif
#ifdef GSSEAP_ENABLE_ACCEPTOR
    { SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES,  GsspQuerySubjectSecurityAttributes  },
#endif
};

NTSTATUS
GsspQueryContextAttributes(
    IN gss_ctx_id_t ContextHandle,
    IN ULONG ContextAttribute,
    IN OUT PVOID Buffer)
{
    NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;
    ULONG i;

    if (ContextHandle == GSS_C_NO_CONTEXT)
        return STATUS_INVALID_HANDLE;

    GsspContextAddRefAndLock(ContextHandle);

    for (i = 0; i < sizeof(GsspContextAttributes) / sizeof(GsspContextAttributes[0]); i++) {
        struct _GSS_CONTEXT_ATTRIBUTE_FUNCTION_TABLE *p = &GsspContextAttributes[i];

        if (p->Attribute == ContextAttribute) {
            Status = p->Query(ContextHandle, ContextAttribute, Buffer);
            break;
        }
    }

cleanup:
    GsspContextUnlockAndRelease(ContextHandle);

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"GsspQueryContextAttributes: Attribute %08x Status %08x",
                   ContextAttribute, Status);

    return Status;
}

NTSTATUS
GsspSetContextAttributes(
    IN gss_ctx_id_t ContextHandle,
    IN ULONG ContextAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize)
{
    NTSTATUS Status;

    if (ContextHandle == GSS_C_NO_CONTEXT)
        return STATUS_INVALID_HANDLE;

    GsspContextAddRefAndLock(ContextHandle);

    switch (ContextAttribute) {
    case SECPKG_ATTR_CONTEXT_DELETED:
        ContextHandle->flags |= CTX_FLAG_DELETED;
        Status = STATUS_SUCCESS;
        break;
    default:
        Status = SEC_E_UNSUPPORTED_FUNCTION;
        break;
    }

cleanup:
    GsspContextUnlockAndRelease(ContextHandle);

#if 0
    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE, L"GsspSetContextAttributes: Attribute %08x Status %08x",
                   ContextAttribute, Status);
#endif

    return Status;
}
