/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * GSS-to-SSPI mapping layer
 */

#include "gssp.h"

static TimeStamp TsIndefinite = { 0xFFFFFFFF, 0x7FFFFFFF };
static TimeStamp TsEpoch;

void GsspMapTime(time_t GssTime, TimeStamp *ts)
{
    if (GssTime == 0 || GssTime == GSS_C_INDEFINITE)
        *ts = TsIndefinite;
    else
        RtlSecondsSince1970ToTime(GssTime, ts);
}

static struct _GSS_SSPI_FLAG_MAP {
    OM_uint32 GssFlag;
    ULONG SspiIscFlag;
    ULONG SspiAscFlag;
} GssSspiFlagMap[] = {
    {
        GSS_C_DELEG_FLAG,   
        ISC_REQ_DELEGATE,
        ASC_REQ_DELEGATE,
    },
    {
        GSS_C_MUTUAL_FLAG,
        ISC_REQ_MUTUAL_AUTH,
        ASC_REQ_MUTUAL_AUTH,
    },
    {
        GSS_C_REPLAY_FLAG,
        ISC_REQ_REPLAY_DETECT,
        ASC_REQ_REPLAY_DETECT
    },
    {
        GSS_C_SEQUENCE_FLAG,
        ISC_REQ_SEQUENCE_DETECT,
        ASC_REQ_SEQUENCE_DETECT,
    },
    {
        GSS_C_CONF_FLAG,
        ISC_REQ_CONFIDENTIALITY,
        ASC_REQ_CONFIDENTIALITY
    },
    {
        GSS_C_INTEG_FLAG,
        ISC_REQ_INTEGRITY,
        ASC_REQ_INTEGRITY
    },
    {
        GSS_C_ANON_FLAG,
        ISC_REQ_NULL_SESSION,
        0
    },
    {
        GSS_C_DCE_STYLE,
        ISC_REQ_USE_DCE_STYLE,
        ASC_REQ_USE_DCE_STYLE
    },
    {
        GSS_C_IDENTIFY_FLAG,
        ISC_REQ_IDENTIFY,
        ASC_REQ_IDENTIFY
    },
    {
        GSS_C_EXTENDED_ERROR_FLAG,
        ISC_REQ_EXTENDED_ERROR,
        ASC_REQ_EXTENDED_ERROR
    },
    /* private */
    {
        GSS_C_ALLOW_MISSING_BINDINGS,
        0,
        ASC_REQ_ALLOW_MISSING_BINDINGS
    },
};

ULONG
GsspMapFlags(OM_uint32 GssFlags, BOOLEAN IsInitiator)
{
    ULONG SspiFlags = 0;
    ULONG i;

    for (i = 0; i < sizeof(GssSspiFlagMap) / sizeof(GssSspiFlagMap[0]); i++) {
        struct _GSS_SSPI_FLAG_MAP *MapEntry = &GssSspiFlagMap[i];
        ULONG SspiFlag;

        if (IsInitiator)
            SspiFlag = MapEntry->SspiIscFlag;
        else
            SspiFlag = MapEntry->SspiAscFlag;

        if (SspiFlag && (GssFlags & MapEntry->GssFlag))
            SspiFlags |= SspiFlag;
    }

    return SspiFlags;
}

OM_uint32
GsspUnmapFlags(ULONG SspiFlags, BOOLEAN IsInitiator)
{
    OM_uint32 GssFlags = 0;
    ULONG i;

    for (i = 0; i < sizeof(GssSspiFlagMap) / sizeof(GssSspiFlagMap[0]); i++) {
        struct _GSS_SSPI_FLAG_MAP *MapEntry = &GssSspiFlagMap[i];
        ULONG SspiFlag;

        if (IsInitiator)
            SspiFlag = MapEntry->SspiIscFlag;
        else
            SspiFlag = MapEntry->SspiAscFlag;

        if (SspiFlag && (SspiFlags & SspiFlag))
            GssFlags |= MapEntry->GssFlag;
    }

    return GssFlags;
}

ULONG
GsspMapCredUsage(gss_cred_usage_t GssUsage)
{
    ULONG SspiUsage = SECPKG_CRED_DEFAULT;

    switch (GssUsage) {
    case GSS_C_BOTH:
        SspiUsage = SECPKG_CRED_BOTH;
        break;
    case GSS_C_INITIATE:
        SspiUsage = SECPKG_CRED_OUTBOUND;
        break;
    case GSS_C_ACCEPT:
        SspiUsage = SECPKG_CRED_INBOUND;
        break;
    }

    return SspiUsage;
}

gss_cred_usage_t
GsspUnmapCredUsage(ULONG SspiUsage)
{
    gss_cred_usage_t GssUsage = SECPKG_CRED_DEFAULT;

    switch (SspiUsage & ~(SECPKG_CRED_RESERVED)) {
    case SECPKG_CRED_BOTH:
        GssUsage = GSS_C_BOTH;
        break;
    case SECPKG_CRED_INBOUND:
        GssUsage = GSS_C_ACCEPT;
        break;
    case SECPKG_CRED_OUTBOUND:
    default:
        GssUsage = GSS_C_INITIATE;
        break;
    }

    return GssUsage;
}

#define IS_KRB_ERROR(err)            ((err) >= ERROR_TABLE_BASE_krb5 && \
                                      (err) <= ERROR_TABLE_BASE_krb5 + 181)

ULONG
GsspMapStatus(OM_uint32 Major, OM_uint32 Minor)
{
    NTSTATUS Status = SEC_E_INTERNAL_ERROR;
    BOOLEAN bUserMode = (LsaSpFunctionTable == NULL);

    switch (Major) {
    case GSS_S_BAD_MECH:
        Status = SEC_E_SECPKG_NOT_FOUND;
        break;
    case GSS_S_BAD_NAME:
        Status = SEC_E_WRONG_PRINCIPAL; /* XXX */
        break;
    case GSS_S_BAD_NAMETYPE:
    case GSS_S_NAME_NOT_MN:
    case GSS_S_BAD_MECH_ATTR:
        Status = SEC_E_INVALID_PARAMETER;
        break;
    case GSS_S_BAD_BINDINGS:
        Status = SEC_E_BAD_BINDINGS;
        break;
    case GSS_S_BAD_STATUS:
        Status = SEC_E_INTERNAL_ERROR;
        break;
    case GSS_S_BAD_SIG:
        Status = SEC_E_MESSAGE_ALTERED;
        break;
    case GSS_S_NO_CRED:
        Status = SEC_E_NO_CREDENTIALS;
        break;
    case GSS_S_NO_CONTEXT:
        Status = SEC_E_NO_CONTEXT;
        break;
    case GSS_S_DEFECTIVE_TOKEN:
        Status = SEC_E_INVALID_TOKEN;
        break;
    case GSS_S_DUPLICATE_TOKEN:
    case GSS_S_UNSEQ_TOKEN:
    case GSS_S_GAP_TOKEN:
    case GSS_S_OLD_TOKEN:
        Status = SEC_E_OUT_OF_SEQUENCE;
        break;
    case GSS_S_DEFECTIVE_CREDENTIAL:
        Status = SEC_E_LOGON_DENIED;
        break;
    case GSS_S_CREDENTIALS_EXPIRED:
        Status = SEC_E_CONTEXT_EXPIRED;
        break;
    case GSS_S_FAILURE: /* and GSS_S_CRED_UNAVAIL */
        if (Minor == ENOMEM) {
            Status = bUserMode ?
                     SEC_E_INSUFFICIENT_MEMORY : STATUS_INSUFFICIENT_RESOURCES;
        } else if (Minor == EINVAL) {
            Status = bUserMode ?
                     SEC_E_INVALID_PARAMETER : STATUS_INVALID_PARAMETER;
        } else if (Minor == GSSEAP_NO_DEFAULT_CRED) {
            Status = SEC_E_NO_CREDENTIALS;
        } else if (IS_KRB_ERROR(Minor)) {
            Status = SEC_E_ENCRYPT_FAILURE;
        } else if (IS_RADIUS_ERROR(Minor)) {
            Status = SEC_E_NO_AUTHENTICATING_AUTHORITY;
        } else {
            Status = SEC_E_INTERNAL_ERROR;
        }
        break;
    case GSS_S_BAD_QOP:
        Status = SEC_E_QOP_NOT_SUPPORTED;
        break;
    case GSS_S_UNAUTHORIZED:
        Status = SEC_E_LOGON_DENIED;
        break;
    case GSS_S_UNAVAILABLE:
        switch (Minor) {
        case GSSEAP_KEY_UNAVAILABLE:
            Status = SEC_E_NO_KERB_KEY;
            break;
        default:
            Status = SEC_E_UNSUPPORTED_FUNCTION;
            break;
        }
        break;
    case GSS_S_CONTINUE_NEEDED:
        Status = SEC_I_CONTINUE_NEEDED;
        break;
    case GSS_S_COMPLETE:
        Status = SEC_E_OK;
        break;
    case GSS_S_DUPLICATE_ELEMENT:
    default:
        break;
    }

    return Status;
}

NTSTATUS
GsspCopyGssNameToClient(gss_name_t GssName, PVOID ClientBuffer)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_buffer_desc NameBuffer = GSS_C_EMPTY_BUFFER;

    Major = gssEapDisplayName(&Minor, GssName, &NameBuffer, NULL);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = GsspCopyGssStringBufferToClientW(&NameBuffer, ClientBuffer);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    Status = STATUS_SUCCESS;

cleanup:
    GsspReleaseBuffer(&Minor, &NameBuffer);

    return Status;
}

NTSTATUS
GsspDisplayGssNameW(
    gss_name_t GssName,
    BOOLEAN bLsaAlloc,
    PWSTR *pwszGssName)
{
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;

    Status = GsspDisplayGssNameUnicodeString(GssName, bLsaAlloc, &UnicodeString);
    if (Status == STATUS_SUCCESS)
        *pwszGssName = UnicodeString.Buffer;

    return Status;
}

NTSTATUS
GsspDisplayGssNameUnicodeString(
    gss_name_t GssName,
    BOOLEAN bLsaAlloc,
    PUNICODE_STRING UnicodeString)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor;
    gss_buffer_desc NameBuffer = GSS_C_EMPTY_BUFFER;

    RtlInitUnicodeString(UnicodeString, NULL);

    if (GssName != GSS_C_NO_NAME) {
        Major = gssEapDisplayName(&Minor, GssName, &NameBuffer, NULL);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

        Status = GsspGssBufferToUnicodeString(&NameBuffer, bLsaAlloc, UnicodeString);
        GSSP_BAIL_ON_ERROR(Status);
    } else {
        Status = STATUS_SUCCESS;
    }

cleanup:
    GsspReleaseBuffer(&Minor, &NameBuffer);

    return Status;
}

OM_uint32
gssEapImportNameW(
    OM_uint32 *Minor,
    PWSTR InputNameBuffer,
    const gss_OID InputNameType,
    const gss_OID InputMechType,
    gss_name_t *pOutputName)
{
    UNICODE_STRING UnicodeString;

    RtlInitUnicodeString(&UnicodeString, InputNameBuffer);

    return gssEapImportNameUnicodeString(Minor, &UnicodeString, InputNameType,
                                         InputMechType, pOutputName);
}

OM_uint32
gssEapImportNameUnicodeString(
    OM_uint32 *Minor,
    PUNICODE_STRING InputNameBuffer,
    const gss_OID InputNameType,
    const gss_OID InputMechType,
    gss_name_t *pOutputName)
{
    NTSTATUS Status;
    gss_buffer_desc GssBuffer = GSS_C_EMPTY_BUFFER;
    OM_uint32 Major, TmpMinor;

    *pOutputName = GSS_C_NO_NAME;

    Status = GsspUnicodeStringToGssBuffer(InputNameBuffer, &GssBuffer);
    if (Status != STATUS_SUCCESS) {
        *Minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    Major = gssEapImportName(Minor, &GssBuffer, InputNameType, InputMechType, pOutputName);

    GsspReleaseBuffer(&TmpMinor, &GssBuffer);

    return Major;
}

NTSTATUS
GsspImportNameUnicodeString(
    PUNICODE_STRING InputName,
    gss_name_t *pOutputName)
{
    OM_uint32 Major, Minor;

    Major = gssEapImportNameUnicodeString(&Minor, InputName,
                                          GSS_C_NT_USER_NAME, GSS_C_NO_OID,
                                          pOutputName);

    return GsspMapStatus(Major, Minor);
}

NTSTATUS
GsspImportNameW(PWSTR InputName, gss_name_t *pOutputName)
{
    OM_uint32 Major, Minor;

    Major = gssEapImportNameW(&Minor, InputName, GSS_C_NT_USER_NAME, GSS_C_NO_OID, pOutputName);

    return GsspMapStatus(Major, Minor);
}

NTSTATUS
GsspGetGssTokenBuffer(
    PSecBufferDesc Buffers,
    gss_buffer_t GssTokenBuffer)
{
    PSecBuffer TokenBuffer = GsspLocateSecBuffer(Buffers, SECBUFFER_TOKEN);

    if (TokenBuffer == NULL)
        return SEC_E_INVALID_TOKEN;

    GsspSecBufferToGssBuffer(TokenBuffer, GssTokenBuffer);

    return STATUS_SUCCESS;
}

NTSTATUS
GsspGetGssChannelBindings(
    PSecBufferDesc Buffers,
    gss_channel_bindings_t GssChannelBindings)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PSecBuffer CBBuffer;

    CBBuffer = GsspLocateSecBuffer(Buffers, SECBUFFER_CHANNEL_BINDINGS);

    RtlZeroMemory(GssChannelBindings, sizeof(*GssChannelBindings));

    if (CBBuffer != NULL) {
        PSEC_CHANNEL_BINDINGS CB = (PSEC_CHANNEL_BINDINGS)CBBuffer->pvBuffer;

        if (CBBuffer->cbBuffer < sizeof(*CB)) {
            Status = SEC_E_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        /* XXX non-application data is ignored, because GSS EAP ignores it */

        GSSP_BAIL_ON_BAD_OFFSET(CBBuffer->cbBuffer,
                                CB->dwApplicationDataOffset,
                                CB->cbApplicationDataLength);

        GssChannelBindings->application_data.length = CB->cbApplicationDataLength;
        GssChannelBindings->application_data.value = (PUCHAR)CB + CB->dwApplicationDataOffset;
    }

cleanup:
    return Status;
}

NTSTATUS
GsspSecBuffersToIov(
    PSecBufferDesc Buffers,
    gss_iov_buffer_t *pIov,
    BOOLEAN bWrapOrGetMIC)
{
    NTSTATUS Status;
    gss_iov_buffer_t Iov;
    ULONG i;
    gss_iov_buffer_t StreamIov = GSS_C_NO_IOV_BUFFER;
    gss_iov_buffer_t DataIov = GSS_C_NO_IOV_BUFFER;

    *pIov = NULL;

    if (Buffers->ulVersion != SECBUFFER_VERSION)
        return SEC_E_INVALID_PARAMETER;

    GsspDebugTrace(WINEVENT_LEVEL_VERBOSE,
                   L"GsspSecBuffersToIov: cBuffers %d", Buffers->cBuffers);

    Status = GsspCalloc(Buffers->cBuffers,
                        sizeof(gss_iov_buffer_desc), (PVOID *)&Iov);
    GSSP_BAIL_ON_ERROR(Status);

    for (i = 0; i < Buffers->cBuffers; i++) {
        PSecBuffer Buffer = &Buffers->pBuffers[i];
        gss_iov_buffer_t GssBuffer = &Iov[i];

        GsspSecBufferToGssBuffer(Buffer, &GssBuffer->buffer);

        switch (Buffer->BufferType & ~(SECBUFFER_ATTRMASK)) {
        case SECBUFFER_DATA:
            if (Buffer->BufferType & SECBUFFER_READONLY_WITH_CHECKSUM) {
                GssBuffer->type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
            } else if (Buffer->BufferType & SECBUFFER_READONLY) {
                GssBuffer->type = GSS_IOV_BUFFER_TYPE_EMPTY;
            } else {
                GssBuffer->type = GSS_IOV_BUFFER_TYPE_DATA;
                if (DataIov == GSS_C_NO_IOV_BUFFER)
                    DataIov = GssBuffer; /* first stream output buffer */
            }
            break;
        case SECBUFFER_TOKEN:
            if (bWrapOrGetMIC && (Buffer->BufferType & SECBUFFER_READONLY)) {
                Status = SEC_E_INVALID_TOKEN;
                goto cleanup;
            }
            GssBuffer->type = GSS_IOV_BUFFER_TYPE_HEADER;
            break;
        case SECBUFFER_PKG_PARAMS:
            GssBuffer->type = GSS_IOV_BUFFER_TYPE_MECH_PARAMS;
            break;
        case SECBUFFER_PADDING:
            if (Buffer->BufferType & SECBUFFER_READONLY)
                GssBuffer->type = GSS_IOV_BUFFER_TYPE_EMPTY;
            else
                GssBuffer->type = GSS_IOV_BUFFER_TYPE_PADDING;
            break;
        case SECBUFFER_STREAM:
            GssBuffer->type = GSS_IOV_BUFFER_TYPE_STREAM;
            StreamIov = GssBuffer;
            break;
        case SECBUFFER_EMPTY:
        default:
            GssBuffer->type = GSS_IOV_BUFFER_TYPE_EMPTY;
            break;
        }

        if (Buffer->BufferType & SECBUFFER_UNMAPPED) {
            Status = GsspLsaAlloc(GssBuffer->buffer.length, &GssBuffer->buffer.value);
            GSSP_BAIL_ON_ERROR(Status);
            
            Status = LsaSpFunctionTable->CopyFromClientBuffer(NULL,
                   GssBuffer->buffer.length,
                   GssBuffer->buffer.value,
                   Buffer->pvBuffer);
            GSSP_BAIL_ON_ERROR(Status);

            GssBuffer->type |= GSS_IOV_BUFFER_FLAG_ALLOCATED;
        }
    }

    /* Always allocate stream data buffers. */
    if (StreamIov != GSS_C_NO_IOV_BUFFER &&
        DataIov != GSS_C_NO_IOV_BUFFER)
        DataIov->type |= GSS_IOV_BUFFER_FLAG_ALLOCATE;

    *pIov = Iov;

    Status = SEC_E_OK;

cleanup:
    if (Status != SEC_E_OK)
        GsspFree(Iov);

    return Status;
}

NTSTATUS
GsspIovToSecBuffers(
    gss_iov_buffer_t Iov,
    PSecBufferDesc Buffers,
    BOOLEAN bWrapOrGetMIC)
{
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < Buffers->cBuffers; i++) {
        PSecBuffer Buffer = &Buffers->pBuffers[i];
        gss_iov_buffer_t GssBuffer = &Iov[i];

        /* Fix up lengths of non-readonly buffers */
        if (Buffer->BufferType & SECBUFFER_READONLY)
            continue;

        /*
         * If we copied the data from the client's address space into a
         * temporary buffer, then copy it back to the client. Otherwise,
         * transfer ownership of the buffer to the caller.
         */
        if (Buffer->BufferType & SECBUFFER_UNMAPPED) {
            GSSP_ASSERT(GssBuffer->buffer.length <= Buffer->cbBuffer);

            Status = LsaSpFunctionTable->CopyToClientBuffer(NULL,
                                                            GssBuffer->buffer.length,
                                                            Buffer->pvBuffer,
                                                            GssBuffer->buffer.value);
            if (Status != STATUS_SUCCESS)
                return Status;
        } else if (GssBuffer->type & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
            Buffer->pvBuffer = GssBuffer->buffer.value;
            GssBuffer->type &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
        }

        Buffer->cbBuffer = GssBuffer->buffer.length;
    }

    return SEC_E_OK;
}

static NTSTATUS
GsspCopyGssBufferToClientBuffer(
    gss_buffer_t GssBuffer,
    PSecBuffer ClientBuffer,
    BOOLEAN bAllocate)
{
    NTSTATUS Status;

    if (bAllocate) {
        if (GssBuffer->value != NULL) {
            Status = LsaSpFunctionTable->AllocateClientBuffer(NULL,
                                                              GssBuffer->length,
                                                              &ClientBuffer->pvBuffer);
            if (Status != STATUS_SUCCESS)
                return Status;
        } else
            ClientBuffer->pvBuffer = NULL;
    } else if (ClientBuffer->cbBuffer < GssBuffer->length)
        return SEC_E_BUFFER_TOO_SMALL;

    if (GssBuffer->value != NULL)
        Status = LsaSpFunctionTable->CopyToClientBuffer(NULL,
                                                        GssBuffer->length,
                                                        ClientBuffer->pvBuffer,
                                                        GssBuffer->value);
    else
        Status = STATUS_SUCCESS;

    if (Status == STATUS_SUCCESS)
        ClientBuffer->cbBuffer = GssBuffer->length;

    return Status;
}

static NTSTATUS
GsspCopyGssBufferToLsaBuffer(
    gss_buffer_t GssBuffer,
    PSecBuffer Buffer,
    BOOLEAN bAllocate)
{
    if (bAllocate) {
        if (GssBuffer->value != NULL) {
            NTSTATUS Status;

            Status= GsspLsaAlloc(GssBuffer->length, &Buffer->pvBuffer);
            if (Status != STATUS_SUCCESS)
                return Status;
        } else
            Buffer->pvBuffer = NULL;
    } else if (Buffer->cbBuffer < GssBuffer->length)
        return SEC_E_BUFFER_TOO_SMALL;

    if (GssBuffer->value != NULL)
        RtlCopyMemory(Buffer->pvBuffer, GssBuffer->value, GssBuffer->length);

    Buffer->cbBuffer = GssBuffer->length;

    return STATUS_SUCCESS;
}

NTSTATUS
GsspCopyGssBuffer(
    gss_buffer_t GssBuffer,
    PSecBuffer Buffer,
    BOOLEAN bAllocate)
{
    GSSP_ASSERT(GssBuffer != GSS_C_NO_BUFFER);

    if (Buffer == NULL)
        return SEC_E_INVALID_PARAMETER;

    return GsspCopyGssBufferToLsaBuffer(GssBuffer, Buffer, bAllocate);
}
