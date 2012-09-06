/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Glue for fast-reauthentication with native Kerberos package
 */

#include "gssp.h"

OM_uint32
gssEapStoreReauthCreds(OM_uint32 *Minor,
                       gss_ctx_id_t GssContext,
                       gss_cred_id_t GssCred,
                       gss_buffer_t CredBuf)
{
    NTSTATUS Status, SubStatus;
    KERB_SUBMIT_TKT_REQUEST *pSubmitTktRequest = NULL;
    DWORD cbSubmitTktRequest;
    LSA_STRING LogonProcessName;
    LSA_STRING PackageName;
    ULONG AuthenticationPackage;
    HANDLE LsaHandle = NULL;
    LSA_OPERATIONAL_MODE SecurityMode;

    RtlInitString(&LogonProcessName, "EapSspFastReauth");
    RtlInitString(&PackageName, MICROSOFT_KERBEROS_NAME_A);

    if (CredBuf->length == 0 || GssCred == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;

    cbSubmitTktRequest = sizeof(*pSubmitTktRequest) +
                         KRB_KEY_LENGTH(&GssContext->rfc3961Key) +
                         CredBuf->length;

    pSubmitTktRequest = GsspCallocPtr(1, cbSubmitTktRequest);
    if (pSubmitTktRequest == NULL) {
        *Minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    pSubmitTktRequest->MessageType = KerbSubmitTicketMessage;
    pSubmitTktRequest->LogonId = GssContext->LogonId;
    pSubmitTktRequest->Flags = 0;

    pSubmitTktRequest->Key.KeyType = GssContext->encryptionType;
    pSubmitTktRequest->Key.Length = KRB_KEY_LENGTH(&GssContext->rfc3961Key);
    pSubmitTktRequest->Key.Offset = sizeof(*pSubmitTktRequest);

    pSubmitTktRequest->KerbCredSize = CredBuf->length;
    pSubmitTktRequest->KerbCredOffset = sizeof(*pSubmitTktRequest) +
                                        pSubmitTktRequest->Key.Length;

    /* Copy the session key */
    RtlCopyMemory((PUCHAR)pSubmitTktRequest + pSubmitTktRequest->Key.Offset,
                  KRB_KEY_DATA(&GssContext->rfc3961Key),
                  KRB_KEY_LENGTH(&GssContext->rfc3961Key));

    /* Copy the cred */
    RtlCopyMemory((PUCHAR)pSubmitTktRequest + pSubmitTktRequest->KerbCredOffset,
                  CredBuf->value, CredBuf->length);

    Status = LsaRegisterLogonProcess(&LogonProcessName, &LsaHandle, &SecurityMode);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthenticationPackage);
    GSSP_BAIL_ON_ERROR(Status);

    Status = LsaCallAuthenticationPackage(LsaHandle,
                                          AuthenticationPackage,
                                          pSubmitTktRequest,
                                          cbSubmitTktRequest,
                                          NULL,
                                          NULL,
                                          &SubStatus);
    if (Status == STATUS_SUCCESS)
        Status = SubStatus;
    GSSP_BAIL_ON_ERROR(Status);

cleanup:
    if (LsaHandle != NULL)
        LsaClose(LsaHandle);
    GsspFreePtr(pSubmitTktRequest);

    /* Don't hard-error if this fails. */
    *Minor = 0;
    return GSS_S_COMPLETE;
}

static BOOLEAN
NtTimeToKerberosTime(PLARGE_INTEGER NtTime, krb5_timestamp *pKerbTime)
{
    ULONG KerbTime;

    *pKerbTime = 0;

    if (!RtlTimeToSecondsSince1970(NtTime, &KerbTime))
        return FALSE;

    *pKerbTime = (krb5_timestamp)KerbTime;
    return TRUE;
}

static OM_uint32
MakeKerberosCredFromLsaTicket(
    OM_uint32 *minor,
    gss_ctx_id_t GssContext,
    KERB_EXTERNAL_TICKET *Ticket,
    gss_buffer_t CredBuf)
{
    krb5_error_code Code;
    krb5_context KrbContext;
    krb5_auth_context AuthContext;
    krb5_data CredsData;
    krb5_creds Creds;
    krb5_keyblock SessionKey;

    CredBuf->length = 0;
    CredBuf->value = NULL;

    KRB_DATA_INIT(&CredsData);
    GSSEAP_KRB_INIT(&KrbContext);

    RtlZeroMemory(&Creds, sizeof(Creds));

    KRB_KEY_INIT(&SessionKey);
    KRB_KEY_TYPE(&SessionKey)   = Ticket->SessionKey.KeyType;
    KRB_KEY_LENGTH(&SessionKey) = Ticket->SessionKey.Length;
    KRB_KEY_DATA(&SessionKey)   = Ticket->SessionKey.Value;

    Creds.client = GssContext->initiatorName->krbPrincipal;
    Creds.server = GssContext->acceptorName->krbPrincipal;
    Creds.session = SessionKey;
    NtTimeToKerberosTime(&Ticket->StartTime,    &Creds.times.starttime);
    NtTimeToKerberosTime(&Ticket->EndTime,      &Creds.times.endtime);
    NtTimeToKerberosTime(&Ticket->RenewUntil,   &Creds.times.renew_till);
    Creds.flags.i = Ticket->TicketFlags;
    Creds.ticket.length = Ticket->EncodedTicketSize;
    Creds.ticket.data = Ticket->EncodedTicket;

    Code = krb5_auth_con_init(KrbContext, &AuthContext);
    GSSP_BAIL_ON_ERROR(Code);

    Code = krb5_auth_con_setflags(KrbContext, AuthContext, 0);
    GSSP_BAIL_ON_ERROR(Code);

    Code = krb5_auth_con_setlocalsubkey(KrbContext, AuthContext,
                                        &GssContext->rfc3961Key);
    GSSP_BAIL_ON_ERROR(Code);

    Code = krbMakeCred(KrbContext, AuthContext, &Creds, &CredsData);
    GSSP_BAIL_ON_ERROR(Code);

    krbDataToGssBuffer(&CredsData, CredBuf);

cleanup:
    krb5_auth_con_free(KrbContext, AuthContext);

    *minor = Code;

    return (Code != 0) ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32
gssEapMakeReauthCreds(OM_uint32 *Minor,
                      gss_ctx_id_t GssContext,
                      gss_cred_id_t GssCred,
                      gss_buffer_t CredBuf)
{
    OM_uint32 Major = GSS_S_FAILURE;
    NTSTATUS Status, SubStatus;
    UNICODE_STRING TargetName;
    UNICODE_STRING AuthenticationPackage;
    PKERB_RETRIEVE_TKT_REQUEST pRetrieveTktRequest = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pRetrieveTktResponse = NULL;
    DWORD cbRetrieveTktRequest;
    DWORD cbRetrieveTktResponse;

    if (GssContext->initiatorName == GSS_C_NO_NAME ||
        GssContext->acceptorName == GSS_C_NO_NAME)
        return GSS_S_BAD_NAME;

    RtlInitUnicodeString(&TargetName, NULL);
    RtlInitUnicodeString(&AuthenticationPackage, MICROSOFT_KERBEROS_NAME_W);

    Status = GsspDisplayGssNameUnicodeString(GssContext->acceptorName,
                                             FALSE,
                                             &TargetName);
    GSSP_BAIL_ON_ERROR(Status);

    cbRetrieveTktRequest = sizeof(*pRetrieveTktRequest) + TargetName.Length;
    Status = GsspCalloc(1, cbRetrieveTktRequest, &pRetrieveTktRequest);
    GSSP_BAIL_ON_ERROR(Status);

    pRetrieveTktRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pRetrieveTktRequest->LogonId = GssContext->LogonId;

    pRetrieveTktRequest->TargetName.Length = TargetName.Length;
    pRetrieveTktRequest->TargetName.MaximumLength = TargetName.MaximumLength;
    pRetrieveTktRequest->TargetName.Buffer = (PWSTR)((PUCHAR)pRetrieveTktRequest + sizeof(*pRetrieveTktRequest));
    RtlCopyMemory(pRetrieveTktRequest->TargetName.Buffer,
                  TargetName.Buffer, TargetName.Length);

    pRetrieveTktRequest->TicketFlags = KERB_USE_DEFAULT_TICKET_FLAGS;
    pRetrieveTktRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
    pRetrieveTktRequest->EncryptionType = KERB_ETYPE_DEFAULT;

    /*
     * XXX according to MS we'd actually have to do S4U2Proxy in order
     * for the ticket to show up in the logon session's ticket cache.
     */
    Status = LsaSpFunctionTable->CallPackage(&AuthenticationPackage,
                                             pRetrieveTktRequest,
                                             cbRetrieveTktRequest,
                                             &pRetrieveTktResponse,
                                             &cbRetrieveTktResponse,
                                             &SubStatus);
    GSSP_BAIL_ON_ERROR(Status);

    if (SubStatus == STATUS_SUCCESS) {
        GSSP_ASSERT(pRetrieveTktResponse != NULL);

        Major = MakeKerberosCredFromLsaTicket(Minor, GssContext,
                                              &pRetrieveTktResponse->Ticket,
                                              CredBuf);
        GSSP_BAIL_ON_ERROR(Major);
    }

    Major = GSS_S_COMPLETE;

cleanup:
    if (pRetrieveTktResponse != NULL)
        LsaSpFunctionTable->FreeReturnBuffer(pRetrieveTktResponse);
    GsspFreeUnicodeString(&TargetName);
    GsspFree(pRetrieveTktRequest);

    return (Status == STATUS_SUCCESS) ? Major : GSS_S_FAILURE;
}
