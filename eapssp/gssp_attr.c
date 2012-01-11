/*
 * Copyright (C) 2011 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Authz attributes
 */

#include "gssp.h"

static NTSTATUS
GsspAttributeToAuthzAttr(
    gss_ctx_id_t GssContext,
    gss_buffer_t GssAttr,
    PAUTHZ_SECURITY_ATTRIBUTE_V1 Attr)
{
    NTSTATUS Status;
    OM_uint32 Major, Minor, TmpMinor;
    int Authenticated, Complete, More;
    ULONG i;
    BOOLEAN bGetDisplayValue = TRUE;
    BOOLEAN bGetValue = TRUE;

    RtlZeroMemory(Attr, sizeof(*Attr));

    Attr->ValueCount = 0;

    /* Count values */
    for (More = -1; More != 0; ) {
        Major = gssEapGetNameAttribute(&Minor,
                                       GssContext->initiatorName,
                                       GssAttr,
                                       &Authenticated,
                                       &Complete,
                                       GSS_C_NO_BUFFER,
                                       GSS_C_NO_BUFFER,
                                       &More);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

        if (Authenticated == 0)
            return STATUS_SUCCESS;

        Attr->ValueCount++;
    }

    Status = GsspGssBufferToWideString(GssAttr, TRUE, &Attr->pName, NULL);
    GSSP_BAIL_ON_ERROR(Status);

    Attr->ValueType = AUTHZ_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING;

    Status = GsspLsaCalloc(Attr->ValueCount,
                           sizeof(AUTHZ_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE),
                           (PVOID *)&Attr->Values.pOctetString);
    GSSP_BAIL_ON_ERROR(Status);

    for (More = -1, i = 0; More != 0; i++) {
        gss_buffer_desc Value = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc DisplayValue = GSS_C_EMPTY_BUFFER;

        Major = gssEapGetNameAttribute(&Minor,
                                       GssContext->initiatorName,
                                       GssAttr,
                                       &Authenticated,
                                       &Complete,
                                       bGetValue ? &Value : GSS_C_NO_BUFFER,
                                       bGetDisplayValue ? &DisplayValue : GSS_C_NO_BUFFER,
                                       &More);
        GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

        if (DisplayValue.length != 0 && i == 0) {
            Attr->ValueType = AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING;
            bGetValue = FALSE;
        } else {
            bGetDisplayValue = FALSE;
        }

        if (Attr->ValueType == AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING) {
            Status = GsspGssBufferToWideString(&DisplayValue,
                                               TRUE,
                                               &Attr->Values.ppString[i],
                                               NULL);
            GSSP_BAIL_ON_ERROR(Status);
        } else {
            Status = GsspLsaAlloc(Value.length,
                                  &Attr->Values.pOctetString[i].pValue);
            GSSP_BAIL_ON_ERROR(Status);

            RtlCopyMemory(Attr->Values.pOctetString[i].pValue,
                          Value.value, Value.length);

            Attr->Values.pOctetString[i].ValueLength = Value.length;
        }
        GsspReleaseBuffer(&TmpMinor, &Value);
        GsspReleaseBuffer(&TmpMinor, &DisplayValue);
    }

cleanup:
    return Status;
}

NTSTATUS
GsspQuerySubjectSecurityAttributes(
    gss_ctx_id_t GssContext,
    ULONG ContextAttribute,
    PVOID Buffer)
{
    PSecPkgContext_SubjectAttributes SubjectAttributes = (PSecPkgContext_SubjectAttributes)Buffer;
    PAUTHZ_SECURITY_ATTRIBUTES_INFORMATION Attrs;
    NTSTATUS Status;
    OM_uint32 Major, Minor, TmpMinor;
    int NameIsMN;
    gss_OID MechOID = GSS_C_NO_OID;
    gss_buffer_set_t GssAttrs = GSS_C_NO_BUFFER_SET;
    ULONG i;

    SubjectAttributes->AttributeInfo = NULL;

    Major = gssEapInquireName(&Minor, GssContext->initiatorName,
                              &NameIsMN, &MechOID, &GssAttrs);
    GSSP_BAIL_ON_GSS_ERROR(Major, Minor);

    if (GssAttrs == GSS_C_NO_BUFFER_SET) {
        Status = STATUS_SUCCESS;
        goto cleanup;
    }

    Status = GsspLsaCalloc(1, sizeof(*Attrs), (PVOID *)&Attrs);
    GSSP_BAIL_ON_ERROR(Status);

    Attrs->Version = AUTHZ_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;
    Attrs->Reserved = 0;
    Attrs->AttributeCount = 0;

    /* XXX the allocation strategy here is totally bogus */
    Status = GsspLsaCalloc(GssAttrs->count,
                           sizeof(AUTHZ_SECURITY_ATTRIBUTE_V1),
                           (PVOID *)&Attrs->Attribute.pAttributeV1);
    GSSP_BAIL_ON_ERROR(Status);

    for (i = 0; i < GssAttrs->count; i++) {
        Status = GsspAttributeToAuthzAttr(GssContext,
                                          &GssAttrs->elements[i],
                                          &Attrs->Attribute.pAttributeV1[Attrs->AttributeCount]);
        GSSP_BAIL_ON_ERROR(Status);

        Attrs->AttributeCount++;
    }

    SubjectAttributes->AttributeInfo = Attrs;

cleanup:
    GsspReleaseBufferSet(&TmpMinor, &GssAttrs);
    return Status;
}
