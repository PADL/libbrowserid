/*
 * Copyright (c) 2010, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Portions Copyright 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "gssapiP_eap.h"

static gss_OID_desc gssEapNtPrincipalName = {
    /* 1.3.6.1.4.1.5322.21.2.1  */
    10, "\x2B\x06\x01\x04\x01\xA9\x4A\x15\x02\x01"
};

gss_OID GSS_EAP_NT_PRINCIPAL_NAME = &gssEapNtPrincipalName;

OM_uint32
gssEapAllocName(OM_uint32 *minor, gss_name_t *pName)
{
    OM_uint32 tmpMinor;
    gss_name_t name;

    *pName = GSS_C_NO_NAME;

    name = (gss_name_t)GSSEAP_CALLOC(1, sizeof(*name));
    if (name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&name->mutex) != 0) {
        *minor = errno;
        gssEapReleaseName(&tmpMinor, &name);
        return GSS_S_FAILURE;
    }

    *pName = name;

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseName(OM_uint32 *minor, gss_name_t *pName)
{
    gss_name_t name;
    krb5_context krbContext = NULL;
    OM_uint32 tmpMinor;

    if (pName == NULL) {
        return GSS_S_COMPLETE;
    }

    name = *pName;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_COMPLETE;
    }

    GSSEAP_KRB_INIT(&krbContext);
    krb5_free_principal(krbContext, name->krbPrincipal);

    samlReleaseAttrContext(&tmpMinor, &name->samlCtx);

    GSSEAP_MUTEX_DESTROY(&name->mutex);
    GSSEAP_FREE(name);
    *pName = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
krbPrincipalToName(OM_uint32 *minor,
                   krb5_principal *principal,
                   gss_name_t *pName)
{
    OM_uint32 major;
    gss_name_t name;

    major = gssEapAllocName(minor, &name);
    if (GSS_ERROR(major))
        return major;

    name->krbPrincipal = *principal;
    *principal = NULL;

    if (name->krbPrincipal->length == 1) {
        name->flags |= NAME_FLAG_NAI;
    } else {
        name->flags |= NAME_FLAG_SERVICE;
    }

    *pName = name;
    *minor = 0;

    return GSS_S_COMPLETE;
}

static OM_uint32
importServiceName(OM_uint32 *minor,
                  const gss_buffer_t nameBuffer,
                  gss_name_t *pName)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    krb5_principal krbPrinc;
    char *service, *host;

    GSSEAP_KRB_INIT(&krbContext);

    major = bufferToString(minor, nameBuffer, &service);
    if (GSS_ERROR(major))
        return major;

    host = strchr(service, '@');
    if (host != NULL) {
        *host = '\0';
        host++;
    }    

    /* XXX this is probably NOT what we want to be doing */
    *minor = krb5_sname_to_principal(krbContext, host, service,
                                     KRB5_NT_SRV_HST, &krbPrinc);
    if (*minor != 0) {
        GSSEAP_FREE(service);
        return GSS_S_FAILURE;
    }

    major = krbPrincipalToName(minor, &krbPrinc, pName);
    if (GSS_ERROR(major)) {
        krb5_free_principal(krbContext, krbPrinc);
    }

    GSSEAP_FREE(service);
    return major;
}

static OM_uint32
importUserName(OM_uint32 *minor,
               const gss_buffer_t nameBuffer,
               gss_name_t *pName)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    krb5_principal krbPrinc;
    char *nameString;

    GSSEAP_KRB_INIT(&krbContext);

    major = bufferToString(minor, nameBuffer, &nameString);
    if (GSS_ERROR(major))
        return major;

    *minor = krb5_parse_name(krbContext, nameString, &krbPrinc);
    if (*minor != 0) {
        GSSEAP_FREE(nameString);
        return GSS_S_FAILURE;
    }

    major = krbPrincipalToName(minor, &krbPrinc, pName);
    if (GSS_ERROR(major)) {
        krb5_free_principal(krbContext, krbPrinc);
    }

    GSSEAP_FREE(nameString);
    return major;
}

static OM_uint32
importExportedName(OM_uint32 *minor,
                   const gss_buffer_t nameBuffer,
                   gss_name_t *pName)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    unsigned char *p;
    size_t len, remain;
    gss_buffer_desc buf;
    enum gss_eap_token_type tok_type;

    GSSEAP_KRB_INIT(&krbContext);

    p = (unsigned char *)nameBuffer->value;
    remain = nameBuffer->length;

    if (remain < 6 + GSS_EAP_MECHANISM->length + 4)
        return GSS_S_BAD_NAME;

    /* TOK_ID */
    tok_type = load_uint16_be(p);
    if (tok_type != TOK_TYPE_EXPORT_NAME &&
        tok_type != TOK_TYPE_EXPORT_NAME_COMPOSITE)
        return GSS_S_BAD_NAME;
    p += 2;
    remain -= 2;

    /* MECH_OID_LEN */
    len = load_uint16_be(p);
    if (len != 2 + GSS_EAP_MECHANISM->length)
        return GSS_S_BAD_NAME;
    p += 2;
    remain -= 2;

    /* MECH_OID */
    if (p[0] != 0x06)
        return GSS_S_BAD_NAME;
    if (p[1] != GSS_EAP_MECHANISM->length)
        return GSS_S_BAD_MECH;
    if (memcmp(&p[2], GSS_EAP_MECHANISM->elements, GSS_EAP_MECHANISM->length))
        return GSS_S_BAD_MECH;
    p += 2 + GSS_EAP_MECHANISM->length;
    remain -= 2 + GSS_EAP_MECHANISM->length;

    /* NAME_LEN */
    len = load_uint32_be(p);
    p += 4;
    remain -= 4;

    if (remain < len)
        return GSS_S_BAD_NAME;

    /* NAME */
    buf.length = len;
    buf.value = p;

    p += len;
    remain -= len;

    if (remain != 0)
        return GSS_S_BAD_NAME;

    major = importUserName(minor, &buf, pName);
    if (GSS_ERROR(major))
        return major;

    if (tok_type == TOK_TYPE_EXPORT_NAME_COMPOSITE) {
        gss_buffer_desc saml;

        saml.length = remain;
        saml.value = p;

        major = samlImportAttrContext(minor, &saml, &(*pName)->samlCtx);
        if (GSS_ERROR(major)) {
            gssEapReleaseName(&tmpMinor, pName);
            return major;
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapImportName(OM_uint32 *minor,
                 const gss_buffer_t nameBuffer,
                 gss_OID nameType,
                 gss_name_t *name)
{
    OM_uint32 major, tmpMinor;

    *name = GSS_C_NO_NAME;

    if (nameType == GSS_C_NULL_OID ||
        oidEqual(nameType, GSS_C_NT_USER_NAME) ||
        oidEqual(nameType, GSS_EAP_NT_PRINCIPAL_NAME))
        major = importUserName(minor, nameBuffer, name);
    else if (oidEqual(nameType, GSS_C_NT_HOSTBASED_SERVICE) ||
               oidEqual(nameType, GSS_C_NT_HOSTBASED_SERVICE_X))
        major = importServiceName(minor, nameBuffer, name);
    else if (oidEqual(nameType, GSS_C_NT_EXPORT_NAME))
        major = importExportedName(minor, nameBuffer, name);
    else
        major = GSS_S_BAD_NAMETYPE;

    if (GSS_ERROR(major))
        gssEapReleaseName(&tmpMinor, name);

    return major;
}

OM_uint32
gssEapExportName(OM_uint32 *minor,
                 const gss_name_t name,
                 gss_buffer_t exportedName,
                 int composite)
{
    OM_uint32 major = GSS_S_FAILURE, tmpMinor;
    krb5_context krbContext;
    char *krbName = NULL;
    size_t krbNameLen;
    unsigned char *p;
    gss_buffer_desc saml;

    saml.length = 0;
    saml.value = NULL;

    exportedName->length = 0;
    exportedName->value = NULL;

    GSSEAP_KRB_INIT(&krbContext);
    GSSEAP_MUTEX_LOCK(&name->mutex);

    /*
     * Don't export a composite name if we don't have any attributes.
     */
    if (composite && !NAME_HAS_ATTRIBUTES(name))
        composite = 0;

    *minor = krb5_unparse_name(krbContext, name->krbPrincipal, &krbName);
    if (*minor != 0) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }
    krbNameLen = strlen(krbName);

    exportedName->length = 6 + GSS_EAP_MECHANISM->length + 4 + krbNameLen;
    if (composite) {
        major = samlExportAttrContext(minor, name->samlCtx, &saml);
        if (GSS_ERROR(major))
            goto cleanup;

        exportedName->length += 4 + saml.length;
    }

    exportedName->value = GSSEAP_MALLOC(exportedName->length);
    if (exportedName->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    /* TOK | MECH_OID_LEN */
    p = (unsigned char *)exportedName->value;
    store_uint16_be(composite
                        ? TOK_TYPE_EXPORT_NAME_COMPOSITE
                        : TOK_TYPE_EXPORT_NAME,
                    p);
    p += 2;
    store_uint16_be(GSS_EAP_MECHANISM->length + 2, p);
    p += 2;

    /* MECH_OID */
    *p++ = 0x06;
    *p++ = GSS_EAP_MECHANISM->length & 0xff;
    memcpy(p, GSS_EAP_MECHANISM->elements, GSS_EAP_MECHANISM->length);
    p += GSS_EAP_MECHANISM->length;

    /* NAME_LEN */
    store_uint32_be(krbNameLen, p);
    p += 4;

    /* NAME */
    memcpy(p, krbName, krbNameLen);
    p += krbNameLen;

    store_uint32_be(saml.length, p);
    p += 4;

    memcpy(p, saml.value, saml.length);
    p += saml.length;

    *minor = 0;
    major = GSS_S_COMPLETE;

cleanup:
    GSSEAP_MUTEX_UNLOCK(&name->mutex);
    gss_release_buffer(&tmpMinor, &saml);
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, exportedName);
    krb5_free_unparsed_name(krbContext, krbName);

    return major;
}

static gss_buffer_desc attributePrefixes[] = {
    {
        /* ATTR_TYPE_NONE */
        0,
        NULL,
    },
    {
        /* ATTR_TYPE_SAML_AAA_ASSERTION */
        sizeof("urn:ietf:params:gss-eap:saml-aaa-assertion"),
        "urn:ietf:params:gss-eap:saml-aaa-assertion"
    },
    {
        /* ATTR_TYPE_SAML_ATTR */
        sizeof("urn:ietf:params:gss-eap:saml-attr"),
        "urn:ietf:params:gss-eap:saml-attr"
    },
    {
        /* ATTR_TYPE_RADIUS_AVP */
        sizeof("urn:ietf:params:gss-eap:radius-avp"),
        "urn:ietf:params:gss-eap:radius-avp",
    }
};

enum gss_eap_attribute_type
gssEapAttributePrefixToType(const gss_buffer_t prefix)
{
    enum gss_eap_attribute_type i;

    for (i = ATTR_TYPE_SAML_AAA_ASSERTION;
         i < sizeof(attributePrefixes) / sizeof(attributePrefixes[0]);
         i++)
    {
        if (bufferEqual(&attributePrefixes[i], prefix))
            return i;
    }

    return ATTR_TYPE_NONE;
}

gss_buffer_t
gssEapAttributeTypeToPrefix(enum gss_eap_attribute_type type)
{
    if (type <= ATTR_TYPE_NONE ||
        type > ATTR_TYPE_RADIUS_AVP)
        return GSS_C_NO_BUFFER;

    return &attributePrefixes[type];
}

OM_uint32
decomposeAttributeName(OM_uint32 *minor,
                       const gss_buffer_t attribute,
                       gss_buffer_t prefix,
                       gss_buffer_t suffix)
{
    char *p = NULL;
    int i;

    for (i = 0; i < attribute->length; i++) {
        if (((char *)attribute->value)[i] == ' ') {
            p = (char *)attribute->value + i + 1;
            break;
        }
    }

    prefix->value = attribute->value;
    prefix->length = i;

    if (p != NULL && *p != '\0')  {
        suffix->length = attribute->length - 1 - prefix->length;
        suffix->value = p;
    } else {
        suffix->length = 0;
        suffix->value = NULL;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
composeAttributeName(OM_uint32 *minor,
                       const gss_buffer_t prefix,
                       const gss_buffer_t suffix,
                       gss_buffer_t attribute)
{
    size_t len = 0;
    char *p;

    attribute->length = 0;
    attribute->value = NULL;

    if (prefix == GSS_C_NO_BUFFER || prefix->length == 0)
        return GSS_S_COMPLETE;

    len = prefix->length;
    if (suffix != NULL) {
        len += 1 + suffix->length;
    }

    p = attribute->value = GSSEAP_MALLOC(len + 1);
    if (attribute->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    attribute->length = len;

    memcpy(p, prefix->value, prefix->length);
    if (suffix != NULL) {
        p[prefix->length] = ' ';
        memcpy(p + prefix->length + 1, suffix->value, suffix->length);
    }

    p[attribute->length] = '\0';

    *minor = 0;
    return GSS_S_COMPLETE;
}
