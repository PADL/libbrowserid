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

#include "gssapiP_eap.h"

struct eap_gss_attribute_args {
    gss_buffer_t prefix;
    gss_buffer_set_t attrs;
};

static OM_uint32
addAttribute(OM_uint32 *minor,
             void *data,
             gss_buffer_t attribute)
{
    struct eap_gss_attribute_args *args = (struct eap_gss_attribute_args *)data;
    OM_uint32 major, tmpMinor;
    gss_buffer_desc qualifiedAttr;

    if (attribute != GSS_C_NO_BUFFER) {
        major = composeAttributeName(minor, args->prefix, attribute, &qualifiedAttr);
        if (GSS_ERROR(major))
            return major;

        major = gss_add_buffer_set_member(minor, &qualifiedAttr, args->attrs);

        gss_release_buffer(&tmpMinor, &qualifiedAttr);
    } else {
        major = gss_add_buffer_set_member(minor, args->prefix, args->attrs);
    }

    return major;
}

OM_uint32 gss_inquire_name(OM_uint32 *minor,
                           gss_name_t name,
                           int *name_is_MN,
                           gss_OID *MN_mech,
                           gss_buffer_set_t *attrs)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    struct eap_gss_attribute_args args;

    *name_is_MN = 1;
    *MN_mech = GSS_EAP_MECHANISM;
    *attrs = GSS_C_NO_BUFFER_SET;

    if (name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    GSSEAP_KRB_INIT(&krbContext);
    GSSEAP_MUTEX_LOCK(&name->mutex);

    major = gss_create_empty_buffer_set(minor, attrs);
    if (GSS_ERROR(major))
        goto cleanup;

    args.attrs = *attrs;

    if (name->assertion != NULL) {
        args.prefix = gssEapAttributeTypeToPrefix(ATTR_TYPE_SAML_AAA_ASSERTION);

        major = addAttribute(minor, &args, GSS_C_NO_BUFFER);
        if (GSS_ERROR(major))
            goto cleanup;

        args.prefix = gssEapAttributeTypeToPrefix(ATTR_TYPE_SAML_ATTR);
        major = samlGetAttributeTypes(minor, name->assertion, &args, addAttribute);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (name->avps != NULL) {
        args.prefix = gssEapAttributeTypeToPrefix(ATTR_TYPE_RADIUS_AVP);
        major = radiusGetAttributeTypes(minor, name->avps, &args, addAttribute);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    GSSEAP_MUTEX_UNLOCK(&name->mutex);

    if (GSS_ERROR(major))
        gss_release_buffer_set(&tmpMinor, attrs);

    return major;
}
