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

OM_uint32
gss_get_name_attribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc prefix, suffix;
    enum gss_eap_attribute_type type;

    if (name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    *authenticated = 0;
    *complete = 0;
    value->length = 0;
    value->value = NULL;
    display_value->length = 0;
    display_value->value = NULL;
    *more = -1;

    GSSEAP_MUTEX_LOCK(&name->mutex);

    major = decomposeAttributeName(minor, attr, &prefix, &suffix);
    if (GSS_ERROR(major))
        goto cleanup;

    type = gssEapAttributePrefixToType(&prefix);
    switch (type) {
    case ATTR_TYPE_SAML_AAA_ASSERTION:
        major = samlGetAssertion(minor, name->samlCtx, value);
        break;
    case ATTR_TYPE_SAML_ATTR:
        major = samlGetAttribute(minor, name->samlCtx, &suffix,
                                 authenticated, complete,
                                 value, display_value, more);
        break;
    case ATTR_TYPE_RADIUS_AVP:
        major = radiusGetAttribute(minor, name->radiusCtx, &suffix,
                                   authenticated, complete,
                                   value, display_value, more);
        break;
    default:
        *minor = ENOENT;
        major = GSS_S_UNAVAILABLE;
        break;
    }

cleanup:
    GSSEAP_MUTEX_UNLOCK(&name->mutex);

    return major;
}
