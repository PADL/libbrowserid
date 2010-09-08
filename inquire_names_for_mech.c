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
gss_inquire_names_for_mech(OM_uint32 *minor,
                           gss_OID mechanism,
                           gss_OID_set *name_types)
{
    OM_uint32 major, tmpMinor;

    if (!gssEapIsMechanismOid(mechanism)) {
        *minor = 0;
        return GSS_S_BAD_MECH;
    }

    major = gss_create_empty_oid_set(minor, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_USER_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_HOSTBASED_SERVICE, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_C_NT_EXPORT_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_oid_set_member(minor, GSS_EAP_NT_PRINCIPAL_NAME, name_types);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, name_types);

    return major;
}
