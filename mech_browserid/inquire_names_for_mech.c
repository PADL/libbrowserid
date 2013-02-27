/*
 * Copyright (c) 2011, JANET(UK)
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
 * Return supported name OID types.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_inquire_names_for_mech(OM_uint32 *minor,
                           gss_OID mechanism,
                           gss_OID_set *ret_name_types)
{
    OM_uint32 major, tmpMinor;
    gss_OID nameTypes[] = {
        GSS_C_NT_USER_NAME,
        GSS_C_NT_HOSTBASED_SERVICE,
        GSS_C_NT_EXPORT_NAME,
#ifdef HAVE_GSS_C_NT_COMPOSITE_EXPORT
        GSS_C_NT_COMPOSITE_EXPORT,
#endif
        GSS_C_NT_BROWSERID_PRINCIPAL,
        GSS_C_NT_ANONYMOUS,
    };
    size_t i;

    if (!gssBidIsMechanismOid(mechanism)) {
        *minor = GSSBID_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    major = gss_create_empty_oid_set(minor, ret_name_types);
    if (GSS_ERROR(major))
        goto cleanup;

    for (i = 0; i < sizeof(nameTypes)/sizeof(nameTypes[0]); i++) {
        major = gss_add_oid_set_member(minor, nameTypes[i], ret_name_types);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, ret_name_types);

    return major;
}
