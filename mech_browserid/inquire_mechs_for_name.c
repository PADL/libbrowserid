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
 * Determine mechanism OIDs supported by name.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_inquire_mechs_for_name(OM_uint32 *minor,
#ifdef HAVE_HEIMDAL_VERSION
                           gss_const_name_t input_name,
#else
                           const gss_name_t input_name,
#endif
                           gss_OID_set *mech_types)
{
    OM_uint32 major, tmpMinor;

    *minor = 0;
    *mech_types = GSS_C_NO_OID_SET;

    if (input_name != GSS_C_NO_NAME &&
        input_name->mechanismUsed != GSS_C_NO_OID) {
        major = gss_create_empty_oid_set(minor, mech_types);
        if (GSS_ERROR(major))
            return major;

        major = gss_add_oid_set_member(minor,
                                       input_name->mechanismUsed,
                                       mech_types);
        if (GSS_ERROR(major)) {
            gss_release_oid_set(&tmpMinor, mech_types);
            return major;
        }
    } else {
        major = gssBidIndicateMechs(minor, mech_types);
        if (GSS_ERROR(major))
            return major;
    }

    return major;
}
