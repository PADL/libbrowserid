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
 *
 */

#include "gssapiP_bid.h"

OM_uint32
gssQueryMechanismInfo(OM_uint32 *minor,
                      gss_const_OID mech_oid,
                      unsigned char auth_scheme[16])
{
    OM_uint32 major;
    krb5_enctype enctype;

    major = gssBidOidToEnctype(minor, (const gss_OID)mech_oid, &enctype);
    if (GSS_ERROR(major))
        return major;

    /* the enctype is encoded in the increasing part of the GUID */
    memcpy(auth_scheme,
           "\x39\xd7\x7d\x00\xe5\x00\x11\xe0\xac\x64\xcd\x53\x46\x50\xac\xb9", 16);

    auth_scheme[3] = (unsigned char)enctype;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
gss_query_mechanism_info(OM_uint32 *minor,
                         gss_const_OID mech_oid,
                         unsigned char auth_scheme[16])
{
    return gssQueryMechanismInfo(minor, mech_oid, auth_scheme);
}
