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
gss_inquire_saslname_for_mech(OM_uint32 *minor,
                              const gss_OID mech,
                              gss_buffer_t sasl_mech_name,
                              gss_buffer_t mech_name,
                              gss_buffer_t mech_description)
{
    OM_uint32 major;
    gss_buffer_t name;
    krb5_enctype etype = ENCTYPE_NULL;
    char krbBuf[128] = "eap-";

    /* Dynamically construct mechanism name from Kerberos string enctype */
    major = gssEapOidToEnctype(minor, mech, &etype);
    if (GSS_ERROR(major))
        return major;

    if (mech_name != GSS_C_NO_BUFFER &&
        krb5_enctype_to_name(etype, 0, &krbBuf[4], sizeof(krbBuf) - 4) == 0) {
        major = makeStringBuffer(minor, krbBuf, mech_name);
        if (GSS_ERROR(major))
            return major;
    }

    if (mech_description != GSS_C_NO_BUFFER) {
        major = makeStringBuffer(minor,
                                 "Extensible Authentication Protocol GSS-API Mechanism",
                                 mech_description);
        if (GSS_ERROR(major))
            return major;
    }

    if (sasl_mech_name != GSS_C_NO_BUFFER) {
        name = gssEapOidToSaslName(mech);
        if (name == GSS_C_NO_BUFFER)
            major = GSS_S_BAD_MECH;
        else
            major = duplicateBuffer(minor, name, sasl_mech_name);
    }

    return major;
}
