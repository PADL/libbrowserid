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
 * Wrapper for acquiring a credential handle.
 */

#include "gssapiP_bid.h"

#ifdef __APPLE__
/* GSS_C_CRED_CFDictionary - 1.3.6.1.4.1.5322.25.1.1 */
static const gss_OID_desc
GSS_C_CRED_CFDictionary = { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x19\x01\x01" };

OM_uint32 GSSAPI_CALLCONV
gss_acquire_cred_ext(OM_uint32 *minor,
                     const gss_name_t desired_name,
                     gss_const_OID credential_type,
                     const void *credential_data,
                     OM_uint32 time_req,
                     gss_const_OID desired_mech,
                     gss_cred_usage_t cred_usage,
                     gss_cred_id_t *output_cred_handle)

{
    OM_uint32 major;
    gss_OID_set_desc desired_mechs = { 1, (gss_OID)desired_mech };

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    if (!oidEqual(credential_type, &GSS_C_CRED_CFDictionary))
        return GSS_S_UNAVAILABLE;

    major = gssBidAcquireCred(minor,
                              desired_name,
                              time_req,
                              desired_mech ? &desired_mechs : GSS_C_NO_OID_SET,
                              cred_usage,
                              output_cred_handle, NULL, NULL);
    if (GSS_ERROR(major))
        return major;

    major = gssBidSetCredWithCFDictionary(minor,
                                          *output_cred_handle,
                                          (CFDictionaryRef)credential_data);
    if (GSS_ERROR(major)) {
        OM_uint32 tmpMinor;
        gssBidReleaseCred(&tmpMinor, output_cred_handle);
    }

    return major;
}
#endif /* __APPLE__ */
