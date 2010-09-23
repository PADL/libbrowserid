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
gss_store_cred(OM_uint32 *minor,
               const gss_cred_id_t input_cred_handle,
               gss_cred_usage_t input_usage,
               const gss_OID desired_mech,
               OM_uint32 overwrite_cred,
               OM_uint32 default_cred,
               gss_OID_set *elements_stored,
               gss_cred_usage_t *cred_usage_stored)
{
    if (elements_stored != NULL)
        *elements_stored = GSS_C_NO_OID_SET;
    if (cred_usage_stored != NULL)
        *cred_usage_stored = input_usage;

    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CRED;

#ifdef GSSEAP_ENABLE_REAUTH
    if (input_cred_handle->krbCred != GSS_C_NO_CREDENTIAL) {
        return gssStoreCred(minor,
                            input_cred_handle->krbCred,
                            input_usage,
                            gss_mech_krb5,
                            overwrite_cred,
                            default_cred,
                            elements_stored,
                            cred_usage_stored);
    }
#endif

    *minor = 0;
    return GSS_S_UNAVAILABLE;
}
