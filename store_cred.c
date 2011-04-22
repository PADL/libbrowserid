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

#include "gssapiP_eap.h"

OM_uint32
gss_store_cred(OM_uint32 *minor,
               const gss_cred_id_t cred,
               gss_cred_usage_t input_usage,
               const gss_OID desired_mech GSSEAP_UNUSED,
#ifdef GSSEAP_ENABLE_REAUTH
               OM_uint32 overwrite_cred,
               OM_uint32 default_cred,
#else
               OM_uint32 overwrite_cred GSSEAP_UNUSED,
               OM_uint32 default_cred GSSEAP_UNUSED,
#endif
               gss_OID_set *elements_stored,
               gss_cred_usage_t *cred_usage_stored)
{
    OM_uint32 major;

    if (elements_stored != NULL)
        *elements_stored = GSS_C_NO_OID_SET;
    if (cred_usage_stored != NULL)
        *cred_usage_stored = input_usage;

    if (cred == GSS_C_NO_CREDENTIAL) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CRED;
    }

    GSSEAP_MUTEX_LOCK(&cred->mutex);

    major = GSS_S_COMPLETE;
    *minor = 0;

#ifdef GSSEAP_ENABLE_REAUTH
    if (cred->reauthCred != GSS_C_NO_CREDENTIAL) {
        major = gssStoreCred(minor,
                             cred->reauthCred,
                             input_usage,
                             (gss_OID)gss_mech_krb5,
                             overwrite_cred,
                             default_cred,
                             elements_stored,
                             cred_usage_stored);
    }
#endif

    GSSEAP_MUTEX_UNLOCK(&cred->mutex);

    return major;
}
