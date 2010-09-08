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
gss_inquire_cred(OM_uint32 *minor,
                 gss_cred_id_t cred,
                 gss_name_t *name,
                 OM_uint32 *pLifetime,
                 gss_cred_usage_t *cred_usage,
                 gss_OID_set *mechanisms)
{
    OM_uint32 major = GSS_S_COMPLETE;

    if (name != NULL) {
        major = gss_duplicate_name(minor, cred->name, name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (pLifetime != NULL) {
        time_t now, lifetime; 
 
        if (cred->expiryTime == 0) {
            lifetime = GSS_C_INDEFINITE; 
        } else  {
            now = time(NULL);
            lifetime = now - cred->expiryTime;
            if (lifetime < 0)
                lifetime = 0;
        }

        *pLifetime = lifetime;
    }

    if (cred_usage != NULL) {
        OM_uint32 flags = (cred->flags & (CRED_FLAG_INITIATE | CRED_FLAG_ACCEPT));

        switch (flags) {
        case CRED_FLAG_INITIATE:
            *cred_usage = GSS_C_INITIATE;
            break;
        case CRED_FLAG_ACCEPT:
            *cred_usage = GSS_C_ACCEPT;
            break;
        default:
            *cred_usage = GSS_C_BOTH;
            break;
        }
    }

    if (mechanisms != NULL) {
        if (cred->mechanisms != GSS_C_NO_OID_SET)
            major = duplicateOidSet(minor, cred->mechanisms, mechanisms);
        else
            major = gssEapIndicateMechs(minor, mechanisms);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    return major;
}
