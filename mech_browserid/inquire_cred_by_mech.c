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
 * Return credential handle properties.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_inquire_cred_by_mech(OM_uint32 *minor,
#ifdef HAVE_HEIMDAL_VERSION
                         gss_const_cred_id_t cred_const,
#else
                         gss_cred_id_t cred,
#endif
                         gss_OID mech_type,
                         gss_name_t *name,
                         OM_uint32 *pInitiatorLifetime,
                         OM_uint32 *pAcceptorLifetime,
                         gss_cred_usage_t *cred_usage)
{
#ifdef HAVE_HEIMDAL_VERSION
    gss_cred_id_t cred = (gss_cred_id_t)cred_const;
#endif
    OM_uint32 major, lifetime;

    if (cred == NULL) {
        *minor = EINVAL;
        return GSS_S_NO_CRED;
    }

    GSSBID_MUTEX_LOCK(&cred->mutex);

    if (!gssBidCredAvailable(cred, mech_type)) {
        major = GSS_S_BAD_MECH;
        *minor = GSSBID_CRED_MECH_MISMATCH;
        goto cleanup;
    }

    major = gssBidInquireCred(minor, cred, name, &lifetime, cred_usage, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    if (pInitiatorLifetime != NULL)
        *pInitiatorLifetime = (cred->flags & CRED_FLAG_INITIATE) ? lifetime : 0;
    if (pAcceptorLifetime != NULL)
        *pAcceptorLifetime = (cred->flags & CRED_FLAG_ACCEPT) ? lifetime : 0;

cleanup:
    GSSBID_MUTEX_UNLOCK(&cred->mutex);

    return major;
}
