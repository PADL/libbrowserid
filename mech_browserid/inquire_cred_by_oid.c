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
 * Return extended credential handle properties.
 */

#include "gssapiP_bid.h"

#if 0
static struct {
    gss_OID_desc oid;
    OM_uint32 (*inquire)(OM_uint32 *, const gss_cred_id_t,
                         const gss_OID, gss_buffer_set_t *);
} inquireCredOps[] = {
};
#endif

OM_uint32 GSSAPI_CALLCONV
gss_inquire_cred_by_oid(OM_uint32 *minor,
#ifdef HAVE_HEIMDAL_VERSION
                        gss_const_cred_id_t cred_handle_const,
                        const gss_OID desired_object GSSBID_UNUSED,
#else
                        const gss_cred_id_t cred_handle,
                        const gss_OID desired_object GSSBID_UNUSED,
#endif
                        gss_buffer_set_t *data_set)
{
#ifdef HAVE_HEIMDAL_VERSION
    gss_cred_id_t cred_handle = (gss_cred_id_t)cred_handle_const;
#endif
    OM_uint32 major;
#if 0
    int i;
#endif
    *data_set = GSS_C_NO_BUFFER_SET;

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CRED;
    }

    GSSBID_MUTEX_LOCK(&cred_handle->mutex);

    major = GSS_S_UNAVAILABLE;
    *minor = GSSBID_BAD_CRED_OPTION;

#if 0
    for (i = 0; i < sizeof(inquireCredOps) / sizeof(inquireCredOps[0]); i++) {
        if (oidEqual(&inquireCredOps[i].oid, desired_object)) {
            major = (*inquireCredOps[i].inquire)(minor, cred_handle,
                                                 desired_object, data_set);
            break;
        }
    }
#endif

    GSSBID_MUTEX_UNLOCK(&cred_handle->mutex);

    return major;
}
