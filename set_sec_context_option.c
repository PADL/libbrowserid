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

static struct {
    gss_OID_desc oid;
    OM_uint32 (*setOption)(OM_uint32 *, gss_ctx_id_t *pCtx,
                           const gss_OID, const gss_buffer_t);
} setCtxOps[] = {
};

OM_uint32
gss_set_sec_context_option(OM_uint32 *minor,
                           gss_ctx_id_t *pCtx,
                           const gss_OID desired_object,
                           const gss_buffer_t value)
{
    OM_uint32 major;
    gss_ctx_id_t ctx = *pCtx;
    int i;

    major = GSS_S_UNAVAILABLE;
    *minor = GSSEAP_BAD_CONTEXT_OPTION;

    if (ctx != GSS_C_NO_CONTEXT)
        GSSEAP_MUTEX_LOCK(&ctx->mutex);

    for (i = 0; i < sizeof(setCtxOps) / sizeof(setCtxOps[0]); i++) {
        if (oidEqual(&setCtxOps[i].oid, desired_object)) {
            major = (*setCtxOps[i].setOption)(minor, &ctx,
                                              desired_object, value);
            break;
        }
    }

    if (*pCtx == NULL)
        *pCtx = ctx;
    else
        GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
