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
 * Message protection services: verify a message integrity check.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_verify_mic(OM_uint32 *minor,
#ifdef HAVE_HEIMDAL_VERSION
               gss_const_ctx_id_t ctx_const,
#else
               gss_ctx_id_t ctx,
#endif
               gss_buffer_t message_buffer,
               gss_buffer_t message_token,
               gss_qop_t *qop_state)
{
#ifdef HAVE_HEIMDAL_VERSION
    gss_ctx_id_t ctx = (gss_ctx_id_t)ctx_const;
#endif
    OM_uint32 major;
    gss_iov_buffer_desc iov[3];
    int conf_state;

    if (message_token->length < 16) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_BAD_SIG;
    }

    *minor = 0;

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[0].buffer = *message_buffer;

    iov[1].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[1].buffer = *message_token;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    major = gssBidUnwrapOrVerifyMIC(minor, ctx, &conf_state, qop_state,
                                    iov, 2, TOK_TYPE_MIC);

    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
