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
 * Message protection services: unwrap.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_unwrap(OM_uint32 *minor,
           gss_ctx_id_t ctx,
           gss_buffer_t input_message_buffer,
           gss_buffer_t output_message_buffer,
           int *conf_state,
           gss_qop_t *qop_state)
{
    OM_uint32 major, tmpMinor;
    gss_iov_buffer_desc iov[2];

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    *minor = 0;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSBID_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    iov[0].type = GSS_IOV_BUFFER_TYPE_STREAM;
    iov[0].buffer = *input_message_buffer;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[1].buffer.value = NULL;
    iov[1].buffer.length = 0;

    major = gssBidUnwrapOrVerifyMIC(minor, ctx, conf_state, qop_state,
                                    iov, 2, TOK_TYPE_WRAP);
    if (major == GSS_S_COMPLETE) {
        *output_message_buffer = iov[1].buffer;
    } else {
        if (iov[1].type & GSS_IOV_BUFFER_FLAG_ALLOCATED)
            gss_release_buffer(&tmpMinor, &iov[1].buffer);
    }

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
