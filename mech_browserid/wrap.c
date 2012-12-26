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
 * Message protection services: wrap.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_wrap(OM_uint32 *minor,
         gss_ctx_id_t ctx,
         int conf_req_flag,
         gss_qop_t qop_req,
         gss_buffer_t input_message_buffer,
         int *conf_state,
         gss_buffer_t output_message_buffer)
{
    OM_uint32 major;

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

    major = gssBidWrap(minor, ctx, conf_req_flag, qop_req,
                       input_message_buffer,
                       conf_state, output_message_buffer);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}

OM_uint32
gssBidWrap(OM_uint32 *minor,
           gss_ctx_id_t ctx,
           int conf_req_flag,
           gss_qop_t qop_req,
           gss_buffer_t input_message_buffer,
           int *conf_state,
           gss_buffer_t output_message_buffer)
{
    OM_uint32 major, tmpMinor;
    gss_iov_buffer_desc iov[4];
    unsigned char *p;
    int i;

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].buffer = *input_message_buffer;

    iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
    iov[2].buffer.value = NULL;
    iov[2].buffer.length = 0;

    iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[3].buffer.value = NULL;
    iov[3].buffer.length = 0;

    major = gssBidWrapIovLength(minor, ctx, conf_req_flag, qop_req,
                                NULL, iov, 4);
    if (GSS_ERROR(major)) {
        return major;
    }

    for (i = 0, output_message_buffer->length = 0; i < 4; i++) {
        output_message_buffer->length += iov[i].buffer.length;
    }

    output_message_buffer->value = GSSBID_MALLOC(output_message_buffer->length);
    if (output_message_buffer->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    for (i = 0, p = output_message_buffer->value; i < 4; i++) {
        if (iov[i].type == GSS_IOV_BUFFER_TYPE_DATA) {
            memcpy(p, input_message_buffer->value, input_message_buffer->length);
        }
        iov[i].buffer.value = p;
        p += iov[i].buffer.length;
    }

    major = gssBidWrapOrGetMIC(minor, ctx, conf_req_flag, conf_state,
                               iov, 4, TOK_TYPE_WRAP);
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, output_message_buffer);
    }

    return major;
}
