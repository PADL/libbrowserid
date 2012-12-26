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
 * Message protection services: determine maximum input size.
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gss_wrap_size_limit(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    OM_uint32 req_output_size,
                    OM_uint32 *max_input_size)
{
    gss_iov_buffer_desc iov[4];
    OM_uint32 major, overhead;

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

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].buffer.length = req_output_size;
    iov[1].buffer.value = NULL;

    iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
    iov[2].buffer.value = NULL;
    iov[2].buffer.length = 0;

    iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[3].buffer.value = NULL;
    iov[3].buffer.length = 0;

    major = gssBidWrapIovLength(minor, ctx, conf_req_flag, qop_req,
                                NULL, iov, 4);
    if (GSS_ERROR(major))
        goto cleanup;

    overhead = iov[0].buffer.length + iov[3].buffer.length;

    if (iov[2].buffer.length == 0 && overhead < req_output_size)
        *max_input_size = req_output_size - overhead;
    else
        *max_input_size = 0;

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
