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
 *
 */

#include "gssapiP_bid.h"

OM_uint32 GSSAPI_CALLCONV
gssBidExchangeMetaData(OM_uint32 *minor,
                       gss_const_OID mech GSSBID_UNUSED,
                       gss_cred_id_t cred GSSBID_UNUSED,
                       gss_ctx_id_t *context_handle,
                       const gss_name_t name,
                       OM_uint32 req_flags GSSBID_UNUSED,
                       gss_const_buffer_t meta_data)
{
    OM_uint32 major;
    int isInitiator = (name != GSS_C_NO_NAME);

    if (isInitiator && meta_data->length) {
        gss_buffer_desc metaDataToken = GSS_C_EMPTY_BUFFER;
        gss_ctx_id_t ctx = *context_handle;
        enum gss_bid_token_type actualTokenType;
        gss_OID oidBuf;

        GSSBID_ASSERT(ctx != GSS_C_NO_CONTEXT);

        oidBuf = ctx->mechanismUsed;

        /* No OID headers on metadata */
        major = gssBidVerifyToken(minor, (gss_buffer_t)meta_data, &actualTokenType,
                                  &metaDataToken, &oidBuf);
        if (GSS_ERROR(major))
            goto cleanup;

        if (actualTokenType != TOK_TYPE_ACCEPTOR_META_DATA) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSBID_WRONG_TOK_ID;
            goto cleanup;
        }

        major = gssBidProcessRPCerts(minor, ctx, &metaDataToken);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_exchange_meta_data(OM_uint32 *minor,
                       gss_const_OID mech,
                       gss_cred_id_t cred,
                       gss_ctx_id_t *context_handle,
                       const gss_name_t name,
                       OM_uint32 req_flags,
                       gss_const_buffer_t meta_data)
{
    gss_ctx_id_t ctx = *context_handle;
    OM_uint32 major;

    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_LOCK(&cred->mutex);

    if (*context_handle != GSS_C_NO_CONTEXT)
        GSSBID_MUTEX_LOCK(&ctx->mutex);

    major = gssBidExchangeMetaData(minor, mech, cred, &ctx,
                                   name, req_flags, meta_data);

    if (*context_handle != GSS_C_NO_CONTEXT)
        GSSBID_MUTEX_UNLOCK(&ctx->mutex);
    else
        *context_handle = ctx;

    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_UNLOCK(&cred->mutex);

    return major;
}
