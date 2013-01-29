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

OM_uint32
gssBidQueryMetaData(OM_uint32 *minor,
                    gss_const_OID mech,
                    gss_cred_id_t cred,
                    gss_ctx_id_t *context_handle,
                    const gss_name_t name,
                    OM_uint32 req_flags,
                    gss_buffer_t meta_data)
{
    OM_uint32 major = GSS_S_COMPLETE, tmpMinor;
    int isInitiator = (name != GSS_C_NO_NAME);
    gss_ctx_id_t ctx = *context_handle;
    gss_buffer_desc metaDataToken = GSS_C_EMPTY_BUFFER;

    meta_data->length = 0;
    meta_data->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        major = gssBidAllocContext(minor, isInitiator, mech, &ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        if (isInitiator)
            ctx->flags |= CTX_FLAG_INITIATOR;
    }

    /*
     * If the credential can be resolved and contains certificate anchors,
     * then we can eliminate the server probe (this is done in util_negoex.c).
     *
     * If the credential cannot be resolved, we should still attempt the
     * probe as long as we have a username.
     */
    if (CTX_IS_INITIATOR(ctx)) {
        if (ctx->cred == GSS_C_NO_CREDENTIAL) {
            major = gssBidResolveInitiatorCred(minor, cred, ctx, name,
                                               req_flags,
                                               GSS_C_NO_CHANNEL_BINDINGS);
            if (GSS_ERROR(major) &&
                *minor != GSSBID_NO_DEFAULT_CRED)
                goto cleanup;
        }

        if (ctx->cred == GSS_C_NO_CREDENTIAL &&
            (cred == GSS_C_NO_CREDENTIAL || cred->name == NULL)) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSBID_NO_DEFAULT_CRED;
            goto cleanup;
        }
    } else if (ctx->cred == GSS_C_NO_CREDENTIAL) {
        major = gssBidAcquireCred(minor,
                                  GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET,
                                  GSS_C_ACCEPT,
                                  &ctx->cred,
                                  NULL,
                                  NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (!CTX_IS_INITIATOR(ctx)) {
        major = gssBidIndicateRPCerts(minor, ctx, &metaDataToken);
        if (GSS_ERROR(major))
            goto cleanup;

        if (metaDataToken.length) {
            major = gssBidMakeToken(minor, ctx, &metaDataToken,
                                    TOK_TYPE_ACCEPTOR_META_DATA, meta_data);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

cleanup:
    gss_release_buffer(&tmpMinor, &metaDataToken);

    if (*context_handle == GSS_C_NO_CONTEXT) {
        if (GSS_ERROR(major))
            gssBidReleaseContext(&tmpMinor, &ctx);
        else
            *context_handle = ctx;
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_query_meta_data(OM_uint32 *minor,
                    gss_const_OID mech,
                    gss_cred_id_t cred,
                    gss_ctx_id_t *context_handle,
                    const gss_name_t name,
                    OM_uint32 req_flags,
                    gss_buffer_t meta_data)
{
    gss_ctx_id_t ctx = *context_handle;
    OM_uint32 major;

    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_LOCK(&cred->mutex);

    if (*context_handle != GSS_C_NO_CONTEXT)
        GSSBID_MUTEX_LOCK(&ctx->mutex);

    major = gssBidQueryMetaData(minor, mech, cred, &ctx,
                                name, req_flags, meta_data);

    if (*context_handle != GSS_C_NO_CONTEXT)
        GSSBID_MUTEX_UNLOCK(&ctx->mutex);
    else
        *context_handle = ctx;

    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_UNLOCK(&cred->mutex);

    return major;
}
