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

static OM_uint32
eapGssSmAcceptAuthenticate(OM_uint32 *minor,
                           gss_ctx_id_t ctx,
                           gss_cred_id_t cred,
                           gss_buffer_t inputToken,
                           gss_channel_bindings_t chanBindings,
                           gss_buffer_t outputToken)
{
    OM_uint32 major, tmpMinor;

cleanup:
    return major;
}


static struct eap_gss_acceptor_sm {
    enum gss_eap_token_type inputTokenType;
    enum gss_eap_token_type outputTokenType;
    OM_uint32 (*processToken)(OM_uint32 *,
                              gss_ctx_id_t,
                              gss_cred_id_t,
                              gss_buffer_t,
                              gss_channel_bindings_t,
                              gss_buffer_t);
} eapGssAcceptorSm[] = {
    { TOK_TYPE_EAP_RESP, TOK_TYPE_EAP_REQ, NULL },
};

OM_uint32
gss_accept_sec_context(OM_uint32 *minor,
                       gss_ctx_id_t *context_handle,
                       gss_cred_id_t cred,
                       gss_buffer_t input_token,
                       gss_channel_bindings_t input_chan_bindings,
                       gss_name_t *src_name,
                       gss_OID *mech_type,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags,
                       OM_uint32 *time_rec,
                       gss_cred_id_t *delegated_cred_handle)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;
    struct eap_gss_acceptor_sm *sm = NULL;
    gss_buffer_desc innerInputToken, innerOutputToken;
    
    *minor = 0;

    innerOutputToken.length = 0;
    innerOutputToken.value = NULL;

    output_token->length = 0;
    output_token->value = NULL;

    if (cred != GSS_C_NO_CREDENTIAL && !(cred->flags & CRED_FLAG_ACCEPT)) {
        return GSS_S_NO_CRED;
    }

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx == GSS_C_NO_CONTEXT) {
        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    sm = &eapGssAcceptorSm[ctx->state];

    major = gssEapVerifyToken(minor, ctx, input_token,
                              sm->inputTokenType, &innerInputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    major = (sm->processToken)(minor,
                               ctx,
                               cred,
                               &innerInputToken,
                               input_chan_bindings,
                               &innerOutputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (src_name != NULL && ctx->initiatorName != GSS_C_NO_NAME) {
        major = gss_duplicate_name(&minor, ctx->initiatorName, src_name);
        if (GSS_ERROR(major))
            goto cleanup;
    }
    if (mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, mech_type);
    }
    if (innerOutputToken.length != 0) {
        major = gssEapMakeToken(minor, ctx, &innerOutputToken,
                                sm->outputTokenType, output_token);
        if (GSS_ERROR(major))
            goto cleanup;
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (time_rec != NULL)
        gss_context_time(&tmpMinor, ctx, time_rec);
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    assert(ctx->state == EAP_STATE_ESTABLISHED || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);

    gss_release_buffer(&tmpMinor, &innerOutputToken);

    return major;
}
