/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */
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
 * Establish a security context on the acceptor (server). These functions
 * wrap around libradsec and (thus) talk to a RADIUS server or proxy.
 */

#include "gssapiP_bid.h"

static OM_uint32
makeResponseToken(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  OM_uint32 protocolMajor,
                  OM_uint32 protocolMinor GSSBID_UNUSED,
                  gss_buffer_t outputToken)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc bufJson = GSS_C_EMPTY_BUFFER;
    json_t *response, *status;
    BIDError err;

    response = json_object();
    if (response == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    status = json_string(protocolMajor == GSS_S_COMPLETE ? "okay" : "failure");
    if (json_object_set(response, "status", status) != 0) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    err = _BIDEncodeJson(ctx->bidContext, response, (char **)&bufJson.value, &bufJson.length);
    if (err != BID_S_OK) {
        json_decref(response);
        return gssBidMapError(minor, err);
    }

    major = gssBidMakeToken(&tmpMinor, ctx, &bufJson, TOK_TYPE_ACCEPTOR_CONTEXT, outputToken);
    if (GSS_ERROR(major)) {
        BIDFree(bufJson.value);
        *minor = tmpMinor;
        return major;
    }

    BIDFree(bufJson.value);
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidAcceptSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
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
    OM_uint32 major, tmpMajor, tmpMinor;
    BIDError err;
    char *szAssertion = NULL;
    gss_buffer_desc bufInnerToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc bufAudienceOrSpn = GSS_C_EMPTY_BUFFER;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    enum gss_bid_token_type actualTokenType;

    if (cred == GSS_C_NO_CREDENTIAL) {
        if (ctx->cred == GSS_C_NO_CREDENTIAL) {
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

        cred = ctx->cred;
    }

    if (CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_FAILURE;
        *minor = GSSBID_CONTEXT_ESTABLISHED;
        goto cleanup;
    }

    major = gssBidVerifyToken(minor, ctx, input_token, &actualTokenType, &bufInnerToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (actualTokenType != TOK_TYPE_INITIATOR_CONTEXT) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_WRONG_TOK_ID;
        goto cleanup;
    }

    major = bufferToString(minor, &bufInnerToken, &szAssertion);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssBidDisplayName(minor, cred->name, &bufAudienceOrSpn, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
        pbChannelBindings = (const unsigned char *)input_chan_bindings->application_data.value;
        cbChannelBindings = input_chan_bindings->application_data.length;
    }

    err = BIDVerifyAssertion(ctx->bidContext,
                             szAssertion,
                             (char *)bufAudienceOrSpn.value,
                             pbChannelBindings,
                             cbChannelBindings,
                             time(NULL),
                             &ctx->bidIdentity,
                             &ctx->expiryTime);
    major = gssBidMapError(minor, err);

    tmpMajor = makeResponseToken(minor, ctx, major, *minor, output_token);
    if (GSS_ERROR(tmpMajor))
        major = tmpMajor;
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssBidContextReady(minor, ctx, cred);
    if (GSS_ERROR(major))
        goto cleanup;

    GSSBID_SM_TRANSITION_NEXT(ctx);

    if (cred->name != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (mech_type != NULL) {
        OM_uint32 tmpMajor;

        tmpMajor = gssBidCanonicalizeOid(&tmpMinor, ctx->mechanismUsed, 0, mech_type);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (major == GSS_S_COMPLETE) {
        if (src_name != NULL && ctx->initiatorName != GSS_C_NO_NAME) {
            major = gssBidDuplicateName(&tmpMinor, ctx->initiatorName, src_name);
            if (GSS_ERROR(major))
                goto cleanup;
        }
        if (time_rec != NULL) {
            major = gssBidContextTime(&tmpMinor, ctx, time_rec);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

    GSSBID_ASSERT(CTX_IS_ESTABLISHED(ctx) || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    gss_release_buffer(&tmpMinor, &bufAudienceOrSpn);
    GSSBID_FREE(szAssertion);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
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

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (src_name != NULL)
        *src_name = GSS_C_NO_NAME;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx == GSS_C_NO_CONTEXT) {
        major = gssBidAllocContext(minor, FALSE, &ctx);
        if (GSS_ERROR(major))
            return major;

        *context_handle = ctx;
    }

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    major = gssBidAcceptSecContext(minor,
                                   ctx,
                                   cred,
                                   input_token,
                                   input_chan_bindings,
                                   src_name,
                                   mech_type,
                                   output_token,
                                   ret_flags,
                                   time_rec,
                                   delegated_cred_handle);

    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssBidReleaseContext(&tmpMinor, context_handle);

    return major;
}
