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
                  OM_uint32 protocolMinor,
                  gss_buffer_t outputToken)
{
    OM_uint32 major;
    gss_buffer_desc bufJson = GSS_C_EMPTY_BUFFER;
    json_t *response = NULL, *status;
    json_t *dh = NULL;
    const char *szTicket = NULL;
    BIDError err;

    response = json_object();
    if (response == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    if (ctx->encryptionType != ENCTYPE_NULL) {
        err = _BIDGetIdentityDHPublicValue(ctx->bidContext, ctx->bidIdentity, &dh);
        if (err != BID_S_OK) {
            major =  gssBidMapError(minor, err);
            goto cleanup;
        }

        if (json_object_set(response, "dh", dh) != 0) {
            major = GSS_S_FAILURE;
            *minor = ENOMEM;
            goto cleanup;
        }
    }

    if (ctx->bidIdentity != BID_C_NO_IDENTITY) {
        err = BIDGetIdentityReauthTicket(ctx->bidContext, ctx->bidIdentity, &szTicket);
        if (err == BID_S_OK)
            json_object_set(response, "ticket", json_string(szTicket));
    }

    status = json_string(protocolMajor == GSS_S_COMPLETE ? "okay" : "failure");
    json_object_set(response, "status", status);
    json_object_set_new(response, "gss-major-status", json_integer(protocolMajor));
    json_object_set_new(response, "gss-minor-status", json_integer(protocolMinor));

    /* XXX using CRK directly */
    err = BIDMakeJsonWebToken(ctx->bidContext, response,
                              KRB_KEY_DATA(&ctx->rfc3961Key),
                              KRB_KEY_LENGTH(&ctx->rfc3961Key),
                              (char **)&bufJson.value, &bufJson.length);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    major = duplicateBuffer(minor, &bufJson, outputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    json_decref(response);
    json_decref(dh);
    BIDFreeData(ctx->bidContext, bufJson.value);

    return major;
}

OM_uint32
gssBidAcceptSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t input_token,
                       gss_channel_bindings_t input_chan_bindings,
                       gss_name_t *src_name GSSBID_UNUSED,
                       gss_OID *mech_type GSSBID_UNUSED,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags GSSBID_UNUSED,
                       OM_uint32 *time_rec GSSBID_UNUSED,
                       gss_cred_id_t *delegated_cred_handle GSSBID_UNUSED)
{
    OM_uint32 major, tmpMinor;
    BIDError err;
    char *szAssertion = NULL;
    gss_buffer_desc bufAudienceOrSpn = GSS_C_EMPTY_BUFFER;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;

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

    major = bufferToString(minor, input_token, &szAssertion);
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
    if (major == GSS_S_COMPLETE) {
        major = gssBidContextReady(minor, ctx, cred);
    }

    major = makeResponseToken(minor, ctx, major, *minor, output_token);
    if (GSS_ERROR(major))
        goto cleanup;

    GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_ESTABLISHED);

    if (cred->name != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            goto cleanup;
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
    gss_buffer_desc innerInputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc innerOutputToken = GSS_C_EMPTY_BUFFER;
    enum gss_bid_token_type actualTokenType;
    gss_OID mech = GSS_C_NO_OID;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (src_name != NULL)
        *src_name = GSS_C_NO_NAME;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx != GSS_C_NO_CONTEXT) {
        GSSBID_MUTEX_LOCK(&ctx->mutex);
        mech = ctx->mechanismUsed;
    }

    major = gssBidVerifyToken(minor, input_token, &actualTokenType, &innerInputToken, &mech);
    if (GSS_ERROR(major))
        goto cleanup;

    if (actualTokenType != TOK_TYPE_INITIATOR_CONTEXT) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_WRONG_TOK_ID;
        goto cleanup;
    }

    if (ctx == GSS_C_NO_CONTEXT) {
        major = gssBidAllocContext(minor, FALSE, mech, &ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        *context_handle = ctx;

        GSSBID_MUTEX_LOCK(&ctx->mutex);
        ctx->mechanismUsed = mech;
    }

    major = gssBidAcceptSecContext(minor,
                                   ctx,
                                   cred,
                                   &innerInputToken,
                                   input_chan_bindings,
                                   src_name,
                                   mech_type,
                                   &innerOutputToken,
                                   ret_flags,
                                   time_rec,
                                   delegated_cred_handle);
    if (GSS_ERROR(major))
        goto cleanup;

    if (innerOutputToken.value != NULL) {
        major = gssBidMakeToken(&tmpMinor, ctx, &innerOutputToken, TOK_TYPE_ACCEPTOR_CONTEXT, output_token);
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

cleanup:
    if (ctx != GSS_C_NO_CONTEXT)
        GSSBID_MUTEX_UNLOCK(&ctx->mutex);
    if (GSS_ERROR(major))
        gssBidReleaseContext(&tmpMinor, context_handle);
    gss_release_buffer(&tmpMinor, &innerOutputToken);

    return major;
}
