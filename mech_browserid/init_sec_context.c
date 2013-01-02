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
 * Establish a security context on the initiator (client). These functions
 * wrap around libbrowserid.
 */

#include "gssapiP_bid.h"

static OM_uint32
initBegin(OM_uint32 *minor,
          gss_ctx_id_t ctx,
          gss_name_t target,
          gss_OID mech GSSBID_UNUSED,
          OM_uint32 reqFlags GSSBID_UNUSED,
          OM_uint32 timeReq,
          gss_channel_bindings_t chanBindings GSSBID_UNUSED)
{
    OM_uint32 major;
    gss_cred_id_t cred = ctx->cred;

    GSSBID_ASSERT(cred != GSS_C_NO_CREDENTIAL);

    if (cred->expiryTime)
        ctx->expiryTime = cred->expiryTime;
    else if (timeReq == 0 || timeReq == GSS_C_INDEFINITE)
        ctx->expiryTime = 0;
    else
        ctx->expiryTime = time(NULL) + timeReq;

    /*
     * The credential mutex protects its name, however we need to
     * explicitly lock the acceptor name (unlikely as it may be
     * that it has attributes set on it).
     */
    major = gssBidDuplicateName(minor, cred->name, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (target != GSS_C_NO_NAME) {
        GSSBID_MUTEX_LOCK(&target->mutex);

        major = gssBidDuplicateName(minor, target, &ctx->acceptorName);
        if (GSS_ERROR(major)) {
            GSSBID_MUTEX_UNLOCK(&target->mutex);
            return major;
        }

        GSSBID_MUTEX_UNLOCK(&target->mutex);
    }

    /* If credentials were provided, check they're usable with this mech */
    if (!gssBidCredAvailable(cred, ctx->mechanismUsed)) {
        *minor = GSSBID_CRED_MECH_MISMATCH;
        return GSS_S_BAD_MECH;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidInitAssertionToken(OM_uint32 *minor,
                         gss_cred_id_t cred GSSBID_UNUSED,
                         gss_ctx_id_t ctx,
                         gss_name_t target_name GSSBID_UNUSED,
                         gss_OID mech_type GSSBID_UNUSED,
                         OM_uint32 req_flags GSSBID_UNUSED,
                         OM_uint32 time_req GSSBID_UNUSED,
                         gss_channel_bindings_t input_chan_bindings GSSBID_UNUSED,
                         gss_buffer_t input_token,
                         gss_OID *actual_mech_type GSSBID_UNUSED,
                         gss_buffer_t output_token,
                         OM_uint32 *ret_flags GSSBID_UNUSED,
                         OM_uint32 *time_rec GSSBID_UNUSED)
{
    OM_uint32 major;

    if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_BAD_CONTEXT_TOKEN;
        goto cleanup;
    }

    major = initBegin(minor, ctx, target_name, mech_type,
                      req_flags, time_req, input_chan_bindings);
    if (GSS_ERROR(major))
        goto cleanup;

    BID_ASSERT(ctx->cred->assertion.length != 0);

    major = gssBidMakeToken(minor, ctx, &ctx->cred->assertion, TOK_TYPE_INITIATOR_CONTEXT, output_token);
    if (GSS_ERROR(major))
        goto cleanup;

    ctx->expiryTime = ctx->cred->expiryTime;

    GSSBID_SM_TRANSITION_NEXT(ctx);

    major = GSS_S_CONTINUE_NEEDED;

cleanup:
    return major;
}

OM_uint32
gssBidInitResponseToken(OM_uint32 *minor,
                       gss_cred_id_t cred,
                       gss_ctx_id_t ctx,
                       gss_name_t target_name GSSBID_UNUSED,
                       gss_OID mech_type GSSBID_UNUSED,
                       OM_uint32 req_flags GSSBID_UNUSED,
                       OM_uint32 time_req GSSBID_UNUSED,
                       gss_channel_bindings_t input_chan_bindings GSSBID_UNUSED,
                       gss_buffer_t input_token,
                       gss_OID *actual_mech_type GSSBID_UNUSED,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags GSSBID_UNUSED,
                       OM_uint32 *time_rec GSSBID_UNUSED)
{
    OM_uint32 major;
    json_t *response = NULL;
    char *szJson = NULL;
    BIDError err;
    gss_buffer_desc bufInnerToken = GSS_C_EMPTY_BUFFER;
    enum gss_bid_token_type actualTokenType;
    const char *status;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_TOK_TRUNC;
        goto cleanup;
    }

    major = gssBidVerifyToken(minor, input_token, &actualTokenType,
                              &bufInnerToken, &ctx->mechanismUsed);
    if (GSS_ERROR(major))
        goto cleanup;

    if (actualTokenType != TOK_TYPE_ACCEPTOR_CONTEXT) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_WRONG_TOK_ID;
        goto cleanup;
    }

    major = bufferToString(minor, &bufInnerToken, &szJson);
    if (GSS_ERROR(major))
        goto cleanup;

    err = _BIDDecodeJson(ctx->bidContext, szJson, BID_JSON_ENCODING_BASE64, &response);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    status = json_string_value(json_object_get(response, "status"));
    if (status == NULL || strcmp(status, "okay") != 0) {
        major = GSS_S_FAILURE; /* XXX we need better error reporting */
        goto cleanup;
    }

    if (ctx->encryptionType != ENCTYPE_NULL) {
        json_t *dh = json_object_get(response, "dh");

        err = _BIDSetIdentityDHPublicValue(ctx->bidContext, ctx->bidIdentity,
                                           json_object_get(dh, "y"));
        if (err != BID_S_OK) {
            major = gssBidMapError(minor, err);
            goto cleanup;
        }
    }

    major = gssBidContextReady(minor, ctx, cred);
    if (GSS_ERROR(major))
        goto cleanup;

    output_token->length = 0;
    output_token->value = NULL;

    GSSBID_SM_TRANSITION_NEXT(ctx);

cleanup:
    GSSBID_FREE(szJson);
    json_decref(response);

    return major;
}

OM_uint32
gssBidInitSecContext(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t ctx,
                     gss_name_t target_name,
                     gss_OID mech_type GSSBID_UNUSED,
                     OM_uint32 req_flags GSSBID_UNUSED,
                     OM_uint32 time_req GSSBID_UNUSED,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;

    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_LOCK(&cred->mutex);

    if (ctx->cred == GSS_C_NO_CREDENTIAL) {
        major = gssBidResolveInitiatorCred(minor, cred, ctx,
                                           target_name,
                                           input_chan_bindings,
                                           &ctx->cred);
        if (GSS_ERROR(major))
            goto cleanup;

        GSSBID_ASSERT(ctx->cred != GSS_C_NO_CREDENTIAL);
    }

    GSSBID_MUTEX_LOCK(&ctx->cred->mutex);
    GSSBID_ASSERT(ctx->cred->flags & CRED_FLAG_RESOLVED);
    GSSBID_ASSERT(ctx->cred->flags & CRED_FLAG_INITIATE);

    switch (ctx->state) {
    case GSSBID_STATE_INITIAL:
        major = gssBidInitAssertionToken(minor, cred, ctx, target_name,
                                         mech_type, req_flags, time_req,
                                         input_chan_bindings, input_token,
                                         actual_mech_type, output_token,
                                         ret_flags, time_rec);
        break;
    case GSSBID_STATE_AUTHENTICATE:
        major = gssBidInitResponseToken(minor, cred, ctx, target_name,
                                        mech_type, req_flags, time_req,
                                        input_chan_bindings, input_token,
                                        actual_mech_type, output_token,
                                        ret_flags, time_rec);
        break;
    case GSSBID_STATE_ESTABLISHED:
    default:
        major = GSS_S_FAILURE;
        *minor = GSSBID_CONTEXT_ESTABLISHED;
        goto cleanup;
    }

    if (GSS_ERROR(major))
        goto cleanup;

    if (actual_mech_type != NULL) {
        OM_uint32 tmpMajor;

        tmpMajor = gssBidCanonicalizeOid(&tmpMinor, ctx->mechanismUsed, 0, actual_mech_type);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (time_rec != NULL)
        gssBidContextTime(&tmpMinor, ctx, time_rec);

    GSSBID_ASSERT(CTX_IS_ESTABLISHED(ctx) || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    if (cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_UNLOCK(&cred->mutex);
    if (ctx->cred != GSS_C_NO_CREDENTIAL)
        GSSBID_MUTEX_UNLOCK(&ctx->cred->mutex);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_init_sec_context(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t *context_handle,
                     gss_name_t target_name,
                     gss_OID mech_type,
                     OM_uint32 req_flags,
                     OM_uint32 time_req,
                     gss_channel_bindings_t input_chan_bindings,
                     gss_buffer_t input_token,
                     gss_OID *actual_mech_type,
                     gss_buffer_t output_token,
                     OM_uint32 *ret_flags,
                     OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            *minor = GSSBID_WRONG_SIZE;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        major = gssBidAllocContext(minor, TRUE, mech_type, &ctx);
        if (GSS_ERROR(major))
            return major;

        *context_handle = ctx;
    }

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    major = gssBidInitSecContext(minor,
                                 cred,
                                 ctx,
                                 target_name,
                                 mech_type,
                                 req_flags,
                                 time_req,
                                 input_chan_bindings,
                                 input_token,
                                 actual_mech_type,
                                 output_token,
                                 ret_flags,
                                 time_rec);

    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssBidReleaseContext(&tmpMinor, context_handle);

    return major;
}
