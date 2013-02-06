/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
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
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
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
    int initialContextToken = (GSSBID_SM_STATE(ctx) == GSSBID_STATE_INITIAL);

    if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSBID_BAD_CONTEXT_TOKEN;
        goto cleanup;
    }

    if (initialContextToken) {
        major = initBegin(minor, ctx, target_name, mech_type,
                          req_flags, time_req, input_chan_bindings);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    BID_ASSERT(ctx->cred->assertion.length != 0);

    major = gssBidMakeToken(minor, ctx, &ctx->cred->assertion,
                            TOK_TYPE_INITIATOR_CONTEXT, initialContextToken,
                            output_token);
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
                       gss_name_t target_name,
                       gss_OID mech_type GSSBID_UNUSED,
                       OM_uint32 req_flags,
                       OM_uint32 time_req GSSBID_UNUSED,
                       gss_channel_bindings_t input_chan_bindings GSSBID_UNUSED,
                       gss_buffer_t input_token,
                       gss_OID *actual_mech_type GSSBID_UNUSED,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags GSSBID_UNUSED,
                       OM_uint32 *time_rec GSSBID_UNUSED)
{
    OM_uint32 major, tmpMinor;
    json_t *response = NULL;
    json_t *tkt = NULL;
    char *szAssertion = NULL;
    BIDError err;
    gss_buffer_desc bufInnerToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc bufAudienceOrSpn = GSS_C_EMPTY_BUFFER;
    enum gss_bid_token_type actualTokenType;
    uint32_t ulReqFlags, ulRetFlags = 0;

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

    major = bufferToString(minor, &bufInnerToken, &szAssertion);
    if (GSS_ERROR(major))
        goto cleanup;

    if (target_name != GSS_C_NO_NAME) {
        major = gssBidDisplayName(minor, target_name, &bufAudienceOrSpn, NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    ulReqFlags = 0;
    if (ctx->encryptionType != ENCTYPE_NULL)
        ulReqFlags |= BID_RP_FLAG_HAVE_SESSION_KEY;
    if ((ctx->flags & CTX_FLAG_REAUTH) == 0) {
        ulReqFlags |= BID_RP_FLAG_INITIAL;
        if (req_flags & GSS_C_MUTUAL_FLAG)
            ulReqFlags |= BID_RP_FLAG_VERIFY_NONCE;
    }

    err = BIDVerifyRPResponseToken(ctx->bidContext,
                                   ctx->bidIdentity,
                                   szAssertion,
                                   (const char *)bufAudienceOrSpn.value,
                                   ulReqFlags,
                                   &response,
                                   &ulRetFlags);

    major = json_integer_value(json_object_get(response, "gss-maj"));
    *minor = json_integer_value(json_object_get(response, "gss-min"));
    if (GSS_ERROR(major) || *minor != 0)
        goto cleanup;
    if (err == BID_S_MISSING_SIGNATURE && ctx->encryptionType == ENCTYPE_NULL)
        err = BID_S_OK; /* couldn't have signed */
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    _BIDGetJsonTimestampValue(ctx->bidContext, response, "exp", &ctx->expiryTime);

    major = gssBidContextReady(minor, ctx, cred); /* need key to verify */
    if (GSS_ERROR(major))
        goto cleanup;

    if ((ctx->flags & CTX_FLAG_REAUTH) == 0) {
        if (ulRetFlags & BID_RP_FLAG_VALIDATED_CERTS)
            ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
        else
            ctx->gssFlags &= ~(GSS_C_MUTUAL_FLAG);
    }

    tkt = json_object_get(response, "tkt");
    if (tkt != NULL && target_name != GSS_C_NO_NAME) {
        uint32_t ulTicketFlags = 0;

        if (ctx->gssFlags & GSS_C_MUTUAL_FLAG)
            ulTicketFlags |= BID_TICKET_FLAG_MUTUAL_AUTH;

        _BIDStoreTicketInCache(ctx->bidContext, ctx->bidIdentity,
                               (const char *)bufAudienceOrSpn.value, tkt,
                               ulTicketFlags);
    }

    output_token->length = 0;
    output_token->value = NULL;

    GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_ESTABLISHED);

cleanup:
    GSSBID_FREE(szAssertion);
    json_decref(response);
    gss_release_buffer(&tmpMinor, &bufAudienceOrSpn);

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
                                           target_name, req_flags,
                                           input_chan_bindings);
        if (GSS_ERROR(major))
            goto cleanup;

        GSSBID_ASSERT(ctx->cred != GSS_C_NO_CREDENTIAL);
    }

    GSSBID_MUTEX_LOCK(&ctx->cred->mutex);
    GSSBID_ASSERT(ctx->cred->flags & CRED_FLAG_RESOLVED);
    GSSBID_ASSERT(ctx->cred->flags & CRED_FLAG_INITIATE);

    major = GSS_S_FAILURE;
    *minor = GSSBID_REAUTH_FAILED;

    while (*minor == GSSBID_REAUTH_FAILED) {
        switch (GSSBID_SM_STATE(ctx)) {
        case GSSBID_STATE_INITIAL:
        case GSSBID_STATE_RETRY_INITIAL:
            major = gssBidInitAssertionToken(minor, cred, ctx, target_name,
                                             mech_type, req_flags, time_req,
                                             input_chan_bindings, input_token,
                                             actual_mech_type, output_token,
                                             ret_flags, time_rec);
            break;
        case GSSBID_STATE_AUTHENTICATE:
        case GSSBID_STATE_RETRY_AUTHENTICATE:
            major = gssBidInitResponseToken(minor, cred, ctx, target_name,
                                            mech_type, req_flags, time_req,
                                            input_chan_bindings, input_token,
                                            actual_mech_type, output_token,
                                            ret_flags, time_rec);
            if (*minor == GSSBID_REAUTH_FAILED &&
                (ctx->flags & CTX_FLAG_REAUTH) &&
                GSSBID_SM_STATE(ctx) != GSSBID_STATE_RETRY_AUTHENTICATE) {
                GSSBID_ASSERT(output_token->value == NULL);

                GSSBID_MUTEX_UNLOCK(&ctx->cred->mutex);
                gssBidReleaseCred(&tmpMinor, &ctx->cred);

                BIDReleaseIdentity(ctx->bidContext, ctx->bidIdentity);
                ctx->bidIdentity = BID_C_NO_IDENTITY;

                major = gssBidResolveInitiatorCred(&tmpMinor, cred, ctx,
                                                   target_name, req_flags,
                                                   input_chan_bindings);
                if (GSS_ERROR(major)) {
                    *minor = tmpMinor;
                    goto cleanup;
                }

                GSSBID_ASSERT((ctx->flags & CTX_FLAG_REAUTH) == 0);
                GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_RETRY_INITIAL);

                input_token = GSS_C_NO_BUFFER;

                GSSBID_MUTEX_LOCK(&ctx->cred->mutex);
            }
            break;
        case GSSBID_STATE_ESTABLISHED:
            major = GSS_S_FAILURE;
            *minor = GSSBID_CONTEXT_ESTABLISHED;
            break;
        }
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
