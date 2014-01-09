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
 *    how to obtain complete source code for the libbrowserid software
 *    and any accompanying software that uses the libbrowserid software.
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
 * Establish a security context on the acceptor (server). These functions
 * wrap around libbrowserid.
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
    json_t *response = NULL;
    json_t *iat = NULL;
    BIDError err;
    uint32_t ulReqFlags, ulRetFlags = 0;

    response = json_object();
    if (response == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    if (ctx->expiryTime != 0)
        _BIDSetJsonTimestampValue(ctx->bidContext, response, "exp", ctx->expiryTime);
    if (GSS_ERROR(protocolMajor))
        json_object_set_new(response, "gss-maj", json_integer(protocolMajor));
    if (protocolMinor != 0) {
        _BIDGetCurrentJsonTimestamp(ctx->bidContext, &iat);
        json_object_set(response, "iat", iat); /* for skew compensation */
        json_object_set_new(response, "gss-min", json_integer(protocolMinor));
    }

    ulReqFlags = 0;
    if (ctx->encryptionType != ENCTYPE_NULL && ctx->bidIdentity != BID_C_NO_IDENTITY)
        ulReqFlags |= BID_RP_FLAG_HAVE_SESSION_KEY;
    if ((ctx->flags & CTX_FLAG_REAUTH) == 0)
        ulReqFlags |= BID_RP_FLAG_INITIAL;

    err = BIDMakeRPResponseToken(ctx->bidContext,
                                 ctx->bidIdentity,
                                 response,
                                 ulReqFlags,
                                 (char **)&bufJson.value,
                                 &bufJson.length,
                                 &ulRetFlags);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    if (ulRetFlags & BID_RP_FLAG_X509)
        ctx->gssFlags |= GSS_C_MUTUAL_FLAG;

    major = duplicateBuffer(minor, &bufJson, outputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    json_decref(iat);
    json_decref(response);
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
    OM_uint32 major, tmpMajor, tmpMinor;
    BIDError err;
    char *szAssertion = NULL;
    gss_buffer_desc bufAudienceOrSpn = GSS_C_EMPTY_BUFFER;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    uint32_t ulReqFlags, ulRetFlags = 0;

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

    if (ctx->acceptorName == GSS_C_NO_NAME && cred->name != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (cred->name != GSS_C_NO_NAME) {
        major = gssBidDisplayName(minor, cred->name, &bufAudienceOrSpn, NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
        pbChannelBindings = (const unsigned char *)input_chan_bindings->application_data.value;
        cbChannelBindings = input_chan_bindings->application_data.length;
    }

    ulReqFlags = BID_VERIFY_FLAG_AGGREGATE_ATTR_CERTS;

    switch (GSSBID_SM_STATE(ctx)) {
    case GSSBID_STATE_INITIAL:
        ulReqFlags |= BID_VERIFY_FLAG_REAUTH;
    case GSSBID_STATE_RETRY_INITIAL:
        err = BIDVerifyAssertion(ctx->bidContext,
                                 cred->bidReplayCache,
                                 szAssertion,
                                 (char *)bufAudienceOrSpn.value,
                                 pbChannelBindings,
                                 cbChannelBindings,
                                 time(NULL),
                                 ulReqFlags,
                                 &ctx->bidIdentity,
                                 &ctx->expiryTime,
                                 &ulRetFlags);
         major = gssBidMapError(minor, err);
         if (ulRetFlags & BID_VERIFY_FLAG_REAUTH) {
            uint32_t ulContextOptions = 0;

            BIDGetContextParam(ctx->bidContext, BID_PARAM_CONTEXT_OPTIONS, (void **)&ulContextOptions);

            /*
             * The following errors are recoverable and the initiator should send a
             * fresh, certificate-signed assertion:
             *
             * - The assertion was not found in the replay cache
             * - The assertion has expired
             * - The initiator assumed it could send a ticket for the host SPN
             *   but the acceptor does not have HOST_SPN_ALIAS set
             */
            if (err == BID_S_INVALID_ASSERTION || err == BID_S_EXPIRED_ASSERTION ||
                ((ulContextOptions & BID_CONTEXT_HOST_SPN_ALIAS) == 0 && err == BID_S_BAD_AUDIENCE)) {
                major = GSS_S_CONTINUE_NEEDED;
                *minor = GSSBID_REAUTH_FAILED;
            } else
                ctx->flags |= CTX_FLAG_REAUTH;
        }
        if ((ulRetFlags & BID_VERIFY_FLAG_REAUTH_MUTUAL) &&     /* master (transitive) context */
            (ulRetFlags & BID_VERIFY_FLAG_MUTUAL_AUTH))         /* initiator context opts */
            ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
        if (ulRetFlags & BID_VERIFY_FLAG_EXTRA_ROUND_TRIP) {
            major = GSS_S_CONTINUE_NEEDED;
            ctx->flags |= CTX_FLAG_EXTRA_ROUND_TRIP;
        }
        if (ulRetFlags & BID_VERIFY_FLAG_DCE)
            ctx->gssFlags |= GSS_C_DCE_STYLE;
        if (ulRetFlags & BID_VERIFY_FLAG_IDENTIFY)
            ctx->gssFlags |= GSS_C_IDENTIFY_FLAG;
        break;
    case GSSBID_STATE_EXTRA_ROUND_TRIP:
        err = BIDVerifyXRTToken(ctx->bidContext,
                                ctx->bidIdentity,
                                szAssertion,
                                0,
                                NULL,
                                &ulRetFlags);
        major = gssBidMapError(minor, err);
        break;
    default:
        GSSBID_ASSERT(0 && "Invalid state");
        break;
    }

    if (major == GSS_S_COMPLETE) {
        major = gssBidContextReady(minor, ctx, cred);
    }

    if (GSSBID_SM_STATE(ctx) != GSSBID_STATE_EXTRA_ROUND_TRIP) {
        tmpMajor = makeResponseToken(minor, ctx, major, gssBidApiToWireError(*minor), output_token);
        if (GSS_ERROR(tmpMajor))
            major = tmpMajor;
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (major == GSS_S_CONTINUE_NEEDED) {
        if (ctx->flags & CTX_FLAG_EXTRA_ROUND_TRIP)
            GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_EXTRA_ROUND_TRIP);
        else
            GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_RETRY_INITIAL);
    } else {
        GSSBID_SM_TRANSITION(ctx, GSSBID_STATE_ESTABLISHED);
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
#ifdef HAVE_HEIMDAL_VERSION
                       gss_const_cred_id_t cred_const,
                       const gss_buffer_t input_token,
                       const gss_channel_bindings_t input_chan_bindings,
#else
                       gss_cred_id_t cred,
                       gss_buffer_t input_token,
                       gss_channel_bindings_t input_chan_bindings,
#endif
                       gss_name_t *src_name,
                       gss_OID *mech_type,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags,
                       OM_uint32 *time_rec,
                       gss_cred_id_t *delegated_cred_handle)
{
#ifdef HAVE_HEIMDAL_VERSION
    gss_cred_id_t cred = (gss_cred_id_t)cred_const;
#endif
    OM_uint32 major, tmpMajor, tmpMinor;
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

        /*
         * Even if there was a NegoEx exchange, there should still be a
         * token header on the very first token.
         */
        if (GSSBID_SM_STATE(ctx) != GSSBID_STATE_INITIAL)
            mech = ctx->mechanismUsed;
    }

    major = gssBidVerifyToken(minor, input_token, &actualTokenType,
                              &innerInputToken, &mech);
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
        tmpMajor = gssBidMakeToken(&tmpMinor, ctx, &innerOutputToken,
                                   TOK_TYPE_ACCEPTOR_CONTEXT, 0, output_token);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            goto cleanup;
        }
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
