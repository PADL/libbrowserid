/*
 * Copyright (c) 2012, JANET(UK)
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

#include "gssapiP_eap.h"

static OM_uint32
eapNegoSmInitInitiatorName(OM_uint32 *minor,
                           gss_cred_id_t cred GSSEAP_UNUSED,
                           gss_ctx_id_t ctx,
                           gss_name_t target GSSEAP_UNUSED,
                           gss_OID mech GSSEAP_UNUSED,
                           OM_uint32 reqFlags GSSEAP_UNUSED,
                           OM_uint32 timeReq GSSEAP_UNUSED,
                           gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                           gss_buffer_t inputToken GSSEAP_UNUSED,
                           gss_buffer_t outputToken,
                           OM_uint32 *smFlags GSSEAP_UNUSED)
{
    gss_buffer_desc realm = GSS_C_EMPTY_BUFFER;

    GSSEAP_ASSERT(ctx->cred != GSS_C_NO_CREDENTIAL);
    GSSEAP_ASSERT(ctx->cred->name != GSS_C_NO_NAME);

    if ((ctx->cred->name->flags & (NAME_FLAG_NAI | NAME_FLAG_SERVICE)) == 0) {
        *minor = GSSEAP_BAD_INITIATOR_NAME;
        return GSS_S_BAD_NAME;
    }

#ifdef GSSEAP_SSP
    if (GsspFlags & GSSP_FLAG_SERVER_PROBE)
#else
    if (getenv("GSSEAP_PROBE"))
#endif
        ctx->cred->flags |= GSS_EAP_PROBE_EAP_SERVER;

    /*
     * If the context is already associated with a certificate or server
     * hash, we don't need to do the metadata exchange.
     */
    if (ctx->cred->caCertificate.length == 0 &&
        (ctx->cred->flags & GSS_EAP_PROBE_EAP_SERVER)) {
        krbPrincRealmToGssBuffer(ctx->cred->name->krbPrincipal, &realm);

        outputToken->value = GSSEAP_MALLOC(realm.length + 1);
        if (outputToken->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        ((char *)outputToken->value)[0] = '@';
        memcpy((char *)outputToken->value + 1, realm.value, realm.length);

        outputToken->length = realm.length + 1;
    }

    GSSEAP_SM_TRANSITION_NEXT(ctx);

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapNegoSmInitServerHash(OM_uint32 *minor,
                        gss_cred_id_t cred GSSEAP_UNUSED,
                        gss_ctx_id_t ctx,
                        gss_name_t target GSSEAP_UNUSED,
                        gss_OID mech GSSEAP_UNUSED,
                        OM_uint32 reqFlags GSSEAP_UNUSED,
                        OM_uint32 timeReq GSSEAP_UNUSED,
                        gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken GSSEAP_UNUSED,
                        OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    GSSEAP_ASSERT(ctx->initiatorCtx.serverHash.length == 0);

    major = duplicateBuffer(minor, inputToken, &ctx->initiatorCtx.serverHash);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapNegoSmInitServerSubject(OM_uint32 *minor,
                           gss_cred_id_t cred GSSEAP_UNUSED,
                           gss_ctx_id_t ctx,
                           gss_name_t target GSSEAP_UNUSED,
                           gss_OID mech GSSEAP_UNUSED,
                           OM_uint32 reqFlags GSSEAP_UNUSED,
                           OM_uint32 timeReq GSSEAP_UNUSED,
                           gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                           gss_buffer_t inputToken,
                           gss_buffer_t outputToken GSSEAP_UNUSED,
                           OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    GSSEAP_ASSERT(ctx->initiatorCtx.serverSubject.length == 0);

    major = duplicateBuffer(minor, inputToken, &ctx->initiatorCtx.serverSubject);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapNegoSmInitServerCert(OM_uint32 *minor,
                        gss_cred_id_t cred GSSEAP_UNUSED,
                        gss_ctx_id_t ctx,
                        gss_name_t target GSSEAP_UNUSED,
                        gss_OID mech GSSEAP_UNUSED,
                        OM_uint32 reqFlags GSSEAP_UNUSED,
                        OM_uint32 timeReq GSSEAP_UNUSED,
                        gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken GSSEAP_UNUSED,
                        OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major;

    GSSEAP_ASSERT(ctx->initiatorCtx.serverCert.length == 0);

    major = duplicateBuffer(minor, inputToken, &ctx->initiatorCtx.serverCert);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapNegoSmInitComplete(OM_uint32 *minor,
                      gss_cred_id_t cred GSSEAP_UNUSED,
                      gss_ctx_id_t ctx,
                      gss_name_t target GSSEAP_UNUSED,
                      gss_OID mech GSSEAP_UNUSED,
                      OM_uint32 reqFlags GSSEAP_UNUSED,
                      OM_uint32 timeReq GSSEAP_UNUSED,
                      gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                      gss_buffer_t inputToken GSSEAP_UNUSED,
                      gss_buffer_t outputToken GSSEAP_UNUSED,
                      OM_uint32 *smFlags GSSEAP_UNUSED)
{
    GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_ESTABLISHED);

    *minor = 0;
    return GSS_S_COMPLETE;
}

static struct gss_eap_sm eapNegoInitiatorSm[] = {
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_INITIATOR_NAME_MD,
        GSSEAP_STATE_INITIAL,
        0,
        eapNegoSmInitInitiatorName
    },
    {
        ITOK_TYPE_SERVER_SHA256_MD,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmInitServerHash
    },
    {
        ITOK_TYPE_SERVER_SUBJECT_MD,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmInitServerSubject
    },
    {
        ITOK_TYPE_SERVER_CERT_MD,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmInitServerCert
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmInitComplete
    }
};

static OM_uint32
eapNegoSmAcceptInitiatorName(OM_uint32 *minor GSSEAP_UNUSED,
                             gss_cred_id_t cred GSSEAP_UNUSED,
                             gss_ctx_id_t ctx,
                             gss_name_t target GSSEAP_UNUSED,
                             gss_OID mech,
                             OM_uint32 reqFlags GSSEAP_UNUSED,
                             OM_uint32 timeReq GSSEAP_UNUSED,
                             gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                             gss_buffer_t inputToken,
                             gss_buffer_t outputToken GSSEAP_UNUSED,
                             OM_uint32 *smFlags)
{
    OM_uint32 major;

    major = gssEapImportName(minor, inputToken, GSS_EAP_NT_EAP_NAME,
                             mech, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_SM_TRANSITION_NEXT(ctx);
    *smFlags |= SM_FLAG_FORCE_SEND_TOKEN;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapNegoSmAcceptServerHash(OM_uint32 *minor,
                          gss_cred_id_t cred,
                          gss_ctx_id_t ctx,
                          gss_name_t target GSSEAP_UNUSED,
                          gss_OID mech,
                          OM_uint32 reqFlags GSSEAP_UNUSED,
                          OM_uint32 timeReq GSSEAP_UNUSED,
                          gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                          gss_buffer_t inputToken GSSEAP_UNUSED,
                          gss_buffer_t outputToken,
                          OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t initiatorCred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc initiatorToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acceptorToken = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t initiatorContext = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptorContext = GSS_C_NO_CONTEXT;
    gss_OID_set_desc mechs;

    /* If initiator didn't send an identity, there's nothing we can do */
    if (ctx->initiatorName == GSS_C_NO_NAME) {
        major = GSS_S_COMPLETE;
        *minor = 0;
        goto cleanup;
    }

    mechs.count = 1;
    mechs.elements = mech;

    major = gssEapAllocContext(minor, &initiatorContext);
    if (GSS_ERROR(major))
        return major;

    initiatorContext->flags |= CTX_FLAG_INITIATOR | CTX_FLAG_SERVER_PROBE;

    major = gssEapAllocContext(minor, &acceptorContext);
    if (GSS_ERROR(major))
        return major;

    major = gssEapAcquireCred(minor,
                              ctx->initiatorName,
                              GSS_C_INDEFINITE,
                              &mechs,
                              GSS_C_INITIATE,
                              &initiatorCred,
                              NULL,
                              NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    initiatorCred->flags |= CRED_FLAG_RESOLVED; /* fake it */

    do {
        major = gssEapInitSecContext(minor, initiatorCred, initiatorContext,
                                     cred->name, mech, 0,
                                     GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                     &acceptorToken, NULL, &initiatorToken,
                                     NULL, NULL);
        gss_release_buffer(&tmpMinor, &acceptorToken);

        if (GSS_ERROR(major))
            break;

        if (initiatorToken.length != 0) {
            major = gssEapAcceptSecContext(minor, acceptorContext, cred,
                                           &initiatorToken, GSS_C_NO_CHANNEL_BINDINGS,
                                           NULL, NULL, &acceptorToken,
                                           NULL, NULL, NULL);
            gss_release_buffer(&tmpMinor, &initiatorToken);
        }

        if (GSS_ERROR(major))
            break;
    } while (major == GSS_S_CONTINUE_NEEDED);

    if (initiatorContext != GSS_C_NO_CONTEXT &&
        initiatorContext->initiatorCtx.serverHash.length != 0) {
        major = duplicateBuffer(minor,
                                &initiatorContext->initiatorCtx.serverHash,
                                outputToken);
        if (GSS_ERROR(major))
            goto cleanup;

        /*
         * stash initiatorContext into ctx->seqState for now; to avoid
         * leaking this, nothing else can fail.
         */
        ctx->seqState = initiatorContext;
        initiatorContext = GSS_C_NO_CONTEXT;
    }

    major = GSS_S_CONTINUE_NEEDED;
    *minor = 0;

cleanup:
    gssEapReleaseCred(&tmpMinor, &initiatorCred);
    gssEapReleaseContext(&tmpMinor, &initiatorContext);
    gssEapReleaseContext(&tmpMinor, &acceptorContext);
    gss_release_buffer(&tmpMinor, &initiatorToken);
    gss_release_buffer(&tmpMinor, &acceptorToken);

    return major;
}

static OM_uint32
eapNegoSmAcceptServerSubject(OM_uint32 *minor,
                            gss_cred_id_t cred GSSEAP_UNUSED,
                            gss_ctx_id_t ctx,
                            gss_name_t target GSSEAP_UNUSED,
                            gss_OID mech GSSEAP_UNUSED,
                            OM_uint32 reqFlags GSSEAP_UNUSED,
                            OM_uint32 timeReq GSSEAP_UNUSED,
                            gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                            gss_buffer_t inputToken GSSEAP_UNUSED,
                            gss_buffer_t outputToken,
                            OM_uint32 *smFlags GSSEAP_UNUSED)
{
    gss_ctx_id_t initiatorContext = (gss_ctx_id_t)ctx->seqState;
    OM_uint32 tmpMinor;

    if (initiatorContext != GSS_C_NO_CONTEXT &&
        initiatorContext->initiatorCtx.serverSubject.length != 0) {
        duplicateBuffer(&tmpMinor,
                        &initiatorContext->initiatorCtx.serverSubject,
                        outputToken);
    }

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

#if 0
static OM_uint32
eapNegoSmAcceptServerCert(OM_uint32 *minor,
                          gss_cred_id_t cred GSSEAP_UNUSED,
                          gss_ctx_id_t ctx GSSEAP_UNUSED,
                          gss_name_t target GSSEAP_UNUSED,
                          gss_OID mech GSSEAP_UNUSED,
                          OM_uint32 reqFlags GSSEAP_UNUSED,
                          OM_uint32 timeReq GSSEAP_UNUSED,
                          gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                          gss_buffer_t inputToken GSSEAP_UNUSED,
                          gss_buffer_t outputToken GSSEAP_UNUSED,
                          OM_uint32 *smFlags GSSEAP_UNUSED)
{
    gss_ctx_id_t initiatorContext = (gss_ctx_id_t)ctx->seqState;
    OM_uint32 tmpMinor;

    if (initiatorContext != GSS_C_NO_CONTEXT &&
        initiatorContext->initiatorCtx.serverCert.length != 0) {
        duplicateBuffer(&tmpMinor,
                        &initiatorContext->initiatorCtx.serverCert,
                        outputToken);
    }

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}
#endif

static OM_uint32
eapNegoSmAcceptComplete(OM_uint32 *minor,
                        gss_cred_id_t cred GSSEAP_UNUSED,
                        gss_ctx_id_t ctx,
                        gss_name_t target GSSEAP_UNUSED,
                        gss_OID mech GSSEAP_UNUSED,
                        OM_uint32 reqFlags GSSEAP_UNUSED,
                        OM_uint32 timeReq GSSEAP_UNUSED,
                        gss_channel_bindings_t chanBindings GSSEAP_UNUSED,
                        gss_buffer_t inputToken GSSEAP_UNUSED,
                        gss_buffer_t outputToken GSSEAP_UNUSED,
                        OM_uint32 *smFlags GSSEAP_UNUSED)
{
    OM_uint32 tmpMinor;

    gssEapReleaseContext(&tmpMinor, (gss_ctx_id_t *)&ctx->seqState);

    GSSEAP_SM_TRANSITION(ctx, GSSEAP_STATE_ESTABLISHED);

    *minor = 0;
    return GSS_S_COMPLETE;
}

static struct gss_eap_sm eapNegoAcceptorSm[] = {
    {
        ITOK_TYPE_INITIATOR_NAME_MD,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_INITIAL,
        0,
        eapNegoSmAcceptInitiatorName
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_SERVER_SHA256_MD,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmAcceptServerHash
    },
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_SERVER_SUBJECT_MD,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmAcceptServerSubject
    },
#if 0
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_SERVER_CERT_MD,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmAcceptServerCert
    },
#endif
    {
        ITOK_TYPE_NONE,
        ITOK_TYPE_NONE,
        GSSEAP_STATE_AUTHENTICATE,
        0,
        eapNegoSmAcceptComplete
    }
};

OM_uint32
gssEapProbe(OM_uint32 *minor,
            gss_const_OID mech,
            gss_cred_id_t cred,
            gss_ctx_id_t ctx,
            const gss_name_t target,
            OM_uint32 req_flags,
            gss_const_buffer_t input_token,
            gss_buffer_t output_token)
{
    OM_uint32 major, tmpMinor;
    int exchangeMetaData = (output_token == GSS_C_NO_BUFFER);
    enum gss_eap_state oldState = ctx->state; /* XXX */
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;
    struct gss_eap_sm_step_args smArgs;

    if (exchangeMetaData) {
        /* remove this if we change OIDs and make metadata mandatory */
        if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
            major = GSS_S_COMPLETE;
            *minor = 0;
            goto cleanup;
        }
    }

    /*
     * We need a mechanism OID in order to generate and validate the
     * correct token headers.
     */
    if (mech == GSS_C_NO_OID) {
        mech = gssEapPrimaryMechForCred(CTX_IS_INITIATOR(ctx)
                                        ? ctx->cred : cred);
    }

    major = gssEapCanonicalizeOid(minor,
                                  (gss_OID)mech,
                                  OID_FLAG_NULL_VALID | OID_FLAG_MAP_NULL_TO_DEFAULT_MECH,
                                  &ctx->mechanismUsed);
    if (GSS_ERROR(major))
        goto cleanup;

    if (output_token == GSS_C_NO_BUFFER)
        output_token = &buffer;

    if (CTX_IS_INITIATOR(ctx)) {
        smArgs.sm = eapNegoInitiatorSm;
        smArgs.smCount = sizeof(eapNegoInitiatorSm) / sizeof(eapNegoInitiatorSm[0]);
    } else {
        smArgs.sm = eapNegoAcceptorSm;
        smArgs.smCount = sizeof(eapNegoAcceptorSm) / sizeof(eapNegoAcceptorSm[0]);
    }

    smArgs.initiatorTokType = TOK_TYPE_INITIATOR_META_DATA;
    smArgs.acceptorTokType  = TOK_TYPE_ACCEPTOR_META_DATA;
    smArgs.flags            = SM_STEP_ALLOW_EMPTY_TOKEN;

    ctx->state = CTX_IS_INITIATOR(ctx) ^ exchangeMetaData
                 ? GSSEAP_STATE_INITIAL : GSSEAP_STATE_AUTHENTICATE;

    major = gssEapSmStep(minor,
                         cred,
                         ctx,
                         target,
                         (gss_OID)mech,
                         req_flags,
                         GSS_C_INDEFINITE,
                         GSS_C_NO_CHANNEL_BINDINGS,
                         (gss_buffer_t)input_token,
                         output_token,
                         &smArgs);

    ctx->state = oldState;

    GSSEAP_ASSERT(major == GSS_S_COMPLETE || !CTX_IS_ESTABLISHED(ctx));

cleanup:
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, output_token);
    gssEapReleaseOid(&tmpMinor, &ctx->mechanismUsed);

    /* squash GSS_C_CONTINUE_NEEDED as mechglue will treat that as an error */

    return GSS_ERROR(major) ? major : GSS_S_COMPLETE;
}

