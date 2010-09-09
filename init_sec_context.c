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
policyVariableToFlag(enum eapol_bool_var variable)
{
    OM_uint32 flag = 0;

    switch (variable) {
    case EAPOL_eapSuccess:
        flag = CTX_FLAG_EAP_SUCCESS;
        break;
    case EAPOL_eapRestart:
        flag = CTX_FLAG_EAP_RESTART;
        break;
    case EAPOL_eapFail:
        flag = CTX_FLAG_EAP_FAIL;
        break;
    case EAPOL_eapResp:
        flag = CTX_FLAG_EAP_RESP;
        break;
    case EAPOL_eapNoResp:
        flag = CTX_FLAG_EAP_NO_RESP;
        break;
    case EAPOL_eapReq:
        flag = CTX_FLAG_EAP_REQ;
        break;
    case EAPOL_portEnabled:
        flag = CTX_FLAG_EAP_PORT_ENABLED;
        break;
    case EAPOL_altAccept:
        flag = CTX_FLAG_EAP_ALT_ACCEPT;
        break;
    case EAPOL_altReject:
        flag = CTX_FLAG_EAP_ALT_REJECT;
        break;
    }

    return flag;
        
}

static struct eap_peer_config *
peerGetConfig(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.eapPeerConfig;
}

static Boolean
peerGetBool(void *data, enum eapol_bool_var variable)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    flag = policyVariableToFlag(variable);

    return ((ctx->flags & flag) != 0);
}

static void
peerSetBool(void *data, enum eapol_bool_var variable,
            Boolean value)
{
    gss_ctx_id_t ctx = data;
    OM_uint32 flag;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    flag = policyVariableToFlag(variable);

    if (value)
        ctx->flags |= flag;
    else
        ctx->flags &= ~(flag);
}

static unsigned int
peerGetInt(void *data, enum eapol_int_var variable)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return FALSE;

    assert(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        return ctx->initiatorCtx.idleWhile;
        break;
    }

    return 0;
}

static void
peerSetInt(void *data, enum eapol_int_var variable,
           unsigned int value)
{
    gss_ctx_id_t ctx = data;

    if (ctx == GSS_C_NO_CONTEXT)
        return;

    assert(CTX_IS_INITIATOR(ctx));

    switch (variable) {
    case EAPOL_idleWhile:
        ctx->initiatorCtx.idleWhile = value;
        break;
    }
}

static struct wpabuf *
peerGetEapReqData(void *ctx)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;

    return &gssCtx->initiatorCtx.reqData;
}

static void
peerSetConfigBlob(void *ctx, struct wpa_config_blob *blob)
{
}

static const struct wpa_config_blob *
peerGetConfigBlob(void *ctx, const char *name)
{
    return NULL;
}

static void
peerNotifyPending(void *ctx)
{
}

static struct eapol_callbacks gssEapPolicyCallbacks = {
    peerGetConfig,
    peerGetBool,
    peerSetBool,
    peerGetInt,
    peerSetInt,
    peerGetEapReqData,
    peerSetConfigBlob,
    peerGetConfigBlob,
    peerNotifyPending,
};

extern int wpa_debug_level;

static OM_uint32
peerConfigInit(OM_uint32 *minor,
               gss_cred_id_t cred,
               gss_ctx_id_t ctx,
               int loadConfig)
{
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;
    krb5_error_code code;
    char *identity;

    GSSEAP_KRB_INIT(&krbContext);

    if (loadConfig) {
        eapPeerConfig->fragment_size = 1024;
        wpa_debug_level = 0;
    }

    code = krb5_unparse_name(krbContext, cred->name->krbPrincipal, &identity);
    if (code != 0) {
        *minor = code;
        return GSS_S_FAILURE;
    }

    eapPeerConfig->identity = (unsigned char *)identity;
    eapPeerConfig->identity_len = strlen(identity);
    eapPeerConfig->password = (unsigned char *)cred->password.value;
    eapPeerConfig->password_len = cred->password.length;

    return GSS_S_COMPLETE;
}

static OM_uint32
peerConfigFree(OM_uint32 *minor,
               gss_ctx_id_t ctx)
{
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;

    GSSEAP_KRB_INIT(&krbContext);

    krb5_free_unparsed_name(krbContext, (char *)eapPeerConfig->identity);

    return GSS_S_COMPLETE;
}

static OM_uint32
completeInit(OM_uint32 *minor,
             gss_ctx_id_t ctx)
{
    OM_uint32 major;
    const unsigned char *key;
    size_t keyLength;
    krb5_context krbContext;

    GSSEAP_KRB_INIT(&krbContext);

    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed, &ctx->encryptionType);
    if (GSS_ERROR(major))
        return major;

    if (ctx->encryptionType != ENCTYPE_NULL &&
        eap_key_available(ctx->initiatorCtx.eap)) {
        key = eap_get_eapKeyData(ctx->initiatorCtx.eap, &keyLength);

        major = gssEapDeriveRFC3961Key(minor, key, keyLength,
                                       ctx->encryptionType, &ctx->rfc3961Key);
        if (GSS_ERROR(major))
            return major;
    } else {
        /*
         * draft-howlett-eap-gss says that integrity/confidentialty should
         * always be advertised as available, but if we have no keying
         * material it seems confusing to the caller to advertise this.
         */
        ctx->gssFlags &= ~(GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG);
    }

    sequenceInit(&ctx->seqState, ctx->recvSeq,
                 ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                 ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                 TRUE);

    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmInitAuthenticate(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_name_t target,
                         gss_OID mech,
                         OM_uint32 reqFlags,
                         OM_uint32 timeReq,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken,
                         gss_buffer_t outputToken)
{
    OM_uint32 major;
    OM_uint32 tmpMajor, tmpMinor;
    time_t now;
    int initialContextToken = 0, code;
    struct wpabuf *resp = NULL;

    initialContextToken = (inputToken == GSS_C_NO_BUFFER ||
                           inputToken->length == 0);

    major = peerConfigInit(minor, cred, ctx, initialContextToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (initialContextToken) {
        struct eap_config eapConfig;

        memset(&eapConfig, 0, sizeof(eapConfig));
        ctx->flags |= CTX_FLAG_EAP_PORT_ENABLED;

        ctx->initiatorCtx.eap = eap_peer_sm_init(ctx,
                                                 &gssEapPolicyCallbacks,
                                                 ctx,
                                                 &eapConfig);

        time(&now);
        if (timeReq == 0 || timeReq == GSS_C_INDEFINITE)
            ctx->expiryTime = 0;
        else
            ctx->expiryTime = now + timeReq;

        major = gss_duplicate_name(minor, cred->name, &ctx->initiatorName);
        if (GSS_ERROR(major))
            goto cleanup;

        major = gss_duplicate_name(minor, target, &ctx->acceptorName);
        if (GSS_ERROR(major))
            goto cleanup;

        if (mech == GSS_C_NULL_OID || oidEqual(mech, GSS_EAP_MECHANISM)) {
            major = gssEapDefaultMech(minor, &ctx->mechanismUsed);
        } else if (gssEapIsConcreteMechanismOid(mech)) {
            if (!gssEapInternalizeOid(mech, &ctx->mechanismUsed))
                major = duplicateOid(minor, mech, &ctx->mechanismUsed);
        } else {
            major = GSS_S_BAD_MECH;
        }
        if (GSS_ERROR(major))
            goto cleanup;

        resp = eap_sm_buildIdentity(ctx->initiatorCtx.eap, 0, 0);
        major = GSS_S_CONTINUE_NEEDED;
        goto cleanup;
    } else {
        ctx->flags |= CTX_FLAG_EAP_REQ; /* we have a Request from the acceptor */
    }

    wpabuf_set(&ctx->initiatorCtx.reqData,
               inputToken->value, inputToken->length);

    major = GSS_S_CONTINUE_NEEDED;

    code = eap_peer_sm_step(ctx->initiatorCtx.eap);
    if (ctx->flags & CTX_FLAG_EAP_RESP) {
        ctx->flags &= ~(CTX_FLAG_EAP_RESP);

        resp = eap_get_eapRespData(ctx->initiatorCtx.eap);
    } else if (ctx->flags & CTX_FLAG_EAP_SUCCESS) {
        major = completeInit(minor, ctx);
        ctx->flags &= ~(CTX_FLAG_EAP_SUCCESS);
        ctx->state = EAP_STATE_ESTABLISHED;
    } else if ((ctx->flags & CTX_FLAG_EAP_FAIL) || code == 0) {
        major = GSS_S_FAILURE;
    }

cleanup:
    if (resp != NULL) {
        OM_uint32 tmpMajor;
        gss_buffer_desc buf;

        assert(major == GSS_S_CONTINUE_NEEDED);

        buf.length = wpabuf_len(resp);
        buf.value = (void *)wpabuf_head(resp);

        tmpMajor = duplicateBuffer(&tmpMinor, &buf, outputToken);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
        }
    }

    wpabuf_set(&ctx->initiatorCtx.reqData, NULL, 0);
    peerConfigFree(&tmpMinor, ctx);

    return major;
}

static OM_uint32
eapGssSmInitKeyTransport(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_name_t target,
                         gss_OID mech,
                         OM_uint32 reqFlags,
                         OM_uint32 timeReq,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken,
                         gss_buffer_t outputToken)
{
    GSSEAP_NOT_IMPLEMENTED;
}

static OM_uint32
eapGssSmInitSecureAssoc(OM_uint32 *minor,
                        gss_cred_id_t cred,
                        gss_ctx_id_t ctx,
                        gss_name_t target,
                        gss_OID mech,
                        OM_uint32 reqFlags,
                        OM_uint32 timeReq,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken)
{
    GSSEAP_NOT_IMPLEMENTED;
}

static OM_uint32
eapGssSmInitGssChannelBindings(OM_uint32 *minor,
                               gss_cred_id_t cred,
                               gss_ctx_id_t ctx,
                               gss_name_t target,
                               gss_OID mech,
                               OM_uint32 reqFlags,
                               OM_uint32 timeReq,
                               gss_channel_bindings_t chanBindings,
                               gss_buffer_t inputToken,
                               gss_buffer_t outputToken)
{
    GSSEAP_NOT_IMPLEMENTED;
}

static OM_uint32
eapGssSmInitEstablished(OM_uint32 *minor,
                        gss_cred_id_t cred,
                        gss_ctx_id_t ctx,
                        gss_name_t target,
                        gss_OID mech,
                        OM_uint32 reqFlags,
                        OM_uint32 timeReq,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t inputToken,
                        gss_buffer_t outputToken)
{
    /* Called with already established context */
    *minor = EINVAL;
    return GSS_S_BAD_STATUS;
}

static struct eap_gss_initiator_sm {
    enum gss_eap_token_type inputTokenType;
    enum gss_eap_token_type outputTokenType;
    OM_uint32 (*processToken)(OM_uint32 *,
                              gss_cred_id_t,
                              gss_ctx_id_t,
                              gss_name_t,
                              gss_OID,
                              OM_uint32,
                              OM_uint32,
                              gss_channel_bindings_t,
                              gss_buffer_t,
                              gss_buffer_t);
} eapGssInitiatorSm[] = {
    { TOK_TYPE_EAP_REQ, TOK_TYPE_EAP_RESP,  eapGssSmInitAuthenticate        },
    { TOK_TYPE_EAP_REQ, TOK_TYPE_EAP_RESP,  eapGssSmInitKeyTransport        },
    { TOK_TYPE_EAP_REQ, TOK_TYPE_EAP_RESP,  eapGssSmInitSecureAssoc         },
    { TOK_TYPE_GSS_CB,  TOK_TYPE_NONE,      eapGssSmInitGssChannelBindings  },
    { TOK_TYPE_NONE,    TOK_TYPE_NONE,      eapGssSmInitEstablished         },
};

OM_uint32
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
    OM_uint32 major;
    OM_uint32 tmpMajor, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;
    struct eap_gss_initiator_sm *sm = NULL;
    gss_buffer_desc innerInputToken, innerOutputToken;

    *minor = 0;

    innerOutputToken.length = 0;
    innerOutputToken.value = NULL;

    output_token->length = 0;
    output_token->value = NULL;

    if (cred != GSS_C_NO_CREDENTIAL && !(cred->flags & CRED_FLAG_INITIATE)) {
        return GSS_S_NO_CRED;
    }

    if (ctx == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            return GSS_S_DEFECTIVE_TOKEN;
        }

        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        ctx->flags |= CTX_FLAG_INITIATOR;

        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    sm = &eapGssInitiatorSm[ctx->state];

    if (input_token != GSS_C_NO_BUFFER) {
        major = gssEapVerifyToken(minor, ctx, input_token,
                                  sm->inputTokenType, &innerInputToken);
        if (GSS_ERROR(major))
            goto cleanup;
    } else {
        innerInputToken.length = 0;
        innerInputToken.value = NULL;
    }

    /*
     * Advance through state machine whilst empty tokens are emitted and
     * the status is not GSS_S_COMPLETE or an error status.
     */
    do {
        major = (sm->processToken)(minor,
                                   cred,
                                   ctx,
                                   target_name,
                                   mech_type,
                                   req_flags,
                                   time_req,
                                   input_chan_bindings,
                                   &innerInputToken,
                                   &innerOutputToken);
        if (GSS_ERROR(major))
            goto cleanup;
    } while (major == GSS_S_CONTINUE_NEEDED && innerOutputToken.length == 0);

    if (actual_mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, actual_mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, actual_mech_type);
    }
    if (innerOutputToken.length != 0) {
        tmpMajor = gssEapMakeToken(&tmpMinor, ctx, &innerOutputToken,
                                   sm->outputTokenType, output_token);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (time_rec != NULL)
        gss_context_time(&tmpMinor, ctx, time_rec);

    assert(ctx->state == EAP_STATE_ESTABLISHED || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);

    gss_release_buffer(&tmpMinor, &innerOutputToken);

    return major;
}
