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

/*
 * Establish a security context on the initiator (client). These functions
 * wrap around libeap.
 */

#include "gssapiP_eap.h"

#ifdef GSSEAP_ENABLE_REAUTH
static OM_uint32
eapGssSmInitGssReauth(OM_uint32 *minor,
                      gss_cred_id_t cred,
                      gss_ctx_id_t ctx,
                      gss_name_t target,
                      gss_OID mech,
                      OM_uint32 reqFlags,
                      OM_uint32 timeReq,
                      gss_channel_bindings_t chanBindings,
                      gss_buffer_t inputToken,
                      gss_buffer_t outputToken);
#endif

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
               gss_ctx_id_t ctx)
{
    krb5_context krbContext;
    struct eap_peer_config *eapPeerConfig = &ctx->initiatorCtx.eapPeerConfig;
    krb5_error_code code;
    char *identity;

    eapPeerConfig->identity = NULL;
    eapPeerConfig->identity_len = 0;
    eapPeerConfig->password = NULL;
    eapPeerConfig->password_len = 0;

    assert(cred != GSS_C_NO_CREDENTIAL);

    GSSEAP_KRB_INIT(&krbContext);

    eapPeerConfig->fragment_size = 1024;
    wpa_debug_level = 0;

    assert(cred->name != GSS_C_NO_NAME);

    if ((cred->name->flags & (NAME_FLAG_NAI | NAME_FLAG_SERVICE)) == 0) {
        *minor = GSSEAP_BAD_INITIATOR_NAME;
        return GSS_S_BAD_NAME;
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

    *minor = 0;
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

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Mark an initiator context as ready for cryptographic operations
 */
static OM_uint32
initReady(OM_uint32 *minor, gss_ctx_id_t ctx, OM_uint32 reqFlags)
{
    OM_uint32 major;
    const unsigned char *key;
    size_t keyLength;

#if 1
    /* XXX actually check for mutual auth */
    if (reqFlags & GSS_C_MUTUAL_FLAG)
        ctx->gssFlags |= GSS_C_MUTUAL_FLAG;
#endif

    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed, &ctx->encryptionType);
    if (GSS_ERROR(major))
        return major;

    if (!eap_key_available(ctx->initiatorCtx.eap)) {
        *minor = GSSEAP_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    key = eap_get_eapKeyData(ctx->initiatorCtx.eap, &keyLength);

    if (keyLength < EAP_EMSK_LEN) {
        *minor = GSSEAP_KEY_TOO_SHORT;
        return GSS_S_UNAVAILABLE;
    }

    major = gssEapDeriveRfc3961Key(minor,
                                   &key[EAP_EMSK_LEN / 2],
                                   EAP_EMSK_LEN / 2,
                                   ctx->encryptionType,
                                   &ctx->rfc3961Key);
       if (GSS_ERROR(major))
           return major;

    major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                      &ctx->checksumType);
    if (GSS_ERROR(major))
        return major;

    major = sequenceInit(minor,
                         &ctx->seqState,
                         ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
initBegin(OM_uint32 *minor,
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

    assert(cred != GSS_C_NO_CREDENTIAL);

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
    major = gssEapDuplicateName(minor, cred->name, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    GSSEAP_MUTEX_LOCK(&target->mutex);

    major = gssEapDuplicateName(minor, target, &ctx->acceptorName);
    if (GSS_ERROR(major)) {
        GSSEAP_MUTEX_UNLOCK(&target->mutex);
        return major;
    }

    GSSEAP_MUTEX_UNLOCK(&target->mutex);

    if (mech == GSS_C_NULL_OID) {
        major = gssEapDefaultMech(minor, &ctx->mechanismUsed);
    } else if (gssEapIsConcreteMechanismOid(mech)) {
        if (!gssEapInternalizeOid(mech, &ctx->mechanismUsed))
            major = duplicateOid(minor, mech, &ctx->mechanismUsed);
    } else {
        major = GSS_S_BAD_MECH;
        *minor = GSSEAP_WRONG_MECH;
    }
    if (GSS_ERROR(major))
        return major;

    /* If credentials were provided, check they're usable with this mech */
    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
        *minor = GSSEAP_CRED_MECH_MISMATCH;
        return GSS_S_BAD_MECH;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmInitIdentity(OM_uint32 *minor,
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
    int initialContextToken;

    initialContextToken = (inputToken->length == 0);
    if (!initialContextToken) {
        *minor = GSSEAP_WRONG_SIZE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    major = initBegin(minor, cred, ctx, target, mech,
                      reqFlags, timeReq, chanBindings,
                      inputToken, outputToken);
    if (GSS_ERROR(major))
        return major;

    ctx->state = EAP_STATE_AUTHENTICATE;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static struct wpabuf emptyWpaBuffer;

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
    OM_uint32 tmpMinor;
    int code;
    struct wpabuf *resp = NULL;
    int initialContextToken;

    *minor = 0;

    initialContextToken = (inputToken == GSS_C_NO_BUFFER ||
                           inputToken->length == 0);

    major = peerConfigInit(minor, cred, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    if (ctx->initiatorCtx.eap == NULL) {
        struct eap_config eapConfig;

        memset(&eapConfig, 0, sizeof(eapConfig));

        ctx->initiatorCtx.eap = eap_peer_sm_init(ctx,
                                                 &gssEapPolicyCallbacks,
                                                 ctx,
                                                 &eapConfig);
        if (ctx->initiatorCtx.eap == NULL) {
            major = GSS_S_FAILURE;
            *minor = GSSEAP_PEER_SM_INIT_FAILURE;
            goto cleanup;
        }

        ctx->flags |= CTX_FLAG_EAP_RESTART | CTX_FLAG_EAP_PORT_ENABLED;
    }

    ctx->flags |= CTX_FLAG_EAP_REQ; /* we have a Request from the acceptor */

    wpabuf_set(&ctx->initiatorCtx.reqData,
               inputToken->value, inputToken->length);

    major = GSS_S_CONTINUE_NEEDED;

    code = eap_peer_sm_step(ctx->initiatorCtx.eap);
    if (ctx->flags & CTX_FLAG_EAP_RESP) {
        ctx->flags &= ~(CTX_FLAG_EAP_RESP);

        resp = eap_get_eapRespData(ctx->initiatorCtx.eap);
    } else if (ctx->flags & CTX_FLAG_EAP_SUCCESS) {
        major = initReady(minor, ctx, reqFlags);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->flags &= ~(CTX_FLAG_EAP_SUCCESS);
        major = GSS_S_CONTINUE_NEEDED;
        ctx->state = EAP_STATE_EXTENSIONS_REQ;
    } else if (ctx->flags & CTX_FLAG_EAP_FAIL) {
        major = GSS_S_DEFECTIVE_CREDENTIAL;
        *minor = GSSEAP_PEER_AUTH_FAILURE;
    } else if (code == 0 && initialContextToken) {
        resp = &emptyWpaBuffer;
        major = GSS_S_CONTINUE_NEEDED;
    } else {
        major = GSS_S_DEFECTIVE_TOKEN;
        *minor = GSSEAP_PEER_BAD_MESSAGE;
    }

cleanup:
    if (resp != NULL) {
        OM_uint32 tmpMajor;
        gss_buffer_desc respBuf;

        assert(major == GSS_S_CONTINUE_NEEDED);

        respBuf.length = wpabuf_len(resp);
        respBuf.value = (void *)wpabuf_head(resp);

        tmpMajor = duplicateBuffer(&tmpMinor, &respBuf, outputToken);
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
eapGssSmInitExtensionsReq(OM_uint32 *minor,
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

    major = gssEapMakeExtensions(minor, cred, ctx, chanBindings, outputToken);
    if (GSS_ERROR(major))
        return major;

    assert(outputToken->value != NULL);

    ctx->state = EAP_STATE_EXTENSIONS_RESP;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmInitExtensionsResp(OM_uint32 *minor,
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

    major = gssEapVerifyExtensions(minor, cred, ctx, chanBindings, inputToken);
    if (GSS_ERROR(major))
        return major;

    ctx->state = EAP_STATE_ESTABLISHED;

    *minor = 0;
    return GSS_S_COMPLETE;
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
    *minor = GSSEAP_CONTEXT_ESTABLISHED;
    return GSS_S_BAD_STATUS;
}

static OM_uint32
eapGssSmInitError(OM_uint32 *minor,
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
    unsigned char *p;

    if (inputToken->length < 8) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    p = (unsigned char *)inputToken->value;

    major = load_uint32_be(&p[0]);
    *minor = ERROR_TABLE_BASE_eapg + load_uint32_be(&p[4]);

    if (!GSS_ERROR(major)) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_BAD_ERROR_TOKEN;
    }

    return major;
}

static struct gss_eap_initiator_sm {
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
    { TOK_TYPE_NONE,        TOK_TYPE_EAP_RESP,      eapGssSmInitIdentity            },
    { TOK_TYPE_EAP_REQ,     TOK_TYPE_EAP_RESP,      eapGssSmInitAuthenticate        },
    { TOK_TYPE_NONE,        TOK_TYPE_EXT_REQ,       eapGssSmInitExtensionsReq       },
    { TOK_TYPE_EXT_RESP,    TOK_TYPE_NONE,          eapGssSmInitExtensionsResp      },
    { TOK_TYPE_NONE,        TOK_TYPE_NONE,          eapGssSmInitEstablished         },
    { TOK_TYPE_CONTEXT_ERR, TOK_TYPE_NONE,          eapGssSmInitError               },
#ifdef GSSEAP_ENABLE_REAUTH
    { TOK_TYPE_GSS_REAUTH,  TOK_TYPE_GSS_REAUTH,    eapGssSmInitGssReauth           },
#endif
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
    struct gss_eap_initiator_sm *sm = NULL;
    gss_buffer_desc innerInputToken;
    gss_buffer_desc innerOutputToken = GSS_C_EMPTY_BUFFER;
    enum gss_eap_token_type tokType;
    gss_cred_id_t defaultCred = GSS_C_NO_CREDENTIAL;
    int initialContextToken = 0;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
            *minor = GSSEAP_WRONG_SIZE;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        ctx->flags |= CTX_FLAG_INITIATOR;

        initialContextToken = 1;
        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (cred == GSS_C_NO_CREDENTIAL) {
        if (ctx->initiatorCtx.defaultCred == GSS_C_NO_CREDENTIAL) {
            major = gssEapAcquireCred(minor,
                                      GSS_C_NO_NAME,
                                      GSS_C_NO_BUFFER,
                                      time_req,
                                      GSS_C_NO_OID_SET,
                                      GSS_C_INITIATE,
                                      &defaultCred,
                                      NULL,
                                      NULL);
            if (GSS_ERROR(major))
                goto cleanup;
        }

        cred = ctx->initiatorCtx.defaultCred;
    }

    GSSEAP_MUTEX_LOCK(&cred->mutex);

#ifdef GSSEAP_ENABLE_REAUTH
    if (initialContextToken && gssEapCanReauthP(cred, target_name, time_req))
        ctx->state = EAP_STATE_KRB_REAUTH_GSS;
#endif

    if ((cred->flags & CRED_FLAG_INITIATE) == 0) {
        major = GSS_S_NO_CRED;
        *minor = GSSEAP_CRED_USAGE_MISMATCH;
        goto cleanup;
    }

    sm = &eapGssInitiatorSm[ctx->state];

    if (input_token != GSS_C_NO_BUFFER) {
        major = gssEapVerifyToken(minor, ctx, input_token,
                                  &tokType, &innerInputToken);
        if (GSS_ERROR(major))
            goto cleanup;

        if (tokType == TOK_TYPE_CONTEXT_ERR) {
            ctx->state = EAP_STATE_ERROR;
        } else if (tokType != sm->inputTokenType) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_WRONG_TOK_ID;
            goto cleanup;
        }
    } else {
        innerInputToken.length = 0;
        innerInputToken.value = NULL;
    }

    /*
     * Advance through state machine whilst empty tokens are emitted and
     * the status is not GSS_S_COMPLETE or an error status.
     */
    do {
        sm = &eapGssInitiatorSm[ctx->state];

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
    } while (major == GSS_S_CONTINUE_NEEDED && innerOutputToken.value == NULL);

    if (actual_mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, actual_mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, actual_mech_type);
    }
    if (innerOutputToken.value != NULL) {
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
        gssEapContextTime(&tmpMinor, ctx, time_rec);

    assert(ctx->state == EAP_STATE_ESTABLISHED || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    if (cred != GSS_C_NO_CREDENTIAL)
        GSSEAP_MUTEX_UNLOCK(&cred->mutex);
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);

    gss_release_buffer(&tmpMinor, &innerOutputToken);

    return major;
}

#ifdef GSSEAP_ENABLE_REAUTH
static OM_uint32
eapGssSmInitGssReauth(OM_uint32 *minor,
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
    OM_uint32 major, tmpMinor;
    gss_name_t mechTarget = GSS_C_NO_NAME;
    gss_OID actualMech = GSS_C_NO_OID;
    OM_uint32 gssFlags, timeRec;

    assert(cred != GSS_C_NO_CREDENTIAL);

    ctx->flags |= CTX_FLAG_KRB_REAUTH_GSS;

    if (inputToken->length == 0) {
        major = initBegin(minor, cred, ctx, target, mech,
                          reqFlags, timeReq, chanBindings,
                          inputToken, outputToken);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = gssEapMechToGlueName(minor, target, &mechTarget);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssInitSecContext(minor,
                              cred->krbCred,
                              &ctx->kerberosCtx,
                              mechTarget,
                              (gss_OID)gss_mech_krb5,
                              reqFlags, /* | GSS_C_DCE_STYLE, */
                              timeReq,
                              chanBindings,
                              inputToken,
                              &actualMech,
                              outputToken,
                              &gssFlags,
                              &timeRec);
    if (GSS_ERROR(major))
        goto cleanup;

    ctx->gssFlags = gssFlags;

    if (major == GSS_S_COMPLETE) {
        major = gssEapReauthComplete(minor, ctx, cred, actualMech, timeRec);
        if (GSS_ERROR(major))
            goto cleanup;
        ctx->state = EAP_STATE_ESTABLISHED;
    }

cleanup:
    gssReleaseName(&tmpMinor, &mechTarget);

    return major;
}
#endif /* GSSEAP_ENABLE_REAUTH */
