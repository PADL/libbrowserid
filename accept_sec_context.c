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

#define EAP_MAX_METHODS 8

#define EAP_TTLS_AUTH_PAP 1
#define EAP_TTLS_AUTH_CHAP 2
#define EAP_TTLS_AUTH_MSCHAP 4
#define EAP_TTLS_AUTH_MSCHAPV2 8

#if 1
struct eap_user {
        struct {
                int vendor;
                u32 method;
        } methods[EAP_MAX_METHODS];
        u8 *password;
        size_t password_len;
        int password_hash; /* whether password is hashed with
                            * nt_password_hash() */
        int phase2;
        int force_version;
        int ttls_auth; /* bitfield of
                        * EAP_TTLS_AUTH_{PAP,CHAP,MSCHAP,MSCHAPV2} */
};

struct eap_eapol_interface {
        /* Lower layer to full authenticator variables */
        Boolean eapResp; /* shared with EAPOL Backend Authentication */
        struct wpabuf *eapRespData;
        Boolean portEnabled;
        int retransWhile;
        Boolean eapRestart; /* shared with EAPOL Authenticator PAE */
        int eapSRTT;
        int eapRTTVAR;

        /* Full authenticator to lower layer variables */
        Boolean eapReq; /* shared with EAPOL Backend Authentication */
        Boolean eapNoReq; /* shared with EAPOL Backend Authentication */
        Boolean eapSuccess;
        Boolean eapFail;
        Boolean eapTimeout;
        struct wpabuf *eapReqData;
        u8 *eapKeyData;
        size_t eapKeyDataLen;
        Boolean eapKeyAvailable; /* called keyAvailable in IEEE 802.1X-2004 */

        /* AAA interface to full authenticator variables */
        Boolean aaaEapReq;
        Boolean aaaEapNoReq;
        Boolean aaaSuccess;
        Boolean aaaFail;
        struct wpabuf *aaaEapReqData;
        u8 *aaaEapKeyData;
        size_t aaaEapKeyDataLen;
        Boolean aaaEapKeyAvailable;
        int aaaMethodTimeout;

        /* Full authenticator to AAA interface variables */
        Boolean aaaEapResp;
        struct wpabuf *aaaEapRespData;
        /* aaaIdentity -> eap_get_identity() */
        Boolean aaaTimeout;
};

#define eapol_callbacks     SERVER_eapol_callbacks

struct eapol_callbacks {
        int (*get_eap_user)(void *ctx, const u8 *identity, size_t identity_len,
                            int phase2, struct eap_user *user);
        const char * (*get_eap_req_id_text)(void *ctx, size_t *len);
};

#define eap_config          SERVER_eap_config

struct eap_config {
        void *ssl_ctx;
        void *msg_ctx;
        void *eap_sim_db_priv;
        Boolean backend_auth;
        int eap_server;
        u8 *pac_opaque_encr_key;
        u8 *eap_fast_a_id;
        size_t eap_fast_a_id_len;
        char *eap_fast_a_id_info;
        int eap_fast_prov;
        int pac_key_lifetime;
        int pac_key_refresh_time;
        int eap_sim_aka_result_ind;
        int tnc;
        struct wps_context *wps;
        const struct wpabuf *assoc_wps_ie;
        const u8 *peer_addr;
        int fragment_size;
};

struct eap_sm * eap_server_sm_init(void *eapol_ctx,
                                   struct eapol_callbacks *eapol_cb,
                                   struct eap_config *eap_conf);
void eap_server_sm_deinit(struct eap_sm *sm);
int eap_server_sm_step(struct eap_sm *sm);
void eap_sm_notify_cached(struct eap_sm *sm);
void eap_sm_pending_cb(struct eap_sm *sm);
int eap_sm_method_pending(struct eap_sm *sm);
const u8 * eap_get_identity(struct eap_sm *sm, size_t *len);
struct eap_eapol_interface * eap_get_interface(struct eap_sm *sm);

#include <eap_server/eap_i.h>

static OM_uint32
initTls(OM_uint32 *minor,
        gss_ctx_id_t ctx)
{
    struct tls_config tconf;
    struct tls_connection_params tparams;

    memset(&tconf, 0, sizeof(tconf));
    ctx->acceptorCtx.tlsContext = tls_init(&tconf);
    if (ctx->acceptorCtx.tlsContext == NULL)
        return GSS_S_FAILURE;

    memset(&tparams, 0, sizeof(tparams));
    tparams.ca_cert = "ca.pem";
    tparams.client_cert = "server.pem";
    tparams.private_key = "server-key.pem";

    if (tls_global_set_params(ctx->acceptorCtx.tlsContext, &tparams)) {
        return GSS_S_FAILURE;
    }

    if (tls_global_set_verify(ctx->acceptorCtx.tlsContext, 0)) {
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

static int
serverGetEapUser(void *ctx,
                 const unsigned char *identity,
                 size_t identityLength,
                 int phase2,
                 struct eap_user *user)
{
    gss_ctx_id_t gssCtx = (gss_ctx_id_t)ctx;
    OM_uint32 major, minor;
    gss_buffer_desc buf;

    memset(user, 0, sizeof(*user));

    buf.length = identityLength;
    buf.value = (void *)identity;

    if (phase2 == 0) {
        user->methods[0].vendor = EAP_VENDOR_IETF;
        user->methods[0].method = EAP_TYPE_PEAP;
        return 0;
    }

    major = gssEapImportName(&minor, &buf, GSS_C_NT_USER_NAME,
                             &gssCtx->initiatorName);
    if (GSS_ERROR(major))
        return -1;

    /*
     * OK, obviously there is no real security here, this is simply
     * for testing the token exchange; this code will be completely
     * replaced with libradsec once that library is available.
     */
    user->methods[0].vendor = EAP_VENDOR_IETF;
    user->methods[0].method = EAP_TYPE_MSCHAPV2;
    user->password = (unsigned char *)strdup(" ");
    user->password_len = 1;

    return 0;
}

static const char *
serverGetEapReqIdText(void *ctx,
                      size_t *len)
{
    *len = 0;
    return NULL;
}
#endif

static OM_uint32
acceptReady(OM_uint32 *minor, gss_ctx_id_t ctx)
{
    OM_uint32 major;
    krb5_context krbContext;

    GSSEAP_KRB_INIT(&krbContext);

    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed, &ctx->encryptionType);
    if (GSS_ERROR(major))
        return major;

    if (ctx->encryptionType != ENCTYPE_NULL &&
        ctx->acceptorCtx.eapPolInterface->eapKeyAvailable) {
        major = gssEapDeriveRFC3961Key(minor,
                                       ctx->acceptorCtx.eapPolInterface->eapKeyData,
                                       ctx->acceptorCtx.eapPolInterface->eapKeyDataLen,
                                       ctx->encryptionType,
                                       &ctx->rfc3961Key);
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
eapGssSmAcceptAuthenticate(OM_uint32 *minor,
                           gss_ctx_id_t ctx,
                           gss_cred_id_t cred,
                           gss_buffer_t inputToken,
                           gss_channel_bindings_t chanBindings,
                           gss_buffer_t outputToken)
{
    OM_uint32 major;
    OM_uint32 tmpMinor, tmpMajor;
    int code;
    struct wpabuf respData;
    static struct eapol_callbacks cb = { serverGetEapUser, serverGetEapReqIdText };
    if (ctx->acceptorCtx.eap == NULL) {
        struct eap_config eapConfig;

        major = initTls(minor, ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        memset(&eapConfig, 0, sizeof(eapConfig));
        eapConfig.eap_server = 1;
        eapConfig.ssl_ctx = ctx->acceptorCtx.tlsContext;

        ctx->acceptorCtx.eap = eap_server_sm_init(ctx, &cb, &eapConfig);
        if (ctx->acceptorCtx.eap == NULL) {
            major = GSS_S_FAILURE;
            goto cleanup;
        }

        ctx->acceptorCtx.eapPolInterface = eap_get_interface(ctx->acceptorCtx.eap);
        ctx->acceptorCtx.eapPolInterface->portEnabled = TRUE;
        ctx->acceptorCtx.eapPolInterface->eapRestart = TRUE;
    }

    if (ctx->acceptorName == GSS_C_NO_NAME &&
        cred != GSS_C_NO_CREDENTIAL &&
        cred->name != GSS_C_NO_NAME) {
        major = gss_duplicate_name(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    wpabuf_set(&respData, inputToken->value, inputToken->length);
    ctx->acceptorCtx.eapPolInterface->eapRespData = &respData;
    ctx->acceptorCtx.eapPolInterface->eapResp = TRUE;

    code = eap_server_sm_step(ctx->acceptorCtx.eap);

    if (ctx->acceptorCtx.eapPolInterface->eapReq) {
        ctx->acceptorCtx.eapPolInterface->eapReq = 0;
        major = GSS_S_CONTINUE_NEEDED;
    }

    if (ctx->acceptorCtx.eapPolInterface->eapSuccess) {
        ctx->acceptorCtx.eapPolInterface->eapSuccess = 0;
        major = acceptReady(minor, ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->state = EAP_STATE_GSS_CHANNEL_BINDINGS;
        major = GSS_S_CONTINUE_NEEDED;
    } else if (ctx->acceptorCtx.eapPolInterface->eapFail) {
        ctx->acceptorCtx.eapPolInterface->eapFail = 0;
        major = GSS_S_FAILURE;
    } else if (code == 0) {
        major = GSS_S_FAILURE;
    }

    if (ctx->acceptorCtx.eapPolInterface->eapReqData != NULL) {
        gss_buffer_desc buf;

        buf.length = wpabuf_len(ctx->acceptorCtx.eapPolInterface->eapReqData);
        buf.value = (void *)wpabuf_head(ctx->acceptorCtx.eapPolInterface->eapReqData);

        tmpMajor = duplicateBuffer(&tmpMinor, &buf, outputToken);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }

cleanup:
    ctx->acceptorCtx.eapPolInterface->eapRespData = NULL;

    return major;
}

static OM_uint32
eapGssSmAcceptGssChannelBindings(OM_uint32 *minor,
                                 gss_ctx_id_t ctx,
                                 gss_cred_id_t cred,
                                 gss_buffer_t inputToken,
                                 gss_channel_bindings_t chanBindings,
                                 gss_buffer_t outputToken)
{
    OM_uint32 major, tmpMinor;
    gss_iov_buffer_desc iov[2];

    outputToken->length = 0;
    outputToken->value = NULL;

    if (chanBindings == GSS_C_NO_CHANNEL_BINDINGS) {
        ctx->state = EAP_STATE_ESTABLISHED;
        return GSS_S_COMPLETE;
    }

    if (inputToken->length < 14) {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[0].buffer.length = 0;
    iov[0].buffer.value = NULL;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS)
        iov[0].buffer = chanBindings->application_data;

    iov[1].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[1].buffer.length = 16;
    iov[1].buffer.value = (unsigned char *)inputToken->value - 2;

    assert(load_uint16_be(iov[1].buffer.value) == TOK_TYPE_GSS_CB);

    iov[2].type = GSS_IOV_BUFFER_TYPE_TRAILER;
    iov[2].buffer.length = inputToken->length - 14;
    iov[2].buffer.value = (unsigned char *)inputToken->value + 14;

    major = gssEapUnwrapOrVerifyMIC(minor, ctx, NULL, NULL,
                                    iov, 3, TOK_TYPE_GSS_CB);
    if (major == GSS_S_COMPLETE) {
        ctx->state = EAP_STATE_ESTABLISHED;
    }

#if 0
    gss_release_buffer(&tmpMinor, &iov[0].buffer);
#endif

    return major;
}

static OM_uint32
eapGssSmAcceptEstablished(OM_uint32 *minor,
                          gss_ctx_id_t ctx,
                          gss_cred_id_t cred,
                          gss_buffer_t inputToken,
                          gss_channel_bindings_t chanBindings,
                          gss_buffer_t outputToken)
{
    /* Called with already established context */
    *minor = EINVAL;
    return GSS_S_BAD_STATUS;
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
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,  eapGssSmAcceptAuthenticate       },
#if 0
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,  NULL                             },
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,  NULL                             },
#endif
    { TOK_TYPE_GSS_CB,      TOK_TYPE_NONE,     eapGssSmAcceptGssChannelBindings },
    { TOK_TYPE_NONE,        TOK_TYPE_NONE,     eapGssSmAcceptEstablished        },
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
    OM_uint32 major;
    OM_uint32 tmpMajor, tmpMinor;
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

    /* If credentials were provided, check they're usable with this mech */
    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
        major = GSS_S_BAD_MECH;
        goto cleanup;
    }

    do {
        sm = &eapGssAcceptorSm[ctx->state];

        major = (sm->processToken)(minor,
                                   ctx,
                                   cred,
                                   &innerInputToken,
                                   input_chan_bindings,
                                   &innerOutputToken);
        if (GSS_ERROR(major))
            goto cleanup;
    } while (major == GSS_S_CONTINUE_NEEDED && innerOutputToken.length == 0);

    if (mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, mech_type);
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
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (major == GSS_S_COMPLETE) {
        if (src_name != NULL && ctx->initiatorName != GSS_C_NO_NAME) {
            major = gss_duplicate_name(&tmpMinor, ctx->initiatorName, src_name);
            if (GSS_ERROR(major))
                goto cleanup;
        }
        if (time_rec != NULL)
            gss_context_time(&tmpMinor, ctx, time_rec);
    }

    assert(ctx->state == EAP_STATE_ESTABLISHED || major == GSS_S_CONTINUE_NEEDED);

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (GSS_ERROR(major))
        gssEapReleaseContext(&tmpMinor, context_handle);

    gss_release_buffer(&tmpMinor, &innerOutputToken);

    return major;
}
