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

#include "gssapiP_eap.h"

#ifdef GSSEAP_ENABLE_REAUTH
static OM_uint32
eapGssSmAcceptGssReauth(OM_uint32 *minor,
                        gss_ctx_id_t ctx,
                        gss_cred_id_t cred,
                        gss_buffer_t inputToken,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t outputToken);
#endif

/*
 * Mark an acceptor context as ready for cryptographic operations
 */
static OM_uint32
acceptReadyEap(OM_uint32 *minor, gss_ctx_id_t ctx, gss_cred_id_t cred)
{
    OM_uint32 major, tmpMinor;
    VALUE_PAIR *vp;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;

    /* Cache encryption type derived from selected mechanism OID */
    major = gssEapOidToEnctype(minor, ctx->mechanismUsed,
                               &ctx->encryptionType);
    if (GSS_ERROR(major))
        return major;

    gssEapReleaseName(&tmpMinor, &ctx->initiatorName);

    major = gssEapRadiusGetRawAvp(minor, ctx->acceptorCtx.vps,
                                  PW_USER_NAME, 0, &vp);
    if (major == GSS_S_COMPLETE) {
        nameBuf.length = vp->length;
        nameBuf.value = vp->vp_strvalue;
    } else {
        ctx->gssFlags |= GSS_C_ANON_FLAG;
    }

    major = gssEapImportName(minor, &nameBuf, GSS_C_NT_USER_NAME,
                             &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    major = gssEapRadiusGetRawAvp(minor, ctx->acceptorCtx.vps,
                                  PW_MS_MPPE_SEND_KEY, VENDORPEC_MS, &vp);
    if (GSS_ERROR(major)) {
        *minor = GSSEAP_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    major = gssEapDeriveRfc3961Key(minor,
                                   vp->vp_octets,
                                   vp->length,
                                   ctx->encryptionType,
                                   &ctx->rfc3961Key);
    if (GSS_ERROR(major))
        return major;

    major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                       &ctx->checksumType);
    if (GSS_ERROR(major))
        return major;

    major = sequenceInit(minor,
                         &ctx->seqState, ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

    major = gssEapCreateAttrContext(minor, cred, ctx,
                                    &ctx->initiatorName->attrCtx,
                                    &ctx->expiryTime);
    if (GSS_ERROR(major))
        return major;

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Emit a identity EAP request to force the initiator (peer) to identify
 * itself.
 */
static OM_uint32
eapGssSmAcceptIdentity(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t inputToken,
                       gss_channel_bindings_t chanBindings,
                       gss_buffer_t outputToken)
{
    OM_uint32 major;
    struct wpabuf *reqData;
    gss_buffer_desc pktBuffer;

    if (inputToken != GSS_C_NO_BUFFER && inputToken->length != 0) {
        *minor = GSSEAP_WRONG_SIZE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    assert(ctx->acceptorName == GSS_C_NO_NAME);

    if (cred->name != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    reqData = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY, 0,
                            EAP_CODE_REQUEST, 0);
    if (reqData == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    pktBuffer.length = wpabuf_len(reqData);
    pktBuffer.value = (void *)wpabuf_head(reqData);

    major = duplicateBuffer(minor, &pktBuffer, outputToken);
    if (GSS_ERROR(major))
        return major;

    ctx->state = GSSEAP_STATE_AUTHENTICATE;

    wpabuf_free(reqData);

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

/*
 * Returns TRUE if the input token contains an EAP identity response.
 */
static int
isIdentityResponseP(gss_buffer_t inputToken)
{
    struct wpabuf respData;

    wpabuf_set(&respData, inputToken->value, inputToken->length);

    return (eap_get_type(&respData) == EAP_TYPE_IDENTITY);
}

/*
 * Pass the asserted initiator identity to the authentication server.
 */
static OM_uint32
setInitiatorIdentity(OM_uint32 *minor,
                     gss_buffer_t inputToken,
                     VALUE_PAIR **vps)
{
    struct wpabuf respData;
    const unsigned char *pos;
    size_t len;
    gss_buffer_desc nameBuf;

    wpabuf_set(&respData, inputToken->value, inputToken->length);

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_IDENTITY,
                           &respData, &len);
    if (pos == NULL) {
        *minor = GSSEAP_PEER_BAD_MESSAGE;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    nameBuf.value = (void *)pos;
    nameBuf.length = len;

    return gssEapRadiusAddAvp(minor, vps, PW_USER_NAME, 0, &nameBuf);
}

/*
 * Pass the asserted acceptor identity to the authentication server.
 */
static OM_uint32
setAcceptorIdentity(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    VALUE_PAIR **vps)
{
    OM_uint32 major;
    gss_buffer_desc nameBuf;
    krb5_context krbContext = NULL;
    krb5_principal krbPrinc;
    struct rs_context *rc = ctx->acceptorCtx.radContext;

    assert(rc != NULL);

    if (ctx->acceptorName == GSS_C_NO_NAME) {
        *minor = 0;
        return GSS_S_COMPLETE;
    }

    if ((ctx->acceptorName->flags & NAME_FLAG_SERVICE) == 0) {
        *minor = GSSEAP_BAD_SERVICE_NAME;
        return GSS_S_BAD_NAME;
    }

    GSSEAP_KRB_INIT(&krbContext);

    krbPrinc = ctx->acceptorName->krbPrincipal;
    assert(krbPrinc != NULL);
    assert(KRB_PRINC_LENGTH(krbPrinc) >= 2);

    /* Acceptor-Service-Name */
    krbPrincComponentToGssBuffer(krbPrinc, 0, &nameBuf);

    major = gssEapRadiusAddAvp(minor, vps,
                               PW_GSS_ACCEPTOR_SERVICE_NAME,
                               VENDORPEC_UKERNA,
                               &nameBuf);
    if (GSS_ERROR(major))
        return major;

    /* Acceptor-Host-Name */
    krbPrincComponentToGssBuffer(krbPrinc, 1, &nameBuf);

    major = gssEapRadiusAddAvp(minor, vps,
                               PW_GSS_ACCEPTOR_HOST_NAME,
                               VENDORPEC_UKERNA,
                               &nameBuf);
    if (GSS_ERROR(major))
        return major;

    if (KRB_PRINC_LENGTH(krbPrinc) > 2) {
        /* Acceptor-Service-Specific */
        krb5_principal_data ssiPrinc = *krbPrinc;
        char *ssi;

        KRB_PRINC_LENGTH(&ssiPrinc) -= 2;
        KRB_PRINC_NAME(&ssiPrinc) += 2;

        *minor = krb5_unparse_name_flags(krbContext, &ssiPrinc,
                                         KRB5_PRINCIPAL_UNPARSE_NO_REALM, &ssi);
        if (*minor != 0)
            return GSS_S_FAILURE;

        nameBuf.value = ssi;
        nameBuf.length = strlen(ssi);

        major = gssEapRadiusAddAvp(minor, vps,
                                   PW_GSS_ACCEPTOR_SERVICE_SPECIFIC,
                                   VENDORPEC_UKERNA,
                                   &nameBuf);

        if (GSS_ERROR(major)) {
            krb5_free_unparsed_name(krbContext, ssi);
            return major;
        }
        krb5_free_unparsed_name(krbContext, ssi);
    }

    krbPrincRealmToGssBuffer(krbPrinc, &nameBuf);
    if (nameBuf.length != 0) {
        /* Acceptor-Realm-Name */
        major = gssEapRadiusAddAvp(minor, vps,
                                   PW_GSS_ACCEPTOR_REALM_NAME,
                                   VENDORPEC_UKERNA,
                                   &nameBuf);
        if (GSS_ERROR(major))
            return major;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Allocate a RadSec handle
 */
static OM_uint32
createRadiusHandle(OM_uint32 *minor,
                   gss_cred_id_t cred,
                   gss_ctx_id_t ctx)
{
    struct gss_eap_acceptor_ctx *actx = &ctx->acceptorCtx;
    const char *configFile = RS_CONFIG_FILE;
    const char *configStanza = "gss-eap";
    struct rs_alloc_scheme ralloc;
    struct rs_error *err;

    assert(actx->radContext == NULL);
    assert(actx->radConn == NULL);

    if (rs_context_create(&actx->radContext, RS_DICT_FILE) != 0) {
        *minor = GSSEAP_RADSEC_CONTEXT_FAILURE;
        return GSS_S_FAILURE;
    }

    if (cred->radiusConfigFile != NULL)
        configFile = cred->radiusConfigFile;
    if (cred->radiusConfigStanza != NULL)
        configStanza = cred->radiusConfigStanza;

    ralloc.calloc  = GSSEAP_CALLOC;
    ralloc.malloc  = GSSEAP_MALLOC;
    ralloc.free    = GSSEAP_FREE;
    ralloc.realloc = GSSEAP_REALLOC;

    rs_context_set_alloc_scheme(actx->radContext, &ralloc);

    if (rs_context_read_config(actx->radContext, configFile) != 0) {
        err = rs_err_ctx_pop(actx->radContext);
        goto fail;
    }

    if (rs_conn_create(actx->radContext, &actx->radConn, configStanza) != 0) {
        err = rs_err_conn_pop(actx->radConn);
        goto fail;
    }

    if (actx->radServer != NULL) {
        if (rs_conn_select_peer(actx->radConn, actx->radServer) != 0) {
            err = rs_err_conn_pop(actx->radConn);
            goto fail;
        }
    }

    *minor = 0;
    return GSS_S_COMPLETE;

fail:
    return gssEapRadiusMapError(minor, err);
}

/*
 * Process a EAP response from the initiator.
 */
static OM_uint32
eapGssSmAcceptAuthenticate(OM_uint32 *minor,
                           gss_ctx_id_t ctx,
                           gss_cred_id_t cred,
                           gss_buffer_t inputToken,
                           gss_channel_bindings_t chanBindings,
                           gss_buffer_t outputToken)
{
    OM_uint32 major, tmpMinor;
    struct rs_connection *rconn;
    struct rs_request *request = NULL;
    struct rs_packet *req = NULL, *resp = NULL;
    struct radius_packet *frreq, *frresp;
    int isIdentityResponse = isIdentityResponseP(inputToken);

    if (ctx->acceptorCtx.radContext == NULL) {
        /* May be NULL from an imported partial context */
        major = createRadiusHandle(minor, cred, ctx);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    rconn = ctx->acceptorCtx.radConn;

    if (rs_packet_create_authn_request(rconn, &req, NULL, NULL) != 0) {
        major = gssEapRadiusMapError(minor, rs_err_conn_pop(rconn));
        goto cleanup;
    }
    frreq = rs_packet_frpkt(req);

    if (isIdentityResponse) {
        major = setInitiatorIdentity(minor, inputToken, &frreq->vps);
        if (GSS_ERROR(major))
            goto cleanup;

        major = setAcceptorIdentity(minor, ctx, &frreq->vps);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = gssEapRadiusAddAvp(minor, &frreq->vps,
                               PW_EAP_MESSAGE, 0, inputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (ctx->acceptorCtx.state.length != 0) {
        major = gssEapRadiusAddAvp(minor, &frreq->vps, PW_STATE, 0,
                                   &ctx->acceptorCtx.state);
        if (GSS_ERROR(major))
            goto cleanup;

        gss_release_buffer(&tmpMinor, &ctx->acceptorCtx.state);
    }

    if (rs_request_create(rconn, &request) != 0) {
        major = gssEapRadiusMapError(minor, rs_err_conn_pop(rconn));
        goto cleanup;
    }

    rs_request_add_reqpkt(request, req);
    req = NULL;

    if (rs_request_send(request, &resp) != 0) {
        major = gssEapRadiusMapError(minor, rs_err_conn_pop(rconn));
        goto cleanup;
    }

    assert(resp != NULL);

    frresp = rs_packet_frpkt(resp);
    switch (frresp->code) {
    case PW_AUTHENTICATION_ACK:
    case PW_ACCESS_CHALLENGE:
        major = GSS_S_CONTINUE_NEEDED;
        break;
    case PW_AUTHENTICATION_REJECT:
        *minor = GSSEAP_RADIUS_AUTH_FAILURE;
        major = GSS_S_DEFECTIVE_CREDENTIAL;
        goto cleanup;
        break;
    default:
        *minor = GSSEAP_UNKNOWN_RADIUS_CODE;
        major = GSS_S_FAILURE;
        goto cleanup;
        break;
    }

    major = gssEapRadiusGetAvp(minor, frresp->vps, PW_EAP_MESSAGE, 0,
                               outputToken, TRUE);
    if (major == GSS_S_UNAVAILABLE && frresp->code == PW_ACCESS_CHALLENGE) {
        *minor = GSSEAP_MISSING_EAP_REQUEST;
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    } else if (GSS_ERROR(major))
        goto cleanup;

    if (frresp->code == PW_ACCESS_CHALLENGE) {
        major = gssEapRadiusGetAvp(minor, frresp->vps, PW_STATE, 0,
                                   &ctx->acceptorCtx.state, TRUE);
        if (GSS_ERROR(major) && *minor != GSSEAP_NO_SUCH_ATTR)
            goto cleanup;
    } else {
        ctx->acceptorCtx.vps = frresp->vps;
        frresp->vps = NULL;

        rs_conn_destroy(ctx->acceptorCtx.radConn);
        ctx->acceptorCtx.radConn = NULL;

        major = acceptReadyEap(minor, ctx, cred);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->state = GSSEAP_STATE_EXTENSIONS_REQ;
    }

    *minor = 0;
    major = GSS_S_CONTINUE_NEEDED;

cleanup:
    if (request != NULL)
        rs_request_destroy(request);
    if (req != NULL)
        rs_packet_destroy(req);

    return major;
}

static OM_uint32
eapGssSmAcceptExtensionsReq(OM_uint32 *minor,
                            gss_ctx_id_t ctx,
                            gss_cred_id_t cred,
                            gss_buffer_t inputToken,
                            gss_channel_bindings_t chanBindings,
                            gss_buffer_t outputToken)
{
    OM_uint32 major;

    major = gssEapVerifyExtensions(minor, cred, ctx, chanBindings, inputToken);
    if (GSS_ERROR(major))
        return major;

    outputToken->length = 0;
    outputToken->value = NULL;

    ctx->state = GSSEAP_STATE_EXTENSIONS_RESP;

    *minor = 0;
    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
eapGssSmAcceptExtensionsResp(OM_uint32 *minor,
                             gss_ctx_id_t ctx,
                             gss_cred_id_t cred,
                             gss_buffer_t inputToken,
                             gss_channel_bindings_t chanBindings,
                             gss_buffer_t outputToken)
{
    OM_uint32 major;

    major = gssEapMakeExtensions(minor, cred, ctx, chanBindings, outputToken);
    if (GSS_ERROR(major))
        return major;

    ctx->state = GSSEAP_STATE_ESTABLISHED;

    *minor = 0;
    return GSS_S_COMPLETE;
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
    *minor = GSSEAP_CONTEXT_ESTABLISHED;
    return GSS_S_BAD_STATUS;
}

static OM_uint32
makeErrorToken(OM_uint32 *minor,
               OM_uint32 majorStatus,
               OM_uint32 minorStatus,
               gss_buffer_t outputToken)
{
    unsigned char errorData[8];
    gss_buffer_desc errorBuffer;

    assert(GSS_ERROR(majorStatus));

    /*
     * Only return error codes that the initiator could have caused,
     * to avoid information leakage.
     */
    if (IS_RADIUS_ERROR(minorStatus)) {
        /* Squash RADIUS error codes */
        minorStatus = GSSEAP_RADIUS_PROT_FAILURE;
    } else if (!IS_WIRE_ERROR(minorStatus)) {
        /* Don't return non-wire error codes */
        return GSS_S_COMPLETE;
    }

    minorStatus -= ERROR_TABLE_BASE_eapg;

    store_uint32_be(majorStatus, &errorData[0]);
    store_uint32_be(minorStatus, &errorData[4]);

    errorBuffer.length = sizeof(errorData);
    errorBuffer.value = errorData;

    return duplicateBuffer(minor, &errorBuffer, outputToken);
}

static struct gss_eap_acceptor_sm {
    enum gss_eap_token_type inputTokenType;
    enum gss_eap_token_type outputTokenType;
    OM_uint32 (*processToken)(OM_uint32 *,
                              gss_ctx_id_t,
                              gss_cred_id_t,
                              gss_buffer_t,
                              gss_channel_bindings_t,
                              gss_buffer_t);
} eapGssAcceptorSm[] = {
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,       eapGssSmAcceptIdentity           },
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,       eapGssSmAcceptAuthenticate       },
    { TOK_TYPE_EXT_REQ,     TOK_TYPE_NONE,          eapGssSmAcceptExtensionsReq      },
    { TOK_TYPE_NONE,        TOK_TYPE_EXT_RESP,      eapGssSmAcceptExtensionsResp     },
    { TOK_TYPE_NONE,        TOK_TYPE_NONE,          eapGssSmAcceptEstablished        },
    { TOK_TYPE_NONE,        TOK_TYPE_CONTEXT_ERR,   NULL                             },
#ifdef GSSEAP_ENABLE_REAUTH
    { TOK_TYPE_GSS_REAUTH,  TOK_TYPE_GSS_REAUTH,    eapGssSmAcceptGssReauth          },
#endif
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
    struct gss_eap_acceptor_sm *sm = NULL;
    gss_buffer_desc innerInputToken = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc innerOutputToken = GSS_C_EMPTY_BUFFER;
    enum gss_eap_token_type tokType;
    int initialContextToken = 0;

    *minor = 0;

    output_token->length = 0;
    output_token->value = NULL;

    if (input_token == GSS_C_NO_BUFFER || input_token->length == 0) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (ctx == GSS_C_NO_CONTEXT) {
        major = gssEapAllocContext(minor, &ctx);
        if (GSS_ERROR(major))
            return major;

        initialContextToken = 1;
        *context_handle = ctx;
    }

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (cred == GSS_C_NO_CREDENTIAL) {
        if (ctx->defaultCred == GSS_C_NO_CREDENTIAL) {
            major = gssEapAcquireCred(minor,
                                      GSS_C_NO_NAME,
                                      GSS_C_NO_BUFFER,
                                      GSS_C_INDEFINITE,
                                      GSS_C_NO_OID_SET,
                                      GSS_C_ACCEPT,
                                      &ctx->defaultCred,
                                      NULL,
                                      NULL);
            if (GSS_ERROR(major))
                goto cleanup;
        }

        cred = ctx->defaultCred;
    }

    GSSEAP_MUTEX_LOCK(&cred->mutex);

    sm = &eapGssAcceptorSm[ctx->state];

    major = gssEapVerifyToken(minor, ctx, input_token,
                              &tokType, &innerInputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
        *minor = GSSEAP_CRED_MECH_MISMATCH;
        major = GSS_S_BAD_MECH;
        goto cleanup;
    }

#ifdef GSSEAP_ENABLE_REAUTH
    /*
     * If we're built with fast reauthentication support, it's valid
     * for an initiator to send a GSS reauthentication token as its
     * initial context token, causing us to short-circuit the state
     * machine and process Kerberos GSS messages instead.
     */
    if (tokType == TOK_TYPE_GSS_REAUTH && initialContextToken) {
        ctx->state = GSSEAP_STATE_KRB_REAUTH;
    } else
#endif
    if (tokType != sm->inputTokenType) {
        *minor = GSSEAP_WRONG_TOK_ID;
        major = GSS_S_DEFECTIVE_TOKEN;
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
        if (GSS_ERROR(major)) {
            /* Possibly generate an error token */
            tmpMajor = makeErrorToken(&tmpMinor, major, *minor, &innerOutputToken);
            if (GSS_ERROR(tmpMajor)) {
                major = tmpMajor;
                goto cleanup;
            }

            sm = &eapGssAcceptorSm[GSSEAP_STATE_ERROR];
            goto send_token;
        }
    } while (major == GSS_S_CONTINUE_NEEDED && innerOutputToken.length == 0);

    if (mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, mech_type);
    }
    if (ret_flags != NULL)
        *ret_flags = ctx->gssFlags;
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (major == GSS_S_COMPLETE) {
        if (src_name != NULL && ctx->initiatorName != GSS_C_NO_NAME) {
            major = gssEapDuplicateName(&tmpMinor, ctx->initiatorName, src_name);
            if (GSS_ERROR(major))
                goto cleanup;
        }
        if (time_rec != NULL) {
            major = gssEapContextTime(&tmpMinor, ctx, time_rec);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

    assert(ctx->state == GSSEAP_STATE_ESTABLISHED || major == GSS_S_CONTINUE_NEEDED);

send_token:
    if (innerOutputToken.value != NULL) {
        tmpMajor = gssEapMakeToken(&tmpMinor, ctx, &innerOutputToken,
                                   sm->outputTokenType, output_token);
        if (GSS_ERROR(tmpMajor)) {
            major = tmpMajor;
            *minor = tmpMinor;
            goto cleanup;
        }
    }

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
acceptReadyKrb(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               gss_cred_id_t cred,
               const gss_name_t initiator,
               const gss_OID mech,
               OM_uint32 timeRec)
{
    OM_uint32 major;

    major = gssEapGlueToMechName(minor, ctx, initiator, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (cred->name != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    major = gssEapReauthComplete(minor, ctx, cred, mech, timeRec);
    if (GSS_ERROR(major))
        return major;

    ctx->state = GSSEAP_STATE_ESTABLISHED;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmAcceptGssReauth(OM_uint32 *minor,
                        gss_ctx_id_t ctx,
                        gss_cred_id_t cred,
                        gss_buffer_t inputToken,
                        gss_channel_bindings_t chanBindings,
                        gss_buffer_t outputToken)
{
    OM_uint32 major, tmpMinor;
    gss_name_t krbInitiator = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    OM_uint32 gssFlags, timeRec = GSS_C_INDEFINITE;

    ctx->flags |= CTX_FLAG_KRB_REAUTH;

    major = gssAcceptSecContext(minor,
                                &ctx->kerberosCtx,
                                cred->krbCred,
                                inputToken,
                                chanBindings,
                                &krbInitiator,
                                &mech,
                                outputToken,
                                &gssFlags,
                                &timeRec,
                                NULL);
    if (major == GSS_S_COMPLETE) {
        major = acceptReadyKrb(minor, ctx, cred,
                               krbInitiator, mech, timeRec);
    }

    ctx->gssFlags = gssFlags;

    gssReleaseName(&tmpMinor, &krbInitiator);

    return major;
}
#endif /* GSSEAP_ENABLE_REAUTH */
