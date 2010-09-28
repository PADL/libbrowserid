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
 * Mark a context as ready for cryptographic operations
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

    vp = rc_avpair_get(ctx->acceptorCtx.avps, PW_USER_NAME, 0);
    if (vp != NULL) {
        nameBuf.length = vp->lvalue;
        nameBuf.value = vp->strvalue;
    } else {
        ctx->gssFlags |= GSS_C_ANON_FLAG;
    }

    major = gssEapImportName(minor, &nameBuf, GSS_C_NT_USER_NAME,
                             &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    ctx->initiatorName->attrCtx = gssEapCreateAttrContext(cred, ctx);

    vp = rc_avpair_get(ctx->acceptorCtx.avps,
                       VENDOR_ATTR_MS_MPPE_SEND_KEY,
                       VENDOR_ID_MICROSOFT);
    if (ctx->encryptionType != ENCTYPE_NULL && vp != NULL) {
        major = gssEapDeriveRfc3961Key(minor,
                                       (unsigned char *)vp->strvalue,
                                       vp->lvalue,
                                       ctx->encryptionType,
                                       &ctx->rfc3961Key);
        if (GSS_ERROR(major))
            return major;

        major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                           &ctx->checksumType);
        if (GSS_ERROR(major))
            return major;
    } else {
        /*
         * draft-howlett-eap-gss says that integrity/confidentialty should
         * always be advertised as available, but if we have no keying
         * material it seems confusing to the caller to advertise this.
         */
        ctx->gssFlags &= ~(GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG);
        ctx->encryptionType = ENCTYPE_NULL;
    }

    major = sequenceInit(minor,
                         &ctx->seqState, ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

    return GSS_S_COMPLETE;
}

static OM_uint32
eapGssSmAcceptIdentity(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t inputToken,
                       gss_channel_bindings_t chanBindings,
                       gss_buffer_t outputToken)
{
    OM_uint32 major;
    union {
        struct eap_hdr pdu;
        unsigned char data[5];
    } pkt;
    gss_buffer_desc pktBuffer;

    if (inputToken != GSS_C_NO_BUFFER && inputToken->length != 0)
        return GSS_S_DEFECTIVE_TOKEN;

    assert(ctx->acceptorCtx.radHandle == NULL);

    major = gssEapRadiusAllocHandle(minor, cred, &ctx->acceptorCtx.radHandle);
    if (GSS_ERROR(major))
        return major;

    assert(ctx->acceptorName == GSS_C_NO_NAME);

    if (cred != GSS_C_NO_CREDENTIAL && cred->name != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    pkt.pdu.code = EAP_CODE_REQUEST;
    pkt.pdu.identifier = 0;
    pkt.pdu.length = htons(sizeof(pkt.data));
    pkt.data[4] = EAP_TYPE_IDENTITY;

    pktBuffer.length = sizeof(pkt.data);
    pktBuffer.value = pkt.data;

    major = duplicateBuffer(minor, &pktBuffer, outputToken);
    if (GSS_ERROR(major))
        return major;

    ctx->state = EAP_STATE_AUTHENTICATE;

    return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
setAcceptorIdentity(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    VALUE_PAIR **avps)
{
    OM_uint32 major;
    gss_buffer_desc nameBuf;
    krb5_context krbContext = NULL;
    krb5_principal krbPrinc;

    /* Awaits further specification */
    if (ctx->acceptorName == GSS_C_NO_NAME)
        return GSS_S_COMPLETE;

    GSSEAP_KRB_INIT(&krbContext);

    krbPrinc = ctx->acceptorName->krbPrincipal;
    assert(krbPrinc != NULL);

    if (krb5_princ_size(krbContext, krbPrinc) < 2)
        return GSS_S_BAD_NAME;

    /* Acceptor-Service-Name */
    krbDataToGssBuffer(krb5_princ_component(krbContext, krbPrinc, 0), &nameBuf);

    major = addAvpFromBuffer(minor, ctx->acceptorCtx.radHandle, avps,
                             VENDOR_ATTR_GSS_ACCEPTOR_SERVICE_NAME,
                             VENDOR_ID_UKERNA,
                             &nameBuf);
    if (GSS_ERROR(major))
        return major;

    /* Acceptor-Host-Name */
    krbDataToGssBuffer(krb5_princ_component(krbContext, krbPrinc, 1), &nameBuf);

    major = addAvpFromBuffer(minor, ctx->acceptorCtx.radHandle, avps,
                             VENDOR_ATTR_GSS_ACCEPTOR_HOST_NAME,
                             VENDOR_ID_UKERNA,
                             &nameBuf);
    if (GSS_ERROR(major))
        return major;

    if (krb5_princ_size(krbContext, krbPrinc) > 2) {
        /* Acceptor-Service-Specific */
        krb5_principal_data ssiPrinc = *krbPrinc;
        char *ssi;

        krb5_princ_size(krbContext, &ssiPrinc) -= 2;
        krb5_princ_name(krbContext, &ssiPrinc) += 2;

        *minor = krb5_unparse_name_flags(krbContext, &ssiPrinc,
                                         KRB5_PRINCIPAL_UNPARSE_NO_REALM, &ssi);
        if (*minor != 0)
            return GSS_S_FAILURE;

        nameBuf.value = ssi;
        nameBuf.length = strlen(ssi);

        major = addAvpFromBuffer(minor, ctx->acceptorCtx.radHandle, avps,
                                 VENDOR_ATTR_GSS_ACCEPTOR_SERVICE_SPECIFIC,
                                 VENDOR_ID_UKERNA,
                                 &nameBuf);

        if (GSS_ERROR(major)) {
            krb5_free_unparsed_name(krbContext, ssi);
            return major;
        }
        krb5_free_unparsed_name(krbContext, ssi);
    }

    krbDataToGssBuffer(krb5_princ_realm(krbContext, krbPrinc), &nameBuf);
    if (nameBuf.length != 0) {
        /* Acceptor-Realm-Name */
        major = addAvpFromBuffer(minor, ctx->acceptorCtx.radHandle, avps,
                                 VENDOR_ATTR_GSS_ACCEPTOR_REALM_NAME,
                                 VENDOR_ID_UKERNA,
                                 &nameBuf);
        if (GSS_ERROR(major))
            return major;
    }

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
    OM_uint32 major, tmpMinor;
    int code;
    VALUE_PAIR *send = NULL;
    VALUE_PAIR *received = NULL;
    rc_handle *rh = ctx->acceptorCtx.radHandle;
    char msgBuffer[4096];
    struct eap_hdr *pdu;
    unsigned char *pos;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;

    pdu = (struct eap_hdr *)inputToken->value;
    pos = (unsigned char *)(pdu + 1);

    if (inputToken->length > sizeof(*pdu) &&
        pdu->code == EAP_CODE_RESPONSE &&
        pos[0] == EAP_TYPE_IDENTITY) {
        /*
         * XXX TODO do we really need to set User-Name? FreeRADIUS does
         * not require it but some other RADIUS servers might.
         */
        major = addAvpFromBuffer(minor, rh, &send, PW_USER_NAME, 0, &nameBuf);
        if (GSS_ERROR(major))
            goto cleanup;

        major = setAcceptorIdentity(minor, ctx, &send);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = addAvpFromBuffer(minor, rh, &send, PW_EAP_MESSAGE, 0, inputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (ctx->acceptorCtx.lastStatus == CHALLENGE_RC) {
        major = addAvpFromBuffer(minor, rh, &send, PW_STATE, 0,
                                 &ctx->acceptorCtx.state);
        if (GSS_ERROR(major))
            goto cleanup;

        gss_release_buffer(&tmpMinor, &ctx->acceptorCtx.state);
    }

    code = rc_auth(rh, 0, send, &received, msgBuffer);
    switch (code) {
    case OK_RC:
    case CHALLENGE_RC:
        major = GSS_S_CONTINUE_NEEDED;
        break;
    case TIMEOUT_RC:
        major = GSS_S_UNAVAILABLE;
        break;
    case REJECT_RC:
        major = GSS_S_DEFECTIVE_CREDENTIAL;
        break;
    default:
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    if (GSS_ERROR(major))
        goto cleanup;

    ctx->acceptorCtx.lastStatus = code;

    major = getBufferFromAvps(minor, received, PW_EAP_MESSAGE, 0,
                              outputToken, TRUE);
    if ((major == GSS_S_UNAVAILABLE && code != OK_RC) ||
        GSS_ERROR(major))
        goto cleanup;

    if (code == CHALLENGE_RC) {
        major = getBufferFromAvps(minor, received, PW_STATE, 0,
                                  &ctx->acceptorCtx.state, TRUE);
        if (major != GSS_S_UNAVAILABLE && GSS_ERROR(major))
            goto cleanup;
    } else {
        ctx->acceptorCtx.avps = received;
        received = NULL;

        major = acceptReadyEap(minor, ctx, cred);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->state = EAP_STATE_EXTENSIONS_REQ;
    }

    major = GSS_S_CONTINUE_NEEDED;

cleanup:
    if (received != NULL)
        rc_avpair_free(received);

    return major;
}

static OM_uint32
acceptGssChannelBindings(OM_uint32 *minor,
                         gss_ctx_id_t ctx,
                         gss_cred_id_t cred,
                         gss_buffer_t inputToken,
                         gss_channel_bindings_t chanBindings)
{
    OM_uint32 major, tmpMinor;
    gss_iov_buffer_desc iov[2];

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[0].buffer.length = 0;
    iov[0].buffer.value = NULL;

    iov[1].type = GSS_IOV_BUFFER_TYPE_STREAM;
    iov[1].buffer = *inputToken;

    major = gssEapUnwrapOrVerifyMIC(minor, ctx, NULL, NULL,
                                    iov, 2, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        return major;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS &&
        !bufferEqual(&iov[0].buffer, &chanBindings->application_data)) {
        major = GSS_S_BAD_BINDINGS;
    } else {
        major = GSS_S_CONTINUE_NEEDED;
    }

    gss_release_buffer(&tmpMinor, &iov[0].buffer);

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

    outputToken->length = 0;
    outputToken->value = NULL;

    major = acceptGssChannelBindings(minor, ctx, cred, inputToken,
                                     chanBindings);
    if (GSS_ERROR(major))
        return major;

    ctx->state = EAP_STATE_EXTENSIONS_RESP;

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
    OM_uint32 major, tmpMinor;
    gss_buffer_desc credsToken = GSS_C_EMPTY_BUFFER;

#ifdef GSSEAP_ENABLE_REAUTH
    /*
     * If we're built with fast reauthentication enabled, then
     * fabricate a ticket from the initiator to ourselves.
     * Otherwise return an empty token.
     */
    major = gssEapMakeReauthCreds(minor, ctx, cred, &credsToken);
    if (GSS_ERROR(major))
        return major;
#else
    credsToken.value = "";
#endif /* GSSEAP_ENABLE_REAUTH */

    major = duplicateBuffer(minor, &credsToken, outputToken);
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, &credsToken);
        return major;
    }

#ifdef GSSEAP_ENABLE_REAUTH
    gss_release_buffer(&tmpMinor, &credsToken);
#endif

    ctx->state = EAP_STATE_ESTABLISHED;

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
    *minor = EINVAL;
    return GSS_S_BAD_STATUS;
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
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,    eapGssSmAcceptIdentity           },
    { TOK_TYPE_EAP_RESP,    TOK_TYPE_EAP_REQ,    eapGssSmAcceptAuthenticate       },
    { TOK_TYPE_EXT_REQ,     TOK_TYPE_NONE,       eapGssSmAcceptExtensionsReq      },
    { TOK_TYPE_NONE,        TOK_TYPE_EXT_RESP,   eapGssSmAcceptExtensionsResp     },
    { TOK_TYPE_NONE,        TOK_TYPE_NONE,       eapGssSmAcceptEstablished        },
#ifdef GSSEAP_ENABLE_REAUTH
    { TOK_TYPE_GSS_REAUTH,  TOK_TYPE_GSS_REAUTH, eapGssSmAcceptGssReauth          },
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

    /* Validate and lock credentials */
    if (cred != GSS_C_NO_CREDENTIAL) {
        if ((cred->flags & CRED_FLAG_ACCEPT) == 0) {
            major = GSS_S_NO_CRED;
            goto cleanup;
        }
        GSSEAP_MUTEX_LOCK(&cred->mutex);
    }

    sm = &eapGssAcceptorSm[ctx->state];

    major = gssEapVerifyToken(minor, ctx, input_token,
                              &tokType, &innerInputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    if (!gssEapCredAvailable(cred, ctx->mechanismUsed)) {
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
        ctx->state = EAP_STATE_KRB_REAUTH_GSS;
    } else
#endif
    if (tokType != sm->inputTokenType) {
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
        if (GSS_ERROR(major))
            goto cleanup;
    } while (major == GSS_S_CONTINUE_NEEDED && innerOutputToken.length == 0);

    if (mech_type != NULL) {
        if (!gssEapInternalizeOid(ctx->mechanismUsed, mech_type))
            duplicateOid(&tmpMinor, ctx->mechanismUsed, mech_type);
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
    if (delegated_cred_handle != NULL)
        *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

    if (major == GSS_S_COMPLETE) {
        if (src_name != NULL && ctx->initiatorName != GSS_C_NO_NAME) {
            major = gssEapDuplicateName(&tmpMinor, ctx->initiatorName, src_name);
            if (GSS_ERROR(major))
                goto cleanup;
        }
        if (time_rec != NULL)
            gssEapContextTime(&tmpMinor, ctx, time_rec);
    }

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
acceptReadyKrb(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               gss_cred_id_t cred,
               const gss_name_t initiator,
               const gss_OID mech,
               OM_uint32 timeRec)
{
    OM_uint32 major;

    major = gssEapGlueToMechName(minor, initiator, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (cred != GSS_C_NO_CREDENTIAL && cred->name != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, cred->name, &ctx->acceptorName);
        if (GSS_ERROR(major))
            return major;
    }

    major = gssEapReauthComplete(minor, ctx, cred, mech, timeRec);
    if (GSS_ERROR(major))
        return major;

    ctx->state = EAP_STATE_ESTABLISHED;

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
    gss_cred_id_t krbCred = GSS_C_NO_CREDENTIAL;
    gss_name_t krbInitiator = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    OM_uint32 gssFlags, timeRec = GSS_C_INDEFINITE;

    ctx->flags |= CTX_FLAG_KRB_REAUTH_GSS;

    if (cred != GSS_C_NO_CREDENTIAL)
        krbCred = cred->krbCred;

    major = gssAcceptSecContext(minor,
                                &ctx->kerberosCtx,
                                krbCred,
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
