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
 * Utility routines for context handles.
 */

#include "gssapiP_eap.h"

OM_uint32
gssEapAllocContext(OM_uint32 *minor,
                   gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx;

    GSSEAP_ASSERT(*pCtx == GSS_C_NO_CONTEXT);

    ctx = (gss_ctx_id_t)GSSEAP_CALLOC(1, sizeof(*ctx));
    if (ctx == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&ctx->mutex) != 0) {
        *minor = GSSEAP_GET_LAST_ERROR();
        gssEapReleaseContext(&tmpMinor, &ctx);
        return GSS_S_FAILURE;
    }

    ctx->state = GSSEAP_STATE_INITIAL;
    ctx->mechanismUsed = GSS_C_NO_OID;

    /*
     * Integrity, confidentiality, sequencing and replay detection are
     * always available.  Regardless of what flags are requested in
     * GSS_Init_sec_context, implementations MUST set the flag corresponding
     * to these services in the output of GSS_Init_sec_context and
     * GSS_Accept_sec_context.
    */
    ctx->gssFlags = GSS_C_TRANS_FLAG    |   /* exporting contexts */
                    GSS_C_INTEG_FLAG    |   /* integrity */
                    GSS_C_CONF_FLAG     |   /* confidentiality */
                    GSS_C_SEQUENCE_FLAG |   /* sequencing */
                    GSS_C_REPLAY_FLAG;      /* replay detection */

    *pCtx = ctx;

    return GSS_S_COMPLETE;
}

static void
releaseInitiatorContext(struct gss_eap_initiator_ctx *ctx)
{
    eap_peer_sm_deinit(ctx->eap);
}

#ifdef GSSEAP_ENABLE_ACCEPTOR
static void
releaseAcceptorContext(struct gss_eap_acceptor_ctx *ctx)
{
    OM_uint32 tmpMinor;

    if (ctx->radConn != NULL)
        rs_conn_destroy(ctx->radConn);
    if (ctx->radContext != NULL)
        rs_context_destroy(ctx->radContext);
    if (ctx->radServer != NULL)
        GSSEAP_FREE(ctx->radServer);
    gss_release_buffer(&tmpMinor, &ctx->state);
    if (ctx->vps != NULL)
        gssEapRadiusFreeAvps(&tmpMinor, &ctx->vps);
}
#endif /* GSSEAP_ENABLE_ACCEPTOR */

OM_uint32
gssEapReleaseContext(OM_uint32 *minor,
                     gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx = *pCtx;
    krb5_context krbContext = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        return GSS_S_COMPLETE;
    }

    gssEapKerberosInit(&tmpMinor, &krbContext);

#ifdef GSSEAP_ENABLE_REAUTH
    if (ctx->flags & CTX_FLAG_KRB_REAUTH) {
        gssDeleteSecContext(&tmpMinor, &ctx->reauthCtx, GSS_C_NO_BUFFER);
    } else
#endif /* GSSEAP_ENABLE_REAUTH */
    if (CTX_IS_INITIATOR(ctx)) {
        releaseInitiatorContext(&ctx->initiatorCtx);
    }
#ifdef GSSEAP_ENABLE_ACCEPTOR
    else {
        releaseAcceptorContext(&ctx->acceptorCtx);
    }
#endif /* GSSEAP_ENABLE_ACCEPTOR */

    krb5_free_keyblock_contents(krbContext, &ctx->rfc3961Key);
    gssEapReleaseName(&tmpMinor, &ctx->initiatorName);
    gssEapReleaseName(&tmpMinor, &ctx->acceptorName);
    gssEapReleaseOid(&tmpMinor, &ctx->mechanismUsed);
    sequenceFree(&tmpMinor, &ctx->seqState);
    gssEapReleaseCred(&tmpMinor, &ctx->cred);

    GSSEAP_MUTEX_DESTROY(&ctx->mutex);

    memset(ctx, 0, sizeof(*ctx));
    GSSEAP_FREE(ctx);
    *pCtx = GSS_C_NO_CONTEXT;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapMakeToken(OM_uint32 *minor,
                gss_ctx_id_t ctx,
                const gss_buffer_t innerToken,
                enum gss_eap_token_type tokenType,
                gss_buffer_t outputToken)
{
    unsigned char *p;

    GSSEAP_ASSERT(ctx->mechanismUsed != GSS_C_NO_OID);

    outputToken->length = tokenSize(ctx->mechanismUsed, innerToken->length);
    outputToken->value = GSSEAP_MALLOC(outputToken->length);
    if (outputToken->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    p = (unsigned char *)outputToken->value;
    makeTokenHeader(ctx->mechanismUsed, innerToken->length, &p, tokenType);
    memcpy(p, innerToken->value, innerToken->length);

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapVerifyToken(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  const gss_buffer_t inputToken,
                  enum gss_eap_token_type *actualToken,
                  gss_buffer_t innerInputToken)
{
    OM_uint32 major;
    size_t bodySize;
    unsigned char *p = (unsigned char *)inputToken->value;
    gss_OID_desc oidBuf;
    gss_OID oid;

    if (ctx->mechanismUsed != GSS_C_NO_OID) {
        oid = ctx->mechanismUsed;
    } else {
        oidBuf.elements = NULL;
        oidBuf.length = 0;
        oid = &oidBuf;
    }

    major = verifyTokenHeader(minor, oid, &bodySize, &p,
                              inputToken->length, actualToken);
    if (GSS_ERROR(major))
        return major;

    if (ctx->mechanismUsed == GSS_C_NO_OID) {
        major = gssEapCanonicalizeOid(minor, oid, 0, &ctx->mechanismUsed);
        if (GSS_ERROR(major))
            return major;
    }

    innerInputToken->length = bodySize;
    innerInputToken->value = p;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapContextTime(OM_uint32 *minor,
                  gss_ctx_id_t context_handle,
                  OM_uint32 *time_rec)
{
    *minor = 0;

    if (context_handle->expiryTime == 0) {
        *time_rec = GSS_C_INDEFINITE;
    } else {
        time_t now, lifetime;

        time(&now);
        lifetime = context_handle->expiryTime - now;
        if (lifetime <= 0) {
            *time_rec = 0;
            return GSS_S_CONTEXT_EXPIRED;
        }
        *time_rec = lifetime;
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
gssEapMakeOrVerifyTokenMIC(OM_uint32 *minor,
                           gss_ctx_id_t ctx,
                           gss_buffer_t tokenMIC,
                           int verifyMIC)
{
    OM_uint32 major;
    size_t i = 0, j;
    enum gss_eap_token_type tokType;
    OM_uint32 micTokType;
    unsigned char wireTokType[2];
    unsigned char *innerTokTypes = NULL, *innerTokLengths = NULL;
    const struct gss_eap_token_buffer_set *tokens;
    ssize_t checksumIndex = -1;

    krb5_keyusage usage;
    krb5_error_code code = 0;
    krb5_context krbContext;
    krb5_crypto_iov *kiov = NULL;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
    krb5_cksumtype cksumType;
#endif
    size_t kiovCount;

    GSSEAP_KRB_INIT(&krbContext);

    tokens = verifyMIC ? ctx->inputTokens : ctx->outputTokens;

    GSSEAP_ASSERT(tokens != NULL);

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_init(krbContext, &ctx->rfc3961Key, ETYPE_NULL, &krbCrypto);
    if (code != 0)
        goto cleanup;
#endif

    kiovCount = 2 + (3 * tokens->buffers.count) + 1;

    if (verifyMIC) {
        assert(tokens->buffers.count != 0);
        kiovCount -= 3;
    }

    kiov = GSSEAP_CALLOC(kiovCount, sizeof(*kiov));
    if (kiov == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    innerTokTypes = GSSEAP_MALLOC(4 * tokens->buffers.count);
    if (innerTokTypes == NULL) {
        *minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    innerTokLengths = GSSEAP_MALLOC(4 * tokens->buffers.count);
    if (innerTokLengths == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    /* Mechanism OID */
    GSSEAP_ASSERT(ctx->mechanismUsed != GSS_C_NO_OID);
    kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    kiov[i].data.length = ctx->mechanismUsed->length;
    kiov[i].data.data = ctx->mechanismUsed->elements;
    i++;

    /* Token type */
    if (CTX_IS_INITIATOR(ctx) ^ verifyMIC) {
        tokType = TOK_TYPE_INITIATOR_CONTEXT;
        micTokType = ITOK_TYPE_INITIATOR_MIC;
        usage = KEY_USAGE_GSSEAP_INITOKEN_MIC;
    } else {
        tokType = TOK_TYPE_ACCEPTOR_CONTEXT;
        micTokType = ITOK_TYPE_ACCEPTOR_MIC;
        usage = KEY_USAGE_GSSEAP_ACCTOKEN_MIC;
    }
    store_uint16_be(tokType, wireTokType);

    kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
    kiov[i].data.length = sizeof(wireTokType);
    kiov[i].data.data = (char *)wireTokType;
    i++;

    for (j = 0; j < tokens->buffers.count; j++) {
        if (verifyMIC &&
            (tokens->types[j] & ITOK_TYPE_MASK) == micTokType) {
            continue;
        }

        kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        kiov[i].data.length = 4;
        kiov[i].data.data = (char *)&innerTokTypes[j * 4];
        store_uint32_be(tokens->types[j] & ~(ITOK_FLAG_VERIFIED),
                        kiov[i].data.data);
        i++;

        kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        kiov[i].data.length = 4;
        kiov[i].data.data = (char *)&innerTokLengths[j * 4];
        store_uint32_be(tokens->buffers.elements[j].length,
                        kiov[i].data.data);
        i++;

        kiov[i].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        gssBufferToKrbData(&tokens->buffers.elements[j], &kiov[i].data);
        i++;
    }

    kiov[i].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    if (verifyMIC) {
        gssBufferToKrbData(tokenMIC, &kiov[i].data);
    } else {
        size_t checksumSize;

        code = krb5_c_checksum_length(krbContext, ctx->checksumType,
                                      &checksumSize);
        if (code != 0)
            goto cleanup;

        kiov[i].data.data = GSSEAP_MALLOC(checksumSize);
        if (kiov[i].data.data == NULL) {
            code = ENOMEM;
            goto cleanup;
        }
        kiov[i].data.length = checksumSize;
        checksumIndex = i;
    }
    i++;
    GSSEAP_ASSERT(i == kiovCount);

#ifdef HAVE_HEIMDAL_VERSION
    cksumType = ctx->checksumType;

    if (verifyMIC) {
        code = krb5_verify_checksum_iov(krbContext, krbCrypto, usage,
                                        kiov, i, &cksumType);
    } else {
        code = krb5_create_checksum_iov(krbContext, krbCrypto, usage,
                                        kiov, i, &cksumType);
    }
#else
    if (verifyMIC) {
        krb5_boolean kvalid = FALSE;

        code = krb5_c_verify_checksum_iov(krbContext, ctx->checksumType,
                                          &ctx->rfc3961Key,
                                          usage, kiov, i, &kvalid);
        if (code == 0 && !kvalid) {
            code = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        }
    } else {
        code = krb5_c_make_checksum_iov(krbContext, ctx->checksumType,
                                        &ctx->rfc3961Key,
                                        usage, kiov, i);
    }
#endif /* HAVE_HEIMDAL_VERSION */

    if (code == 0 && !verifyMIC) {
        krbDataToGssBuffer(&kiov[checksumIndex].data, tokenMIC);
        checksumIndex = -1;
    }

cleanup:
    if (checksumIndex != -1)
        GSSEAP_FREE(kiov[checksumIndex].data.data);
    if (kiov != NULL)
        GSSEAP_FREE(kiov);
    if (innerTokTypes != NULL)
        GSSEAP_FREE(innerTokTypes);
    if (innerTokLengths != NULL)
        GSSEAP_FREE(innerTokLengths);
#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
#endif

    *minor = code;

    switch (code) {
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
        major = GSS_S_BAD_SIG;
        break;
    case 0:
        major = GSS_S_COMPLETE;
        break;
    default:
        major = GSS_S_FAILURE;
        break;
    }

    return major;
}

OM_uint32
gssEapMakeTokenMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   gss_buffer_t tokenMIC)
{
    tokenMIC->length = 0;
    tokenMIC->value = NULL;

    return gssEapMakeOrVerifyTokenMIC(minor, ctx, tokenMIC, FALSE);
}

OM_uint32
gssEapVerifyTokenMIC(OM_uint32 *minor,
                     gss_ctx_id_t ctx,
                     const gss_buffer_t tokenMIC)
{
    return gssEapMakeOrVerifyTokenMIC(minor, ctx, tokenMIC, TRUE);
}
