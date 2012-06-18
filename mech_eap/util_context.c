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

#ifdef GSSEAP_SSP
    ctx->RefCount = 1;
#endif

    *pCtx = ctx;

    return GSS_S_COMPLETE;
}

static void
releaseInitiatorContext(struct gss_eap_initiator_ctx *ctx)
{
    OM_uint32 minor;

    eap_peer_sm_deinit(ctx->eap);
    gss_release_buffer(&minor, &ctx->serverSubject);
    gss_release_buffer(&minor, &ctx->serverHash);
    gss_release_buffer(&minor, &ctx->serverCert);
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

#ifdef GSSEAP_SSP
    if (InterlockedDecrement(&ctx->RefCount) > 0) {
        *pCtx = GSS_C_NO_CONTEXT;
        return GSS_S_COMPLETE;
    }
#endif

    gssEapKerberosInit(&tmpMinor, &krbContext);

#if defined(GSSEAP_ENABLE_REAUTH) && !defined(GSSEAP_SSP)
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

#ifdef GSSEAP_SSP
    if (ctx->TokenHandle != NULL)
        CloseHandle(ctx->TokenHandle);
    GsspFreeUnicodeString(&ctx->AccountName);
    if (ctx->ProfileBuffer != NULL)
        LsaFreeReturnBuffer(ctx->ProfileBuffer);
#endif

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
    gss_iov_buffer_desc *iov = NULL;
    size_t i = 0, j;
    enum gss_eap_token_type tokType;
    OM_uint32 micTokType;
    unsigned char wireTokType[2];
    unsigned char *innerTokTypes = NULL, *innerTokLengths = NULL;
    const struct gss_eap_token_buffer_set *tokens;

    tokens = verifyMIC ? ctx->inputTokens : ctx->outputTokens;

    GSSEAP_ASSERT(tokens != NULL);

    iov = GSSEAP_CALLOC(2 + (3 * tokens->buffers.count) + 1, sizeof(*iov));
    if (iov == NULL) {
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
    iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[i].buffer.length = ctx->mechanismUsed->length;
    iov[i].buffer.value = ctx->mechanismUsed->elements;
    i++;

    /* Token type */
    if (CTX_IS_INITIATOR(ctx) ^ verifyMIC) {
        tokType = TOK_TYPE_INITIATOR_CONTEXT;
        micTokType = ITOK_TYPE_INITIATOR_MIC;
    } else {
        tokType = TOK_TYPE_ACCEPTOR_CONTEXT;
        micTokType = ITOK_TYPE_ACCEPTOR_MIC;
    }
    store_uint16_be(tokType, wireTokType);

    iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[i].buffer.length = sizeof(wireTokType);
    iov[i].buffer.value = wireTokType;
    i++;

    for (j = 0; j < tokens->buffers.count; j++) {
        if (verifyMIC &&
            (tokens->types[j] & ITOK_TYPE_MASK) == micTokType)
            continue; /* will use this slot for trailer */

        iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
        iov[i].buffer.length = 4;
        iov[i].buffer.value = &innerTokTypes[j * 4];
        store_uint32_be(tokens->types[j] & ~(ITOK_FLAG_VERIFIED),
                        iov[i].buffer.value);
        i++;

        iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
        iov[i].buffer.length = 4;
        iov[i].buffer.value = &innerTokLengths[j * 4];
        store_uint32_be(tokens->buffers.elements[j].length,
                        iov[i].buffer.value);
        i++;

        iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
        iov[i].buffer = tokens->buffers.elements[j];
        i++;
    }

    if (verifyMIC) {
        GSSEAP_ASSERT(tokenMIC->length >= 16);

        GSSEAP_ASSERT(i < 2 + (3 * tokens->buffers.count));

        iov[i].type = GSS_IOV_BUFFER_TYPE_HEADER;
        iov[i].buffer = *tokenMIC;
        i++;

        major = gssEapUnwrapOrVerifyMIC(minor, ctx, NULL, NULL,
                                        iov, i, TOK_TYPE_MIC);
    } else {
        iov[i++].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
        major = gssEapWrapOrGetMIC(minor, ctx, FALSE, NULL,
                                   iov, i, TOK_TYPE_MIC);
        if (!GSS_ERROR(major))
            *tokenMIC = iov[i - 1].buffer;
    }

cleanup:
    if (iov != NULL)
        gssEapReleaseIov(iov, tokens->buffers.count);
    if (innerTokTypes != NULL)
        GSSEAP_FREE(innerTokTypes);
    if (innerTokLengths != NULL)
        GSSEAP_FREE(innerTokLengths);

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
    if (tokenMIC->length < 16) {
        *minor = GSSEAP_TOK_TRUNC;
        return GSS_S_BAD_SIG;
    }

    return gssEapMakeOrVerifyTokenMIC(minor, ctx, tokenMIC, TRUE);
}
