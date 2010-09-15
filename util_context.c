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

OM_uint32
gssEapAllocContext(OM_uint32 *minor,
                   gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx;

    assert(*pCtx == GSS_C_NO_CONTEXT);

    ctx = (gss_ctx_id_t)GSSEAP_CALLOC(1, sizeof(*ctx));
    if (ctx == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&ctx->mutex) != 0) {
        *minor = errno;
        gssEapReleaseContext(&tmpMinor, &ctx);
        return GSS_S_FAILURE;
    }

    ctx->state = EAP_STATE_AUTHENTICATE;

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

static void
releaseAcceptorContext(struct gss_eap_acceptor_ctx *ctx)
{
#ifdef BUILTIN_EAP
    eap_server_sm_deinit(ctx->eap);
    if (ctx->tlsContext != NULL)
        tls_deinit(ctx->tlsContext);
#endif
}

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

    if (CTX_IS_INITIATOR(ctx)) {
        releaseInitiatorContext(&ctx->initiatorCtx);
    } else {
        releaseAcceptorContext(&ctx->acceptorCtx);
    }

    krb5_free_keyblock_contents(krbContext, &ctx->rfc3961Key);
    gssEapReleaseName(&tmpMinor, &ctx->initiatorName);
    gssEapReleaseName(&tmpMinor, &ctx->acceptorName);
    gss_release_oid(&tmpMinor, &ctx->mechanismUsed);
    sequenceFree(&tmpMinor, &ctx->seqState);

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
                  enum gss_eap_token_type tokenType,
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
                              inputToken->length, tokenType);
    if (GSS_ERROR(major))
        return GSS_S_DEFECTIVE_TOKEN;

    if (ctx->mechanismUsed == GSS_C_NO_OID) {
        if (!gssEapIsConcreteMechanismOid(oid))
            return GSS_S_BAD_MECH;

        if (!gssEapInternalizeOid(oid, &ctx->mechanismUsed)) {
            major = duplicateOid(minor, oid, &ctx->mechanismUsed);
            if (GSS_ERROR(major))
                return major;
        }
    }

    innerInputToken->length = bodySize;
    innerInputToken->value = p;

    *minor = 0;
    return GSS_S_COMPLETE;
}
