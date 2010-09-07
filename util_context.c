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

    *minor = krb5_init_context(&ctx->kerberosCtx);
    if (*minor != 0) {
        gssEapReleaseContext(&tmpMinor, &ctx);
        return GSS_S_FAILURE;
    }

    *pCtx = ctx;

    return GSS_S_COMPLETE;
}

static void
releaseInitiatorContext(struct eap_gss_initiator_ctx *ctx)
{
    eap_peer_sm_deinit(ctx->eap);
    wpabuf_free(ctx->eapReqData);
}

static void
releaseAcceptorContext(struct eap_gss_acceptor_ctx *ctx)
{
}

OM_uint32
gssEapReleaseContext(OM_uint32 *minor,
                     gss_ctx_id_t *pCtx)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *pCtx;

    if (ctx == GSS_C_NO_CONTEXT) {
        return GSS_S_COMPLETE;
    }

    if (CTX_IS_INITIATOR(ctx)) {
        releaseInitiatorContext(&ctx->initiatorCtx);
    } else {
        releaseAcceptorContext(&ctx->acceptorCtx);
    }

    if (ctx->encryptionKey != NULL) {
        krb5_free_keyblock(ctx->kerberosCtx, ctx->encryptionKey);
    }

    if (ctx->kerberosCtx != NULL) {
        krb5_free_context(ctx->kerberosCtx);
    }

    gssEapReleaseName(&tmpMinor, &ctx->initiatorName);
    gssEapReleaseName(&tmpMinor, &ctx->acceptorName);

    memset(ctx, 0, sizeof(*ctx));
    GSSEAP_FREE(ctx);
    *pCtx = GSS_C_NO_CONTEXT;

    *minor = 0;
    return GSS_S_COMPLETE;
}
