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
gssEapExportLucidSecContext(OM_uint32 *minor,
                            gss_ctx_id_t ctx,
                            const gss_OID desiredObject,
                            gss_buffer_set_t *data_set)
{
    gss_krb5_lucid_context_v1_t *lctx;
    gss_krb5_lucid_key_t *lkey = NULL;
    OM_uint32 major;
    gss_buffer_desc rep;

    lctx = (gss_krb5_lucid_context_v1_t *)GSSEAP_CALLOC(1, sizeof(*lctx));
    if (lctx == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    lctx->version = 1;
    lctx->initiate = CTX_IS_INITIATOR(ctx);
    lctx->endtime = ctx->expiryTime;
    lctx->send_seq = ctx->sendSeq;
    lctx->recv_seq = ctx->recvSeq;
    lctx->protocol = 1;

    lctx->cfx_kd.have_acceptor_subkey =
        ((rfc4121Flags(ctx, 0) & TOK_FLAG_ACCEPTOR_SUBKEY) != 0);

    lkey = lctx->cfx_kd.have_acceptor_subkey
           ? &lctx->cfx_kd.ctx_key
           : &lctx->cfx_kd.acceptor_subkey;

    lkey->type = KRB_KEY_TYPE(&ctx->rfc3961Key);
    lkey->data = GSSEAP_MALLOC(KRB_KEY_LENGTH(&ctx->rfc3961Key));
    if (lkey->data == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }
    lkey->length = KRB_KEY_LENGTH(&ctx->rfc3961Key);
    memcpy(lkey->data, KRB_KEY_DATA(&ctx->rfc3961Key), lkey->length);

    rep.value = &lctx;
    rep.length = sizeof(void *);

    major = gss_add_buffer_set_member(minor, &rep, data_set);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    if (GSS_ERROR(major)) {
        if (lctx != NULL) {
            if (lkey != NULL && lkey->data != NULL) {
                memset(lkey->data, 0, lkey->length);
                GSSEAP_FREE(lkey->data);
            }
            GSSEAP_FREE(lctx);
        }
    }

    return major;
}
