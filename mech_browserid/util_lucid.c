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
 * "Lucid" security context export routine (called by MIT Kerberos mechanism).
 */

#include "gssapiP_bid.h"

OM_uint32
gssBidExportLucidSecContext(OM_uint32 *minor,
                            gss_ctx_id_t ctx,
                            const gss_OID desiredObject GSSBID_UNUSED,
                            gss_buffer_set_t *data_set)
{
    OM_uint32 major = GSS_S_COMPLETE;
    int haveAcceptorSubkey =
        ((rfc4121Flags(ctx, 0) & TOK_FLAG_ACCEPTOR_SUBKEY) != 0);
    gss_buffer_desc rep;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_error_code code;
    krb5_storage *sp;
    krb5_data data = { 0 };

    sp = krb5_storage_emem();
    if (sp == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    code = krb5_store_int32(sp, 1);     /* version */
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, CTX_IS_INITIATOR(ctx));
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, ctx->expiryTime); 
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, 0);
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, ctx->sendSeq);
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, 0);
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, ctx->recvSeq);
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, 1);     /* is_cfx */
    if (code != 0)
        goto cleanup;

    code = krb5_store_int32(sp, haveAcceptorSubkey);
    if (code != 0)
        goto cleanup;

    code = krb5_store_keyblock(sp, ctx->rfc3961Key);
    if (code != 0)
        goto cleanup;

    if (haveAcceptorSubkey) {
        code = krb5_store_keyblock(sp, ctx->rfc3961Key);
        if (code != 0)
            goto cleanup;
    }

    code = krb5_storage_to_data(sp, &data);
    if (code != 0)
        goto cleanup;

    rep.length = data.length;
    rep.value = data.data;

    major = gss_add_buffer_set_member(minor, &rep, data_set);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    krb5_data_free(&data);

    if (major == GSS_S_COMPLETE) {
        *minor = code;
        major = (code != 0) ? GSS_S_FAILURE : GSS_S_COMPLETE;
    }

    return major;
#else
    gss_krb5_lucid_context_v1_t *lctx;
    gss_krb5_lucid_key_t *lkey = NULL;

    lctx = (gss_krb5_lucid_context_v1_t *)GSSBID_CALLOC(1, sizeof(*lctx));
    if (lctx == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    lctx->version = 1;
    lctx->initiate = CTX_IS_INITIATOR(ctx);
    if (ctx->expiryTime == 0)
        lctx->endtime = KRB_TIME_FOREVER;
    else
        lctx->endtime = ctx->expiryTime;
    lctx->send_seq = ctx->sendSeq;
    lctx->recv_seq = ctx->recvSeq;
    lctx->protocol = 1;

    lctx->cfx_kd.have_acceptor_subkey = haveAcceptorSubkey;

    lkey = haveAcceptorSubkey
           ? &lctx->cfx_kd.acceptor_subkey
           : &lctx->cfx_kd.ctx_key;

    lkey->type = KRB_KEY_TYPE(&ctx->rfc3961Key);
    lkey->data = GSSBID_MALLOC(KRB_KEY_LENGTH(&ctx->rfc3961Key));
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
                GSSBID_FREE(lkey->data);
            }
            GSSBID_FREE(lctx);
        }
    }

    return major;
#endif /* HAVE_HEIMDAL_VERSION */
}
