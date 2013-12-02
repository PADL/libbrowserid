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
 * Copyright 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Message protection services: unwrap with scatter-gather API.
 */

#include "gssapiP_bid.h"

/*
 * Caller must provide TOKEN | DATA | PADDING | TRAILER, except
 * for DCE in which case it can just provide TOKEN | DATA (must
 * guarantee that DATA is padded)
 */
static OM_uint32
unwrapToken(OM_uint32 *minor,
            gss_ctx_id_t ctx,
#ifdef HAVE_HEIMDAL_VERSION
            krb5_crypto krbCrypto,
#else
            krb5_keyblock *unused GSSBID_UNUSED,
#endif
            int *conf_state,
            gss_qop_t *qop_state,
            gss_iov_buffer_desc *iov,
            int iov_count,
            enum gss_bid_token_type toktype)
{
    OM_uint32 major = GSS_S_FAILURE, code;
    gss_iov_buffer_t header;
    gss_iov_buffer_t padding;
    gss_iov_buffer_t trailer;
    unsigned char flags;
    unsigned char *ptr = NULL;
    int keyUsage;
    size_t rrc, ec;
    size_t dataLen, assocDataLen;
    uint64_t seqnum;
    int valid = 0;
    int conf_flag = 0;
    krb5_context krbContext;
#ifdef HAVE_HEIMDAL_VERSION
    int freeCrypto = (krbCrypto == NULL);
#endif

    GSSBID_KRB_INIT(&krbContext);

    *minor = 0;

    if (qop_state != NULL)
        *qop_state = GSS_C_QOP_DEFAULT;

    header = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    GSSBID_ASSERT(header != NULL);

    padding = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding != NULL && padding->buffer.length != 0) {
        code = GSSBID_BAD_PADDING_IOV;
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    trailer = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);

    flags = rfc4121Flags(ctx, TRUE);

    if (toktype == TOK_TYPE_WRAP) {
        keyUsage = !CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SEAL
                   : KEY_USAGE_ACCEPTOR_SEAL;
    } else {
        keyUsage = !CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SIGN
                   : KEY_USAGE_ACCEPTOR_SIGN;
    }

    gssBidIovMessageLength(iov, iov_count, &dataLen, &assocDataLen);

    ptr = (unsigned char *)header->buffer.value;

    if (header->buffer.length < 16) {
        code = GSSBID_TOK_TRUNC;
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    if ((ptr[2] & flags) != flags) {
        code = GSSBID_BAD_DIRECTION;
        major = GSS_S_BAD_SIG;
        goto cleanup;
    }

#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto == NULL) {
        code = krb5_crypto_init(krbContext, &ctx->rfc3961Key,
                                ETYPE_NULL, &krbCrypto);
        if (code != 0)
            goto cleanup;
    }
#endif

    if (toktype == TOK_TYPE_WRAP) {
        size_t krbTrailerLen;

        if (load_uint16_be(ptr) != TOK_TYPE_WRAP)
            goto defective;
        conf_flag = ((ptr[2] & TOK_FLAG_WRAP_CONFIDENTIAL) != 0);
        if (ptr[3] != 0xFF)
            goto defective;
        ec = load_uint16_be(ptr + 4);
        rrc = load_uint16_be(ptr + 6);
        seqnum = load_uint64_be(ptr + 8);

        code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                               conf_flag ? KRB5_CRYPTO_TYPE_TRAILER :
                                           KRB5_CRYPTO_TYPE_CHECKSUM,
                               &krbTrailerLen);
        if (code != 0)
            goto cleanup;

        /* Deal with RRC */
        if (trailer == NULL) {
            size_t desired_rrc = krbTrailerLen;

            if (conf_flag) {
                desired_rrc += 16; /* E(Header) */

                if ((ctx->gssFlags & GSS_C_DCE_STYLE) == 0)
                    desired_rrc += ec;
            }

            /* According to MS, we only need to deal with a fixed RRC for DCE */
            if (rrc != desired_rrc)
                goto defective;
        } else if (rrc != 0) {
            goto defective;
        }

        if (conf_flag) {
            unsigned char *althdr;

            /* Decrypt */
            code = gssBidDecrypt(krbContext,
                                 ((ctx->gssFlags & GSS_C_DCE_STYLE) != 0),
                                 ec, rrc, KRB_CRYPTO_CONTEXT(ctx), keyUsage,
                                 iov, iov_count);
            if (code != 0) {
                major = GSS_S_BAD_SIG;
                goto cleanup;
            }

            /* Validate header integrity */
            if (trailer == NULL)
                althdr = (unsigned char *)header->buffer.value + 16 + ec;
            else
                althdr = (unsigned char *)trailer->buffer.value + ec;

            if (load_uint16_be(althdr) != TOK_TYPE_WRAP
                || althdr[2] != ptr[2]
                || althdr[3] != ptr[3]
                || memcmp(althdr + 8, ptr + 8, 8) != 0) {
                code = GSSBID_BAD_WRAP_TOKEN;
                major = GSS_S_BAD_SIG;
                goto cleanup;
            }
        } else {
            /* Verify checksum: note EC is checksum size here, not padding */
            if (ec != krbTrailerLen)
                goto defective;

            /* Zero EC, RRC before computing checksum */
            store_uint16_be(0, ptr + 4);
            store_uint16_be(0, ptr + 6);

            code = gssBidVerify(krbContext, ctx->checksumType, rrc,
                                KRB_CRYPTO_CONTEXT(ctx), keyUsage,
                                iov, iov_count, &valid);
            if (code != 0 || valid == FALSE) {
                major = GSS_S_BAD_SIG;
                goto cleanup;
            }
        }

        major = sequenceCheck(&code, &ctx->seqState, seqnum);
        if (GSS_ERROR(major))
            goto cleanup;
    } else if (toktype == TOK_TYPE_MIC) {
        if (load_uint16_be(ptr) != toktype)
            goto defective;

    verify_mic_1:
        if (ptr[3] != 0xFF)
            goto defective;
        seqnum = load_uint64_be(ptr + 8);

        /*
         * Although MIC tokens don't have a RRC, they are similarly
         * composed of a header and a checksum. So the verify_mic()
         * can be implemented with a single header buffer, fake the
         * RRC to the putative trailer length if no trailer buffer.
         */
        code = gssBidVerify(krbContext, ctx->checksumType,
                            trailer != NULL ? 0 : header->buffer.length - 16,
                            KRB_CRYPTO_CONTEXT(ctx), keyUsage,
                            iov, iov_count, &valid);
        if (code != 0 || valid == FALSE) {
            major = GSS_S_BAD_SIG;
            goto cleanup;
        }
        major = sequenceCheck(minor, &ctx->seqState, seqnum);
        if (GSS_ERROR(major))
            goto cleanup;
    } else if (toktype == TOK_TYPE_DELETE_CONTEXT) {
        if (load_uint16_be(ptr) != TOK_TYPE_DELETE_CONTEXT)
            goto defective;
        goto verify_mic_1;
    } else {
        goto defective;
    }

    if (conf_state != NULL)
        *conf_state = conf_flag;

    code = 0;
    major = GSS_S_COMPLETE;
    goto cleanup;

defective:
    code = GSSBID_BAD_WRAP_TOKEN;
    major = GSS_S_DEFECTIVE_TOKEN;

cleanup:
    *minor = code;
#ifdef HAVE_HEIMDAL_VERSION
    if (freeCrypto && krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
#endif

    return major;
}

int
rotateLeft(void *ptr, size_t bufsiz, size_t rc)
{
    void *tbuf;

    if (bufsiz == 0)
        return 0;
    rc = rc % bufsiz;
    if (rc == 0)
        return 0;

    tbuf = GSSBID_MALLOC(rc);
    if (tbuf == NULL)
        return ENOMEM;

    memcpy(tbuf, ptr, rc);
    memmove(ptr, (char *)ptr + rc, bufsiz - rc);
    memcpy((char *)ptr + bufsiz - rc, tbuf, rc);
    GSSBID_FREE(tbuf);

    return 0;
}

/*
 * Split a STREAM | SIGN_DATA | DATA into
 *         HEADER | SIGN_DATA | DATA | PADDING | TRAILER
 */
static OM_uint32
unwrapStream(OM_uint32 *minor,
             gss_ctx_id_t ctx,
             int *conf_state,
             gss_qop_t *qop_state,
             gss_iov_buffer_desc *iov,
             int iov_count,
             enum gss_bid_token_type toktype)
{
    unsigned char *ptr;
    OM_uint32 code = 0, major = GSS_S_FAILURE;
    krb5_context krbContext;
    int conf_req_flag;
    int i = 0, j;
    gss_iov_buffer_desc *tiov = NULL;
    gss_iov_buffer_t stream, data = NULL;
    gss_iov_buffer_t theader, tdata = NULL, tpadding, ttrailer;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
#endif

    GSSBID_KRB_INIT(&krbContext);

    GSSBID_ASSERT(toktype == TOK_TYPE_WRAP);

    if (toktype != TOK_TYPE_WRAP) {
        code = GSSBID_WRONG_TOK_ID;
        goto cleanup;
    }

    stream = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_STREAM);
    GSSBID_ASSERT(stream != NULL);

    if (stream->buffer.length < 16) {
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    ptr = (unsigned char *)stream->buffer.value;
    ptr += 2; /* skip token type */

    tiov = (gss_iov_buffer_desc *)GSSBID_CALLOC((size_t)iov_count + 2,
                                                sizeof(gss_iov_buffer_desc));
    if (tiov == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    /* HEADER */
    theader = &tiov[i++];
    theader->type = GSS_IOV_BUFFER_TYPE_HEADER;
    theader->buffer.value = stream->buffer.value;
    theader->buffer.length = 16;

    /* n[SIGN_DATA] | DATA | m[SIGN_DATA] */
    for (j = 0; j < iov_count; j++) {
        OM_uint32 type = GSS_IOV_BUFFER_TYPE(iov[j].type);

        if (type == GSS_IOV_BUFFER_TYPE_DATA) {
            if (data != NULL) {
                /* only a single DATA buffer can appear */
                code = GSSBID_BAD_STREAM_IOV;
                goto cleanup;
            }

            data = &iov[j];
            tdata = &tiov[i];
        }
        if (type == GSS_IOV_BUFFER_TYPE_DATA ||
            type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            tiov[i++] = iov[j];
    }

    if (data == NULL) {
        /* a single DATA buffer must be present */
        code = GSSBID_BAD_STREAM_IOV;
        goto cleanup;
    }

    /* PADDING | TRAILER */
    tpadding = &tiov[i++];
    tpadding->type = GSS_IOV_BUFFER_TYPE_PADDING;
    tpadding->buffer.length = 0;
    tpadding->buffer.value = NULL;

    ttrailer = &tiov[i++];
    ttrailer->type = GSS_IOV_BUFFER_TYPE_TRAILER;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_init(krbContext, &ctx->rfc3961Key, ETYPE_NULL, &krbCrypto);
    if (code != 0)
        goto cleanup;
#endif

    {
        size_t ec, rrc;
        size_t krbHeaderLen = 0;
        size_t krbTrailerLen = 0;

        conf_req_flag = ((ptr[0] & TOK_FLAG_WRAP_CONFIDENTIAL) != 0);
        ec = conf_req_flag ? load_uint16_be(ptr + 2) : 0;
        rrc = load_uint16_be(ptr + 4);

        if (rrc != 0) {
            code = rotateLeft((unsigned char *)stream->buffer.value + 16,
                              stream->buffer.length - 16, rrc);
            if (code != 0)
                goto cleanup;
            store_uint16_be(0, ptr + 4); /* set RRC to zero */
        }

        if (conf_req_flag) {
            code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                                    KRB5_CRYPTO_TYPE_HEADER, &krbHeaderLen);
            if (code != 0)
                goto cleanup;
            theader->buffer.length += krbHeaderLen; /* length validated later */
        }

        /* no PADDING for CFX, EC is used instead */
        code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                               conf_req_flag
                                  ? KRB5_CRYPTO_TYPE_TRAILER
                                  : KRB5_CRYPTO_TYPE_CHECKSUM,
                               &krbTrailerLen);
        if (code != 0)
            goto cleanup;

        ttrailer->buffer.length = ec + (conf_req_flag ? 16 : 0 /* E(Header) */) +
                                  krbTrailerLen;
        ttrailer->buffer.value = (unsigned char *)stream->buffer.value +
            stream->buffer.length - ttrailer->buffer.length;
    }

    /* IOV: -----------0-------------+---1---+--2--+----------------3--------------*/
    /* CFX: GSS-Header | Kerb-Header | Data  |     | EC | E(Header) | Kerb-Trailer */
    /* GSS: -------GSS-HEADER--------+-DATA--+-PAD-+----------GSS-TRAILER----------*/

    /* validate lengths */
    if (stream->buffer.length < theader->buffer.length +
        tpadding->buffer.length +
        ttrailer->buffer.length) {
        major = GSS_S_DEFECTIVE_TOKEN;
        code = GSSBID_TOK_TRUNC;
        goto cleanup;
    }

    /* setup data */
    tdata->buffer.length = stream->buffer.length - ttrailer->buffer.length -
        tpadding->buffer.length - theader->buffer.length;

    GSSBID_ASSERT(data != NULL);

    if (data->type & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
        code = gssBidAllocIov(tdata, tdata->buffer.length);
        if (code != 0)
            goto cleanup;

        memcpy(tdata->buffer.value,
               (unsigned char *)stream->buffer.value + theader->buffer.length,
               tdata->buffer.length);
    } else {
        tdata->buffer.value = (unsigned char *)stream->buffer.value +
                              theader->buffer.length;
    }

    GSSBID_ASSERT(i <= iov_count + 2);

    major = unwrapToken(&code, ctx, KRB_CRYPTO_CONTEXT(ctx),
                        conf_state, qop_state, tiov, i, toktype);
    if (major == GSS_S_COMPLETE) {
        *data = *tdata;
    } else if (tdata->type & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
        OM_uint32 tmp;

        gss_release_buffer(&tmp, &tdata->buffer);
        tdata->type &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
    }

cleanup:
    if (tiov != NULL)
        GSSBID_FREE(tiov);
#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
#endif

    *minor = code;

    return major;
}

OM_uint32
gssBidUnwrapOrVerifyMIC(OM_uint32 *minor,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_bid_token_type toktype)
{
    OM_uint32 major;

    if (ctx->encryptionType == ENCTYPE_NULL) {
        *minor = GSSBID_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    if (gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_STREAM) != NULL) {
        major = unwrapStream(minor, ctx, conf_state, qop_state,
                             iov, iov_count, toktype);
    } else {
        major = unwrapToken(minor, ctx,
                            NULL, /* krbCrypto */
                            conf_state, qop_state,
                            iov, iov_count, toktype);
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_unwrap_iov(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               int *conf_state,
               gss_qop_t *qop_state,
               gss_iov_buffer_desc *iov,
               int iov_count)
{
    OM_uint32 major;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    *minor = 0;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSBID_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    major = gssBidUnwrapOrVerifyMIC(minor, ctx, conf_state, qop_state,
                                    iov, iov_count, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
