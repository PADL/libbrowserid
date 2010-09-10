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

#include "gssapiP_eap.h"

/*
 * Caller must provide TOKEN | DATA | PADDING | TRAILER, except
 * for DCE in which case it can just provide TOKEN | DATA (must
 * guarantee that DATA is padded)
 */
OM_uint32
unwrapToken(OM_uint32 *minor,
            gss_ctx_id_t ctx,
            int *conf_state,
            gss_qop_t *qop_state,
            gss_iov_buffer_desc *iov,
            int iov_count,
            enum gss_eap_token_type toktype)
{
    OM_uint32 code;
    gss_iov_buffer_t header;
    gss_iov_buffer_t padding;
    gss_iov_buffer_t trailer;
    unsigned char acceptorFlag;
    unsigned char *ptr = NULL;
    int keyUsage;
    size_t rrc, ec;
    size_t dataLen, assocDataLen;
    uint64_t seqnum;
    int valid = 0;
    int conf_flag = 0;
    krb5_context krbContext;

    GSSEAP_KRB_INIT(&krbContext);

    *minor = 0;

    if (qop_state != NULL)
        *qop_state = GSS_C_QOP_DEFAULT;

    header = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    assert(header != NULL);

    padding = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding != NULL && padding->buffer.length != 0)
        return GSS_S_DEFECTIVE_TOKEN;

    trailer = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);

    acceptorFlag = CTX_IS_INITIATOR(ctx) ? TOK_FLAG_SENDER_IS_ACCEPTOR : 0;
    switch (toktype) {
    case TOK_TYPE_WRAP:
        keyUsage = !CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SEAL
                   : KEY_USAGE_ACCEPTOR_SEAL;
        break;
    case TOK_TYPE_GSS_CB:
        keyUsage = KEY_USAGE_CHANNEL_BINDINGS;
        break;
    case TOK_TYPE_MIC:
    default:
        keyUsage = !CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SIGN
                   : KEY_USAGE_ACCEPTOR_SIGN;
        break;
    }

    gssEapIovMessageLength(iov, iov_count, &dataLen, &assocDataLen);

    ptr = (unsigned char *)header->buffer.value;

    if (header->buffer.length < 16) {
        *minor = 0;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if ((ptr[2] & TOK_FLAG_SENDER_IS_ACCEPTOR) != acceptorFlag) {
        return GSS_S_BAD_SIG;
    }

    if (ptr[2] & TOK_FLAG_ACCEPTOR_SUBKEY) {
        return GSS_S_BAD_SIG;
    }

    if (toktype == TOK_TYPE_WRAP) {
        unsigned int krbTrailerLen;

        if (load_uint16_be(ptr) != TOK_TYPE_WRAP)
            goto defective;
        conf_flag = ((ptr[2] & TOK_FLAG_WRAP_CONFIDENTIAL) != 0);
        if (ptr[3] != 0xFF)
            goto defective;
        ec = load_uint16_be(ptr + 4);
        rrc = load_uint16_be(ptr + 6);
        seqnum = load_uint64_be(ptr + 8);

        code = krb5_c_crypto_length(krbContext,
                                    ctx->encryptionType,
                                    conf_flag ? KRB5_CRYPTO_TYPE_TRAILER :
                                    KRB5_CRYPTO_TYPE_CHECKSUM,
                                    &krbTrailerLen);
        if (code != 0) {
            *minor = code;
            return GSS_S_FAILURE;
        }

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
            code = gssEapDecrypt(krbContext,
                                 ((ctx->gssFlags & GSS_C_DCE_STYLE) != 0),
                                 ec, rrc, &ctx->rfc3961Key,
                                 keyUsage, 0, iov, iov_count);
            if (code != 0) {
                *minor = code;
                return GSS_S_BAD_SIG;
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
                *minor = 0;
                return GSS_S_BAD_SIG;
            }
        } else {
            /* Verify checksum: note EC is checksum size here, not padding */
            if (ec != krbTrailerLen)
                goto defective;

            /* Zero EC, RRC before computing checksum */
            store_uint16_be(0, ptr + 4);
            store_uint16_be(0, ptr + 6);

            code = gssEapVerify(krbContext, ctx->checksumType, rrc,
                                &ctx->rfc3961Key, keyUsage,
                                iov, iov_count, &valid);
            if (code != 0 || valid == FALSE) {
                *minor = code;
                return GSS_S_BAD_SIG;
            }
        }

        code = sequenceCheck(&ctx->seqState, seqnum);
    } else if (toktype == TOK_TYPE_MIC || toktype == TOK_TYPE_GSS_CB) {
        if (load_uint16_be(ptr) != toktype)
            goto defective;

    verify_mic_1:
        if (ptr[3] != 0xFF)
            goto defective;
        seqnum = load_uint64_be(ptr + 8);

        code = gssEapVerify(krbContext, ctx->checksumType, 0,
                            &ctx->rfc3961Key, keyUsage,
                            iov, iov_count, &valid);
        if (code != 0 || valid == FALSE) {
            *minor = code;
            return GSS_S_BAD_SIG;
        }
        if (toktype != TOK_TYPE_GSS_CB)
            code = sequenceCheck(&ctx->seqState, seqnum);
    } else if (toktype == TOK_TYPE_DELETE_CONTEXT) {
        if (load_uint16_be(ptr) != TOK_TYPE_DELETE_CONTEXT)
            goto defective;
        goto verify_mic_1;
    } else {
        goto defective;
    }

    *minor = 0;

    if (conf_state != NULL)
        *conf_state = conf_flag;

    return code;

defective:
    *minor = 0;

    return GSS_S_DEFECTIVE_TOKEN;
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

    tbuf = GSSEAP_MALLOC(rc);
    if (tbuf == NULL)
        return ENOMEM;

    memcpy(tbuf, ptr, rc);
    memmove(ptr, (char *)ptr + rc, bufsiz - rc);
    memcpy((char *)ptr + bufsiz - rc, tbuf, rc);
    GSSEAP_FREE(tbuf);

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
             enum gss_eap_token_type toktype)
{
    unsigned char *ptr;
    OM_uint32 code = 0, major = GSS_S_FAILURE;
    krb5_context krbContext;
    int conf_req_flag, toktype2;
    int i = 0, j;
    gss_iov_buffer_desc *tiov = NULL;
    gss_iov_buffer_t stream, data = NULL;
    gss_iov_buffer_t theader, tdata = NULL, tpadding, ttrailer;

    GSSEAP_KRB_INIT(&krbContext);

    assert(toktype == TOK_TYPE_WRAP);

    if (toktype != TOK_TYPE_WRAP || (ctx->gssFlags & GSS_C_DCE_STYLE)) {
        code = EINVAL;
        goto cleanup;
    }

    stream = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_STREAM);
    assert(stream != NULL);

    if (stream->buffer.length < 16) {
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    ptr = (unsigned char *)stream->buffer.value;
    toktype2 = load_uint16_be(ptr);
    ptr += 2;

    tiov = (gss_iov_buffer_desc *)GSSEAP_CALLOC((size_t)iov_count + 2,
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
                code = EINVAL;
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
        code = EINVAL;
        goto cleanup;
    }

    /* PADDING | TRAILER */
    tpadding = &tiov[i++];
    tpadding->type = GSS_IOV_BUFFER_TYPE_PADDING;
    tpadding->buffer.length = 0;
    tpadding->buffer.value = NULL;

    ttrailer = &tiov[i++];
    ttrailer->type = GSS_IOV_BUFFER_TYPE_TRAILER;

    {
        size_t ec, rrc;
        unsigned int krbHeaderLen = 0;
        unsigned int krbTrailerLen = 0;

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
            code = krb5_c_crypto_length(krbContext, ctx->encryptionType,
                                        KRB5_CRYPTO_TYPE_HEADER, &krbHeaderLen);
            if (code != 0)
                goto cleanup;
            theader->buffer.length += krbHeaderLen; /* length validated later */
        }

        /* no PADDING for CFX, EC is used instead */
        code = krb5_c_crypto_length(krbContext, ctx->encryptionType,
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
    /* Old: GSS-Header | Conf        | Data  | Pad |                               */
    /* CFX: GSS-Header | Kerb-Header | Data  |     | EC | E(Header) | Kerb-Trailer */
    /* GSS: -------GSS-HEADER--------+-DATA--+-PAD-+----------GSS-TRAILER----------*/

    /* validate lengths */
    if (stream->buffer.length < theader->buffer.length +
        tpadding->buffer.length +
        ttrailer->buffer.length) {
        code = KRB5_BAD_MSIZE;
        major = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    /* setup data */
    tdata->buffer.length = stream->buffer.length - ttrailer->buffer.length -
        tpadding->buffer.length - theader->buffer.length;

    assert(data != NULL);

    if (data->type & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
        code = gssEapAllocIov(tdata, tdata->buffer.length);
        if (code != 0)
            goto cleanup;

        memcpy(tdata->buffer.value,
               (unsigned char *)stream->buffer.value + theader->buffer.length,
               tdata->buffer.length);
    } else {
        tdata->buffer.value = (unsigned char *)stream->buffer.value +
                              theader->buffer.length;
    }

    assert(i <= iov_count + 2);

    major = unwrapToken(&code, ctx, conf_state, qop_state,
                        tiov, i, toktype);
    if (major == GSS_S_COMPLETE) {
        *data = *tdata;
    } else if (tdata->type & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
        OM_uint32 tmp;

        gss_release_buffer(&tmp, &tdata->buffer);
        tdata->type &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
    }

cleanup:
    if (tiov != NULL)
        GSSEAP_FREE(tiov);

    *minor = code;

    return major;
}

OM_uint32
gssEapUnwrapOrVerifyMIC(OM_uint32 *minor,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_eap_token_type toktype)
{
    OM_uint32 major;

    if (!CTX_IS_ESTABLISHED(ctx))
        return GSS_S_NO_CONTEXT;

    if (ctx->encryptionType == ENCTYPE_NULL)
        return GSS_S_UNAVAILABLE;

    if (gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_STREAM) != NULL) {
        major = unwrapStream(minor, ctx, conf_state, qop_state,
                             iov, iov_count, toktype);
    } else {
        major = unwrapToken(minor, ctx, conf_state, qop_state,
                            iov, iov_count, toktype);
    }

    return major;
}

OM_uint32
gss_unwrap_iov(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               int *conf_state,
               gss_qop_t *qop_state,
               gss_iov_buffer_desc *iov,
               int iov_count)
{
    return gssEapUnwrapOrVerifyMIC(minor, ctx, conf_state, qop_state,
                                   iov, iov_count, TOK_TYPE_WRAP);
}
