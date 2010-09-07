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
 * lib/gssapi/krb5/k5sealv3iov.c
 *
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
 *
 *
 */

#include "gssapiP_eap.h"

OM_uint32
gssEapUnwrapOrVerifyMIC(OM_uint32 *minor_status,
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
    unsigned char acceptor_flag;
    unsigned char *ptr = NULL;
    int key_usage;
    size_t rrc, ec;
    size_t data_length, assoc_data_length;
    uint64_t seqnum;
    krb5_boolean valid;
    krb5_cksumtype cksumtype;
    int conf_flag = 0;

    *minor_status = 0;

    if (qop_state != NULL)
        *qop_state = GSS_C_QOP_DEFAULT;

    if (!CTX_IS_ESTABLISHED(ctx))
        return GSS_S_NO_CONTEXT;

    header = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    assert(header != NULL);

    padding = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding != NULL && padding->buffer.length != 0)
        return GSS_S_DEFECTIVE_TOKEN;

    trailer = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);

    acceptor_flag = CTX_IS_INITIATOR(ctx) ? TOK_FLAG_SENDER_IS_ACCEPTOR : 0;
    key_usage = (toktype == TOK_TYPE_WRAP
                 ? (!CTX_IS_INITIATOR(ctx)
                    ? KRB_USAGE_INITIATOR_SEAL
                    : KRB_USAGE_ACCEPTOR_SEAL)
                 : (!CTX_IS_INITIATOR(ctx)
                    ? KRB_USAGE_INITIATOR_SIGN
                    : KRB_USAGE_ACCEPTOR_SIGN));

    gssEapIovMessageLength(iov, iov_count, &data_length, &assoc_data_length);

    ptr = (unsigned char *)header->buffer.value;

    if (header->buffer.length < 16) {
        *minor_status = 0;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if ((ptr[2] & TOK_FLAG_SENDER_IS_ACCEPTOR) != acceptor_flag) {
        return GSS_S_BAD_SIG;
    }

    if (ptr[2] & TOK_FLAG_ACCEPTOR_SUBKEY) {
        return GSS_S_BAD_SIG;
    }

    if (toktype == TOK_TYPE_WRAP) {
        unsigned int k5_trailerlen;

        if (load_16_be(ptr) != TOK_TYPE_WRAP)
            goto defective;
        conf_flag = ((ptr[2] & TOK_FLAG_WRAP_CONFIDENTIAL) != 0);
        if (ptr[3] != 0xFF)
            goto defective;
        ec = load_16_be(ptr + 4);
        rrc = load_16_be(ptr + 6);
        seqnum = load_64_be(ptr + 8);

        code = krb5_c_crypto_length(ctx->kerberosCtx,
                                    KRB_KEYTYPE(ctx->encryptionKey),
                                    conf_flag ? KRB5_CRYPTO_TYPE_TRAILER :
                                    KRB5_CRYPTO_TYPE_CHECKSUM,
                                    &k5_trailerlen);
        if (code != 0) {
            *minor_status = code;
            return GSS_S_FAILURE;
        }

        /* Deal with RRC */
        if (trailer == NULL) {
            size_t desired_rrc = k5_trailerlen;

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
            code = gssEapDecrypt(ctx->kerberosCtx,
                                 ((ctx->gssFlags & GSS_C_DCE_STYLE) != 0),
                                 ec, rrc, ctx->encryptionKey,
                                 key_usage, 0, iov, iov_count);
            if (code != 0) {
                *minor_status = code;
                return GSS_S_BAD_SIG;
            }

            /* Validate header integrity */
            if (trailer == NULL)
                althdr = (unsigned char *)header->buffer.value + 16 + ec;
            else
                althdr = (unsigned char *)trailer->buffer.value + ec;

            if (load_16_be(althdr) != TOK_TYPE_WRAP
                || althdr[2] != ptr[2]
                || althdr[3] != ptr[3]
                || memcmp(althdr + 8, ptr + 8, 8) != 0) {
                *minor_status = 0;
                return GSS_S_BAD_SIG;
            }
        } else {
            /* Verify checksum: note EC is checksum size here, not padding */
            if (ec != k5_trailerlen)
                goto defective;

            /* Zero EC, RRC before computing checksum */
            store_16_be(0, ptr + 4);
            store_16_be(0, ptr + 6);

            code = gssEapVerify(ctx->kerberosCtx, cksumtype, rrc,
                                ctx->encryptionKey, key_usage,
                                iov, iov_count, &valid);
            if (code != 0 || valid == FALSE) {
                *minor_status = code;
                return GSS_S_BAD_SIG;
            }
        }

        code = g_order_check(&ctx->seqState, seqnum);
    } else if (toktype == TOK_TYPE_MIC) {
        if (load_16_be(ptr) != TOK_TYPE_MIC)
            goto defective;

    verify_mic_1:
        if (ptr[3] != 0xFF)
            goto defective;
        seqnum = load_64_be(ptr + 8);

        code = gssEapVerify(ctx->kerberosCtx, cksumtype, 0,
                            ctx->encryptionKey, key_usage,
                            iov, iov_count, &valid);
        if (code != 0 || valid == FALSE) {
            *minor_status = code;
            return GSS_S_BAD_SIG;
        }
        code = g_order_check(&ctx->seqState, seqnum);
    } else if (toktype == TOK_TYPE_DELETE) {
        if (load_16_be(ptr) != TOK_TYPE_DELETE)
            goto defective;
        goto verify_mic_1;
    } else {
        goto defective;
    }

    *minor_status = 0;

    if (conf_state != NULL)
        *conf_state = conf_flag;

    return code;

defective:
    *minor_status = 0;

    return GSS_S_DEFECTIVE_TOKEN;
}

OM_uint32
gss_unwrap_iov(OM_uint32 *minor,
               gss_ctx_id_t ctx,
               int *conf_state,
               gss_qop_t *qop_state,
               gss_iov_buffer_desc *iov,
               int iov_count)
{
    return gssEapUnwrapOrVerifyMIC(minor, ctx,
                                   iov, iov_count, conf_state,
                                   qop_state, TOK_TYPE_WRAP);

}
