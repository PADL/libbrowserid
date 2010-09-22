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

#define INIT_IOV_DATA(_iov)     do { (_iov)->buffer.value = NULL;       \
        (_iov)->buffer.length = 0; }                                    \
    while (0)

OM_uint32
gssEapWrapIovLength(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count)
{
    gss_iov_buffer_t header, trailer, padding;
    size_t dataLength, assocDataLength;
    size_t gssHeaderLen, gssPadLen, gssTrailerLen;
    unsigned int krbHeaderLen = 0, krbTrailerLen = 0, krbPadLen = 0;
    krb5_error_code code;
    krb5_context krbContext;
    int dce_style;
    size_t ec;

    if (qop_req != GSS_C_QOP_DEFAULT)
        return GSS_S_FAILURE;

    if (!CTX_IS_ESTABLISHED(ctx))
        return GSS_S_NO_CONTEXT;

    GSSEAP_KRB_INIT(&krbContext);

    header = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    if (header == NULL) {
        *minor = EINVAL;
        return GSS_S_FAILURE;
    }
    INIT_IOV_DATA(header);

    trailer = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);
    if (trailer != NULL) {
        INIT_IOV_DATA(trailer);
    }

    dce_style = ((ctx->gssFlags & GSS_C_DCE_STYLE) != 0);

    /* For CFX, EC is used instead of padding, and is placed in header or trailer */
    padding = gssEapLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding != NULL) {
        INIT_IOV_DATA(padding);
    }

    gssEapIovMessageLength(iov, iov_count, &dataLength, &assocDataLength);

    if (conf_req_flag && gssEapIsIntegrityOnly(iov, iov_count))
        conf_req_flag = FALSE;

    gssHeaderLen = gssPadLen = gssTrailerLen = 0;

    code = krb5_c_crypto_length(krbContext, ctx->encryptionType,
                                conf_req_flag ?
                                KRB5_CRYPTO_TYPE_TRAILER : KRB5_CRYPTO_TYPE_CHECKSUM,
                                &krbTrailerLen);
    if (code != 0) {
        *minor = code;
        return GSS_S_FAILURE;
    }

    if (conf_req_flag) {
        code = krb5_c_crypto_length(krbContext, ctx->encryptionType,
                                    KRB5_CRYPTO_TYPE_HEADER, &krbHeaderLen);
        if (code != 0) {
            *minor = code;
            return GSS_S_FAILURE;
        }
    }

    gssHeaderLen = 16; /* Header */
    if (conf_req_flag) {
        gssHeaderLen += krbHeaderLen; /* Kerb-Header */
        gssTrailerLen = 16 /* E(Header) */ + krbTrailerLen; /* Kerb-Trailer */

        code = krb5_c_padding_length(krbContext, ctx->encryptionType,
                                     dataLength - assocDataLength + 16 /* E(Header) */,
                                     &krbPadLen);
        if (code != 0) {
            *minor = code;
            return GSS_S_FAILURE;
        }

        if (krbPadLen == 0 && dce_style) {
            /* Windows rejects AEAD tokens with non-zero EC */
            code = krb5_c_block_size(krbContext, ctx->encryptionType, &ec);
            if (code != 0) {
                *minor = code;
                return GSS_S_FAILURE;
            }
        } else
            ec = krbPadLen;

        gssTrailerLen += ec;
    } else {
        gssTrailerLen = krbTrailerLen; /* Kerb-Checksum */
    }

    dataLength += gssPadLen;

    if (trailer == NULL)
        gssHeaderLen += gssTrailerLen;
    else
        trailer->buffer.length = gssTrailerLen;

    assert(gssPadLen == 0 || padding != NULL);

    if (padding != NULL)
        padding->buffer.length = gssPadLen;

    header->buffer.length = gssHeaderLen;

    if (conf_state != NULL)
        *conf_state = conf_req_flag;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gss_wrap_iov_length(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count)
{
    return gssEapWrapIovLength(minor, ctx, conf_req_flag, qop_req,
                               conf_state, iov, iov_count);
}
