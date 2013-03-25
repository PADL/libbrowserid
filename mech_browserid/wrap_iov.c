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
 * Message protection services: wrap with scatter-gather API.
 */

#include "gssapiP_bid.h"

unsigned char
rfc4121Flags(gss_ctx_id_t ctx, int receiving)
{
    unsigned char flags;
    int isAcceptor;

    isAcceptor = !CTX_IS_INITIATOR(ctx);
    if (receiving)
        isAcceptor = !isAcceptor;

    flags = 0;
    if (isAcceptor)
        flags |= TOK_FLAG_SENDER_IS_ACCEPTOR;

#if 0
    if ((ctx->flags & CTX_FLAG_KRB_REAUTH) &&
        (ctx->gssFlags & GSS_C_MUTUAL_FLAG))
        flags |= TOK_FLAG_ACCEPTOR_SUBKEY;
#endif

    return flags;
}

OM_uint32
gssBidWrapOrGetMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int conf_req_flag,
                   int *conf_state,
                   gss_iov_buffer_desc *iov,
                   int iov_count,
                   enum gss_bid_token_type toktype)
{
    krb5_error_code code = 0;
    gss_iov_buffer_t header;
    gss_iov_buffer_t padding;
    gss_iov_buffer_t trailer;
    unsigned char flags;
    unsigned char *outbuf = NULL;
    unsigned char *tbuf = NULL;
    int keyUsage;
    size_t rrc = 0;
    size_t gssHeaderLen, gssTrailerLen;
    size_t dataLen, assocDataLen;
    krb5_context krbContext;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
#endif

    if (ctx->encryptionType == ENCTYPE_NULL) {
        *minor = GSSBID_KEY_UNAVAILABLE;
        return GSS_S_UNAVAILABLE;
    }

    GSSBID_KRB_INIT(&krbContext);

    flags = rfc4121Flags(ctx, FALSE);

    if (toktype == TOK_TYPE_WRAP) {
        keyUsage = CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SEAL
                   : KEY_USAGE_ACCEPTOR_SEAL;
    } else {
        keyUsage = CTX_IS_INITIATOR(ctx)
                   ? KEY_USAGE_INITIATOR_SIGN
                   : KEY_USAGE_ACCEPTOR_SIGN;
    }

    gssBidIovMessageLength(iov, iov_count, &dataLen, &assocDataLen);

    header = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    if (header == NULL) {
        *minor = GSSBID_MISSING_IOV;
        return GSS_S_FAILURE;
    }

    padding = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_PADDING);
    if (padding != NULL)
        padding->buffer.length = 0;

    trailer = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_init(krbContext, &ctx->rfc3961Key, ETYPE_NULL, &krbCrypto);
    if (code != 0)
        goto cleanup;
#endif

    if (toktype == TOK_TYPE_WRAP && conf_req_flag) {
        size_t krbHeaderLen, krbTrailerLen, krbPadLen;
        size_t ec = 0, confDataLen = dataLen - assocDataLen;
        int bHasAEAD;

        code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                               KRB5_CRYPTO_TYPE_HEADER, &krbHeaderLen);
        if (code != 0)
            goto cleanup;

        code = krbPaddingLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                                confDataLen + 16 /* E(Header) */,
                                &krbPadLen);
        if (code != 0)
            goto cleanup;

        /*
         * Windows' Kerberos SSP rejects AEAD tokens with non-zero EC;
         * let's be bug-for-bug compatible with that. We do an extra check
         * that AEAD is actually in use to guard against a corner case on
         * Windows where DCE_STYLE may be set for a non-DCE context.
         */
        bHasAEAD = (gssBidLocateIov(iov, iov_count,
                                    GSS_IOV_BUFFER_TYPE_SIGN_ONLY) != NULL);

        if (krbPadLen == 0 && (ctx->gssFlags & GSS_C_DCE_STYLE) && bHasAEAD) {
            code = krbBlockSize(krbContext, KRB_CRYPTO_CONTEXT(ctx), &ec);
            if (code != 0)
                goto cleanup;
        } else
            ec = krbPadLen;

        code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                               KRB5_CRYPTO_TYPE_TRAILER, &krbTrailerLen);
        if (code != 0)
            goto cleanup;

        gssHeaderLen = 16 /* Header */ + krbHeaderLen;
        gssTrailerLen = ec + 16 /* E(Header) */ + krbTrailerLen;

        if (trailer == NULL) {
            rrc = gssTrailerLen;
            /* Workaround for Windows bug where it rotates by EC + RRC */
            if (ctx->gssFlags & GSS_C_DCE_STYLE)
                rrc -= ec;
            gssHeaderLen += gssTrailerLen;
        }

        if (header->type & GSS_IOV_BUFFER_FLAG_ALLOCATE) {
            code = gssBidAllocIov(header, (size_t)gssHeaderLen);
        } else if (header->buffer.length < gssHeaderLen)
            code = GSSBID_WRONG_SIZE;
        if (code != 0)
            goto cleanup;
        outbuf = (unsigned char *)header->buffer.value;
        header->buffer.length = (size_t)gssHeaderLen;

        if (trailer != NULL) {
            if (trailer->type & GSS_IOV_BUFFER_FLAG_ALLOCATE)
                code = gssBidAllocIov(trailer, (size_t)gssTrailerLen);
            else if (trailer->buffer.length < gssTrailerLen)
                code = GSSBID_WRONG_SIZE;
            if (code != 0)
                goto cleanup;
            trailer->buffer.length = (size_t)gssTrailerLen;
        }

        /* TOK_ID */
        store_uint16_be((uint16_t)toktype, outbuf);
        /* flags */
        outbuf[2] = flags
                     | (conf_req_flag ? TOK_FLAG_WRAP_CONFIDENTIAL : 0);
        /* filler */
        outbuf[3] = 0xFF;
        /* EC */
        store_uint16_be(ec, outbuf + 4);
        /* RRC */
        store_uint16_be(0, outbuf + 6);
        store_uint64_be(ctx->sendSeq, outbuf + 8);

        /*
         * EC | copy of header to be encrypted, located in
         * (possibly rotated) trailer
         */
        if (trailer == NULL)
            tbuf = (unsigned char *)header->buffer.value + 16; /* Header */
        else
            tbuf = (unsigned char *)trailer->buffer.value;

        memset(tbuf, 0xFF, ec);
        memcpy(tbuf + ec, header->buffer.value, 16);

        code = gssBidEncrypt(krbContext,
                             ((ctx->gssFlags & GSS_C_DCE_STYLE) != 0),
                             ec, rrc, KRB_CRYPTO_CONTEXT(ctx),
                             keyUsage, iov, iov_count);
        if (code != 0)
            goto cleanup;

        /* RRC */
        store_uint16_be(rrc, outbuf + 6);

        ctx->sendSeq++;
    } else if (toktype == TOK_TYPE_WRAP && !conf_req_flag) {
    wrap_with_checksum:

        gssHeaderLen = 16;

        code = krbCryptoLength(krbContext, KRB_CRYPTO_CONTEXT(ctx),
                               KRB5_CRYPTO_TYPE_CHECKSUM, &gssTrailerLen);
        if (code != 0)
            goto cleanup;

        GSSBID_ASSERT(gssTrailerLen <= 0xFFFF);

        if (trailer == NULL) {
            rrc = gssTrailerLen;
            gssHeaderLen += gssTrailerLen;
        }

        if (header->type & GSS_IOV_BUFFER_FLAG_ALLOCATE)
            code = gssBidAllocIov(header, (size_t)gssHeaderLen);
        else if (header->buffer.length < gssHeaderLen)
            code = GSSBID_WRONG_SIZE;
        if (code != 0)
            goto cleanup;
        outbuf = (unsigned char *)header->buffer.value;
        header->buffer.length = (size_t)gssHeaderLen;

        if (trailer != NULL) {
            if (trailer->type & GSS_IOV_BUFFER_FLAG_ALLOCATE)
                code = gssBidAllocIov(trailer, (size_t)gssTrailerLen);
            else if (trailer->buffer.length < gssTrailerLen)
                code = GSSBID_WRONG_SIZE;
            if (code != 0)
                goto cleanup;
            trailer->buffer.length = (size_t)gssTrailerLen;
        }

        /* TOK_ID */
        store_uint16_be((uint16_t)toktype, outbuf);
        /* flags */
        outbuf[2] = flags;
        /* filler */
        outbuf[3] = 0xFF;
        if (toktype == TOK_TYPE_WRAP) {
            /* Use 0 for checksum calculation, substitute
             * checksum length later.
             */
            /* EC */
            store_uint16_be(0, outbuf + 4);
            /* RRC */
            store_uint16_be(0, outbuf + 6);
        } else {
            /* MIC and DEL store 0xFF in EC and RRC */
            store_uint16_be(0xFFFF, outbuf + 4);
            store_uint16_be(0xFFFF, outbuf + 6);
        }
        store_uint64_be(ctx->sendSeq, outbuf + 8);

        code = gssBidSign(krbContext, ctx->checksumType, rrc,
                          KRB_CRYPTO_CONTEXT(ctx), keyUsage,
                          iov, iov_count);
        if (code != 0)
            goto cleanup;

        ctx->sendSeq++;

        if (toktype == TOK_TYPE_WRAP) {
            /* Fix up EC field */
            store_uint16_be(gssTrailerLen, outbuf + 4);
            /* Fix up RRC field */
            store_uint16_be(rrc, outbuf + 6);
        }
    } else if (toktype == TOK_TYPE_MIC) {
        trailer = NULL;
        goto wrap_with_checksum;
    } else if (toktype == TOK_TYPE_DELETE_CONTEXT) {
        trailer = NULL;
        goto wrap_with_checksum;
    } else {
        abort();
    }

    code = 0;
    if (conf_state != NULL)
        *conf_state = conf_req_flag;

cleanup:
    if (code != 0)
        gssBidReleaseIov(iov, iov_count);
#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
#endif

    *minor = code;

    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32 GSSAPI_CALLCONV
gss_wrap_iov(OM_uint32 *minor,
             gss_ctx_id_t ctx,
             int conf_req_flag,
             gss_qop_t qop_req,
             int *conf_state,
             gss_iov_buffer_desc *iov,
             int iov_count)
{
    OM_uint32 major;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    if (qop_req != GSS_C_QOP_DEFAULT) {
        *minor = GSSBID_UNKNOWN_QOP;
        return GSS_S_UNAVAILABLE;
    }

    *minor = 0;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSBID_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    major = gssBidWrapOrGetMIC(minor, ctx, conf_req_flag, conf_state,
                               iov, iov_count, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
