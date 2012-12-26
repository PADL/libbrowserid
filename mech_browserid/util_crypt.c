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
 * Copyright 2001, 2008 by the Massachusetts Institute of Technology.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Message protection services: cryptography helpers.
 */

#include "gssapiP_bid.h"

/*
 * DCE_STYLE indicates actual RRC is EC + RRC
 * EC is extra rotate count for DCE_STYLE, pad length otherwise
 * RRC is rotate count.
 */
static krb5_error_code
mapIov(krb5_context context, int dce_style, size_t ec, size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
       krb5_crypto crypto,
#else
       krb5_keyblock *crypto,
#endif
       gss_iov_buffer_desc *iov,
       int iov_count, krb5_crypto_iov **pkiov,
       size_t *pkiov_count)
{
    gss_iov_buffer_t header;
    gss_iov_buffer_t trailer;
    int i = 0, j;
    size_t kiov_count;
    krb5_crypto_iov *kiov;
    size_t k5_headerlen = 0, k5_trailerlen = 0;
    size_t gss_headerlen, gss_trailerlen;
    krb5_error_code code;

    *pkiov = NULL;
    *pkiov_count = 0;

    header = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_HEADER);
    GSSBID_ASSERT(header != NULL);

    trailer = gssBidLocateIov(iov, iov_count, GSS_IOV_BUFFER_TYPE_TRAILER);
    GSSBID_ASSERT(trailer == NULL || rrc == 0);

    code = krbCryptoLength(context, crypto, KRB5_CRYPTO_TYPE_HEADER, &k5_headerlen);
    if (code != 0)
        return code;

    code = krbCryptoLength(context, crypto, KRB5_CRYPTO_TYPE_TRAILER, &k5_trailerlen);
    if (code != 0)
        return code;

    /* Check header and trailer sizes */
    gss_headerlen = 16 /* GSS-Header */ + k5_headerlen; /* Kerb-Header */
    gss_trailerlen = ec + 16 /* E(GSS-Header) */ + k5_trailerlen; /* Kerb-Trailer */

    /* If we're caller without a trailer, we must rotate by trailer length */
    if (trailer == NULL) {
        size_t actual_rrc = rrc;

        if (dce_style)
            actual_rrc += ec; /* compensate for Windows bug */

        if (actual_rrc != gss_trailerlen)
            return KRB5_BAD_MSIZE;

        gss_headerlen += gss_trailerlen;
        gss_trailerlen = 0;
    } else {
        if (trailer->buffer.length != gss_trailerlen)
            return KRB5_BAD_MSIZE;
    }

    if (header->buffer.length != gss_headerlen)
        return KRB5_BAD_MSIZE;

    kiov_count = 3 + iov_count;
    kiov = (krb5_crypto_iov *)GSSBID_MALLOC(kiov_count * sizeof(krb5_crypto_iov));
    if (kiov == NULL)
        return ENOMEM;

    /*
     * The krb5 header is located at the end of the GSS header.
     */
    kiov[i].flags = KRB5_CRYPTO_TYPE_HEADER;
    kiov[i].data.length = k5_headerlen;
    kiov[i].data.data = (char *)header->buffer.value + header->buffer.length - k5_headerlen;
    i++;

    for (j = 0; j < iov_count; j++) {
        kiov[i].flags = gssBidMapCryptoFlag(iov[j].type);
        if (kiov[i].flags == KRB5_CRYPTO_TYPE_EMPTY)
            continue;

        kiov[i].data.length = iov[j].buffer.length;
        kiov[i].data.data = (char *)iov[j].buffer.value;
        i++;
    }

    /*
     * The EC and encrypted GSS header are placed in the trailer, which may
     * be rotated directly after the plaintext header if no trailer buffer
     * is provided.
     */
    kiov[i].flags = KRB5_CRYPTO_TYPE_DATA;
    kiov[i].data.length = ec + 16; /* E(Header) */
    if (trailer == NULL)
        kiov[i].data.data = (char *)header->buffer.value + 16;
    else
        kiov[i].data.data = (char *)trailer->buffer.value;
    i++;

    /*
     * The krb5 trailer is placed after the encrypted copy of the
     * krb5 header (which may be in the GSS header or trailer).
     */
    kiov[i].flags = KRB5_CRYPTO_TYPE_TRAILER;
    kiov[i].data.length = k5_trailerlen;
    kiov[i].data.data = (char *)kiov[i - 1].data.data + ec + 16; /* E(Header) */
    i++;

    *pkiov = kiov;
    *pkiov_count = i;

    return 0;
}

int
gssBidEncrypt(krb5_context context,
              int dce_style,
              size_t ec,
              size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
              krb5_crypto crypto,
#else
              krb5_keyblock *crypto,
#endif
              int usage,
              gss_iov_buffer_desc *iov,
              int iov_count)
{
    krb5_error_code code;
    size_t kiov_count;
    krb5_crypto_iov *kiov = NULL;

    code = mapIov(context, dce_style, ec, rrc, crypto,
                  iov, iov_count, &kiov, &kiov_count);
    if (code != 0)
        goto cleanup;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_encrypt_iov_ivec(context, crypto, usage, kiov, kiov_count, NULL);
#else
    code = krb5_c_encrypt_iov(context, crypto, usage, NULL, kiov, kiov_count);
#endif
    if (code != 0)
        goto cleanup;

cleanup:
    if (kiov != NULL)
        GSSBID_FREE(kiov);

    return code;
}

int
gssBidDecrypt(krb5_context context,
              int dce_style,
              size_t ec,
              size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
              krb5_crypto crypto,
#else
              krb5_keyblock *crypto,
#endif
              int usage,
              gss_iov_buffer_desc *iov,
              int iov_count)
{
    krb5_error_code code;
    size_t kiov_count;
    krb5_crypto_iov *kiov;

    code = mapIov(context, dce_style, ec, rrc, crypto,
                  iov, iov_count, &kiov, &kiov_count);
    if (code != 0)
        goto cleanup;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_decrypt_iov_ivec(context, crypto, usage, kiov, kiov_count, NULL);
#else
    code = krb5_c_decrypt_iov(context, crypto, usage, NULL, kiov, kiov_count);
#endif

cleanup:
    if (kiov != NULL)
        GSSBID_FREE(kiov);

    return code;
}

int
gssBidMapCryptoFlag(OM_uint32 type)
{
    int ktype;

    switch (GSS_IOV_BUFFER_TYPE(type)) {
    case GSS_IOV_BUFFER_TYPE_DATA:
    case GSS_IOV_BUFFER_TYPE_PADDING:
        ktype = KRB5_CRYPTO_TYPE_DATA;
        break;
    case GSS_IOV_BUFFER_TYPE_SIGN_ONLY:
        ktype = KRB5_CRYPTO_TYPE_SIGN_ONLY;
        break;
    default:
        ktype = KRB5_CRYPTO_TYPE_EMPTY;
        break;
    }

    return ktype;
}

gss_iov_buffer_t
gssBidLocateIov(gss_iov_buffer_desc *iov, int iov_count, OM_uint32 type)
{
    int i;
    gss_iov_buffer_t p = GSS_C_NO_IOV_BUFFER;

    if (iov == GSS_C_NO_IOV_BUFFER)
        return GSS_C_NO_IOV_BUFFER;

    for (i = iov_count - 1; i >= 0; i--) {
        if (GSS_IOV_BUFFER_TYPE(iov[i].type) == type) {
            if (p == GSS_C_NO_IOV_BUFFER)
                p = &iov[i];
            else
                return GSS_C_NO_IOV_BUFFER;
        }
    }

    return p;
}

void
gssBidIovMessageLength(gss_iov_buffer_desc *iov,
                       int iov_count,
                       size_t *data_length_p,
                       size_t *assoc_data_length_p)
{
    int i;
    size_t data_length = 0, assoc_data_length = 0;

    GSSBID_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    *data_length_p = *assoc_data_length_p = 0;

    for (i = 0; i < iov_count; i++) {
        OM_uint32 type = GSS_IOV_BUFFER_TYPE(iov[i].type);

        if (type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            assoc_data_length += iov[i].buffer.length;

        if (type == GSS_IOV_BUFFER_TYPE_DATA ||
            type == GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
            data_length += iov[i].buffer.length;
    }

    *data_length_p = data_length;
    *assoc_data_length_p = assoc_data_length;
}

void
gssBidReleaseIov(gss_iov_buffer_desc *iov, int iov_count)
{
    int i;
    OM_uint32 min_stat;

    GSSBID_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    for (i = 0; i < iov_count; i++) {
        if (iov[i].type & GSS_IOV_BUFFER_FLAG_ALLOCATED) {
            gss_release_buffer(&min_stat, &iov[i].buffer);
            iov[i].type &= ~(GSS_IOV_BUFFER_FLAG_ALLOCATED);
        }
    }
}

int
gssBidIsIntegrityOnly(gss_iov_buffer_desc *iov, int iov_count)
{
    int i;
    krb5_boolean has_conf_data = FALSE;

    GSSBID_ASSERT(iov != GSS_C_NO_IOV_BUFFER);

    for (i = 0; i < iov_count; i++) {
        if (GSS_IOV_BUFFER_TYPE(iov[i].type) == GSS_IOV_BUFFER_TYPE_DATA) {
            has_conf_data = TRUE;
            break;
        }
    }

    return (has_conf_data == FALSE);
}

int
gssBidAllocIov(gss_iov_buffer_t iov, size_t size)
{
    GSSBID_ASSERT(iov != GSS_C_NO_IOV_BUFFER);
    GSSBID_ASSERT(iov->type & GSS_IOV_BUFFER_FLAG_ALLOCATE);

    iov->buffer.length = size;
    iov->buffer.value = GSSBID_MALLOC(size);
    if (iov->buffer.value == NULL) {
        iov->buffer.length = 0;
        return ENOMEM;
    }

    iov->type |= GSS_IOV_BUFFER_FLAG_ALLOCATED;

    return 0;
}
