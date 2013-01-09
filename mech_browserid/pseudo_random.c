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
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 * PRF
 */

#include "gssapiP_bid.h"

OM_uint32
gssBidPseudoRandom(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int prf_key,
                   const gss_buffer_t prf_in,
                   gss_buffer_t prf_out)
{
    krb5_error_code code;
    int i;
    OM_uint32 tmpMinor;
    size_t prflen;
    krb5_data t, ns;
    unsigned char *p;
    krb5_context krbContext;
    ssize_t desired_output_len = prf_out->length;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
#endif

    *minor = 0;

    GSSBID_KRB_INIT(&krbContext);

    KRB_DATA_INIT(&t);
    KRB_DATA_INIT(&ns);

    if (prf_key != GSS_C_PRF_KEY_PARTIAL &&
        prf_key != GSS_C_PRF_KEY_FULL) {
        code = GSSBID_BAD_PRF_KEY;
        goto cleanup;
    }

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_prf_length(krbContext, ctx->encryptionType, &prflen);
#else
    code = krb5_c_prf_length(krbContext, ctx->encryptionType, &prflen);
#endif
    if (code != 0)
        goto cleanup;

    ns.length = 4 + prf_in->length;
    ns.data = GSSBID_MALLOC(ns.length);
    if (ns.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_crypto_init(krbContext, &ctx->rfc3961Key, 0, &krbCrypto);
    if (code != 0)
        goto cleanup;
#else
    t.length = prflen;
    t.data = GSSBID_MALLOC(t.length);
    if (t.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
#endif

    memcpy((unsigned char *)ns.data + 4, prf_in->value, prf_in->length);
    i = 0;
    p = (unsigned char *)prf_out->value;
    while (desired_output_len > 0) {
        store_uint32_be(i, ns.data);

#ifdef HAVE_HEIMDAL_VERSION
        code = krb5_crypto_prf(krbContext, krbCrypto, &ns, &t);
#else
        code = krb5_c_prf(krbContext, &ctx->rfc3961Key, &ns, &t);
#endif
        if (code != 0)
            goto cleanup;

        memcpy(p, t.data, MIN(t.length, desired_output_len));

        p += t.length;
        desired_output_len -= t.length;
        i++;
    }

cleanup:
    if (code != 0)
        gss_release_buffer(&tmpMinor, prf_out);
    if (ns.data != NULL) {
        memset(ns.data, 0, ns.length);
        GSSBID_FREE(ns.data);
    }
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto_destroy(krbContext, krbCrypto);
    krb5_data_free(&t);
#else
    if (t.data != NULL) {
        memset(t.data, 0, t.length);
        GSSBID_FREE(t.data);
    }
#endif

    *minor = code;

    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32 GSSAPI_CALLCONV
gss_pseudo_random(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  int prf_key,
                  const gss_buffer_t prf_in,
                  ssize_t desired_output_len,
                  gss_buffer_t prf_out)
{
    OM_uint32 major;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    prf_out->length = 0;
    prf_out->value = NULL;

    *minor = 0;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        major = GSS_S_NO_CONTEXT;
        *minor = GSSBID_CONTEXT_INCOMPLETE;
        goto cleanup;
    }

    prf_out->value = GSSBID_MALLOC(desired_output_len);
    if (prf_out->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    prf_out->length = desired_output_len;

    major = gssBidPseudoRandom(minor, ctx, prf_key,
                               prf_in, prf_out);

cleanup:
    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
