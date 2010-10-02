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

#include "gssapiP_eap.h"

OM_uint32
gss_pseudo_random(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  int prf_key,
                  const gss_buffer_t prf_in,
                  ssize_t desired_output_len,
                  gss_buffer_t prf_out)
{
    krb5_error_code code;
    int i;
    OM_uint32 tmpMinor;
    size_t prflen;
    krb5_data t, ns;
    unsigned char *p;
    krb5_context krbContext;

    prf_out->length = 0;
    prf_out->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_NO_CONTEXT;
    }

    *minor = 0;

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    if (!CTX_IS_ESTABLISHED(ctx)) {
        GSSEAP_MUTEX_UNLOCK(&ctx->mutex);
        return GSS_S_NO_CONTEXT;
    }

    GSSEAP_KRB_INIT(&krbContext);

    t.length = 0;
    t.data = NULL;

    ns.length = 0;
    ns.data = NULL;

    if (prf_key != GSS_C_PRF_KEY_PARTIAL &&
        prf_key != GSS_C_PRF_KEY_FULL) {
        code = EINVAL;
        goto cleanup;
    }

    prf_out->value = GSSEAP_MALLOC(desired_output_len);
    if (prf_out->value == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    prf_out->length = desired_output_len;

    code = krb5_c_prf_length(krbContext,
                             ctx->encryptionType,
                             &prflen);
    if (code != 0)
        goto cleanup;

    ns.length = 4 + prf_in->length;
    ns.data = GSSEAP_MALLOC(ns.length);
    if (ns.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    t.length = prflen;
    t.data = GSSEAP_MALLOC(t.length);
    if (t.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    memcpy(ns.data + 4, prf_in->value, prf_in->length);
    i = 0;
    p = (unsigned char *)prf_out->value;
    while (desired_output_len > 0) {
        store_uint32_be(i, ns.data);

        code = krb5_c_prf(krbContext, &ctx->rfc3961Key, &ns, &t);
        if (code != 0)
            goto cleanup;

        memcpy(p, t.data, MIN(t.length, desired_output_len));

        p += t.length;
        desired_output_len -= t.length;
        i++;
    }

cleanup:
    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    if (code != 0)
        gss_release_buffer(&tmpMinor, prf_out);
    krb5_free_data_contents(krbContext, &ns);
    krb5_free_data_contents(krbContext, &t);

    *minor = code;

    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}
