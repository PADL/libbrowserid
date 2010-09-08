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

static GSSEAP_THREAD_ONCE krbContextKeyOnce = GSSEAP_ONCE_INITIALIZER;
static GSSEAP_THREAD_KEY krbContextKey;

static void
destroyKrbContext(void *arg)
{
    krb5_context context = (krb5_context)arg;

    if (context != NULL)
        krb5_free_context(context);
}

static void
createKrbContextKey(void)
{
    GSSEAP_KEY_CREATE(&krbContextKey, destroyKrbContext);
}

OM_uint32
gssEapKerberosInit(OM_uint32 *minor, krb5_context *context)
{
    *minor = 0;

    GSSEAP_ONCE(&krbContextKeyOnce, createKrbContextKey);

    *context = GSSEAP_GETSPECIFIC(krbContextKey);
    if (*context == NULL) {
        *minor = krb5_init_context(context);
        if (*minor == 0) {
            if (GSSEAP_SETSPECIFIC(krbContextKey, *context) != 0) {
                *minor = errno;
                krb5_free_context(*context);
                *context = NULL;
            }
        }
    }

    return *minor == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

/*
 * Derive a key for RFC 4121 use by using the following
 * derivation function:
 *
 *    random-to-key(prf(random-to-key([e]msk), "rfc4121-gss-eap"))
 *
 * where random-to-key and prf are defined in RFC 3961.
 */
OM_uint32
gssEapDeriveRFC3961Key(OM_uint32 *minor,
                       gss_buffer_t msk,
                       krb5_enctype enctype,
                       krb5_keyblock *pKey)
{
    krb5_context context;
    krb5_data data, prf;
    krb5_keyblock kd;
    krb5_error_code code;
    size_t keybytes, keylength, prflength;

    memset(pKey, 0, sizeof(*pKey));

    GSSEAP_KRB_INIT(&context);

    kd.contents = NULL;
    kd.length = 0;
    KRB_KEYTYPE(&kd) = enctype;

    prf.data = NULL;
    prf.length = 0;

    code = krb5_c_keylengths(context, enctype, &keybytes, &keylength);
    if (code != 0)
        goto cleanup;

    data.length = msk->length;
    data.data = (char *)msk->value;

    kd.contents = GSSEAP_MALLOC(keylength);
    if (kd.contents == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    kd.length = keylength;

    /* Convert MSK into a Kerberos key */
    code = krb5_c_random_to_key(context, enctype, &data, &kd);
    if (code != 0)
        goto cleanup;

    data.length = sizeof("rfc4121-gss-eap") - 1;
    data.data = "rfc4121-gss-eap";

    /* Plug derivation constant and key into PRF */
    code = krb5_c_prf_length(context, enctype, &prflength);
    if (code != 0)
        goto cleanup;

    prf.length = prflength;
    prf.data = GSSEAP_MALLOC(prflength);
    if (data.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    code = krb5_c_prf(context, &kd, &data, &prf);
    if (code != 0)
        goto cleanup;

    /* Finally, convert PRF output into a new key which we will return */
    code = krb5_c_random_to_key(context, enctype, &prf, &kd);
    if (code != 0)
        goto cleanup;

    *pKey = kd;
    kd.contents = NULL;

cleanup:
    if (kd.contents != NULL) {
        memset(kd.contents, 0, kd.length);
        GSSEAP_FREE(kd.contents);
    }
    if (prf.data != NULL) {
        memset(prf.data, 0, prf.length);
        GSSEAP_FREE(prf.data);
    }

    *minor = code;
    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}
