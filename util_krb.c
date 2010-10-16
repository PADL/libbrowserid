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
 * Kerberos 5 helpers.
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
 * Derive a key K for RFC 4121 use by using the following
 * derivation function (based on RFC 4402);
 *
 * KMSK = random-to-key(MSK)
 * Tn = pseudo-random(KMSK, n || "rfc4121-gss-eap")
 * L = output key size
 * K = truncate(L, T1 || T2 || .. || Tn)
 */
OM_uint32
gssEapDeriveRfc3961Key(OM_uint32 *minor,
                       const unsigned char *inputKey,
                       size_t inputKeyLength,
                       krb5_enctype encryptionType,
                       krb5_keyblock *pKey)
{
    krb5_context krbContext;
    krb5_data data, ns, t, prfOut;
    krb5_keyblock kd;
    krb5_error_code code;
    size_t randomLength, keyLength, prfLength;
    unsigned char constant[4 + sizeof("rfc4121-gss-eap") - 1], *p;
    ssize_t i, remain;

    assert(encryptionType != ENCTYPE_NULL);

    memset(pKey, 0, sizeof(*pKey));

    GSSEAP_KRB_INIT(&krbContext);

    KRB_KEY_INIT(&kd);
    KRB_KEY_TYPE(&kd) = encryptionType;

    t.data = NULL;
    t.length = 0;

    prfOut.data = NULL;
    prfOut.length = 0;

    code = krb5_c_keylengths(krbContext, encryptionType,
                             &randomLength, &keyLength);
    if (code != 0)
        goto cleanup;

    data.length = MIN(inputKeyLength, randomLength);
    data.data = (char *)inputKey;

    KRB_KEY_DATA(&kd) = GSSEAP_MALLOC(keyLength);
    if (KRB_KEY_DATA(&kd) == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    KRB_KEY_LENGTH(&kd) = keyLength;

    /* Convert MSK into a Kerberos key */
    code = krb5_c_random_to_key(krbContext, encryptionType, &data, &kd);
    if (code != 0)
        goto cleanup;

    memset(&constant[0], 0, 4);
    memcpy(&constant[4], "rfc4121-gss-eap", sizeof("rfc4121-gss-eap") - 1);

    ns.length = sizeof(constant);
    ns.data = (char *)constant;

    /* Plug derivation constant and key into PRF */
    code = krb5_c_prf_length(krbContext, encryptionType, &prfLength);
    if (code != 0)
        goto cleanup;

    t.length = prfLength;
    t.data = GSSEAP_MALLOC(t.length);
    if (t.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    prfOut.length = randomLength;
    prfOut.data = GSSEAP_MALLOC(prfOut.length);
    if (prfOut.data == NULL) {
        code = ENOMEM;
        goto cleanup;
    }

    for (i = 0, p = (unsigned char *)prfOut.data, remain = randomLength;
         remain > 0;
         p += t.length, remain -= t.length, i++)
    {
        store_uint32_be(i, ns.data);

        code = krb5_c_prf(krbContext, &kd, &ns, &t);
        if (code != 0)
            goto cleanup;

        memcpy(p, t.data, MIN(t.length, remain));
     }

    /* Finally, convert PRF output into a new key which we will return */
    code = krb5_c_random_to_key(krbContext, encryptionType, &prfOut, &kd);
    if (code != 0)
        goto cleanup;

    *pKey = kd;
    KRB_KEY_DATA(&kd) = NULL;

cleanup:
    if (KRB_KEY_DATA(&kd) != NULL) {
        memset(KRB_KEY_DATA(&kd), 0, KRB_KEY_LENGTH(&kd));
        GSSEAP_FREE(KRB_KEY_DATA(&kd));
    }
    if (t.data != NULL) {
        memset(t.data, 0, t.length);
        GSSEAP_FREE(t.data);
    }
    if (prfOut.data != NULL) {
        memset(prfOut.data, 0, prfOut.length);
        GSSEAP_FREE(prfOut.data);
    }
    *minor = code;
    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

#ifdef HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE
extern krb5_error_code
krb5int_c_mandatory_cksumtype(krb5_context, krb5_enctype, krb5_cksumtype *);
#endif

OM_uint32
rfc3961ChecksumTypeForKey(OM_uint32 *minor,
                          krb5_keyblock *key,
                          krb5_cksumtype *cksumtype)
{
    krb5_context krbContext;
#ifndef HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE
    krb5_data data;
    krb5_checksum cksum;
#endif

    GSSEAP_KRB_INIT(&krbContext);

#ifdef HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE
    *minor = krb5int_c_mandatory_cksumtype(krbContext, KRB_KEY_TYPE(key),
                                           cksumtype);
    if (*minor != 0)
        return GSS_S_FAILURE;
#else
    data.length = 0;
    data.data = NULL;

    memset(&cksum, 0, sizeof(cksum));

    /*
     * This is a complete hack but it's the only way to work with
     * MIT Kerberos pre-1.9 without using private API, as it does
     * not support passing in zero as the checksum type.
     */
    *minor = krb5_c_make_checksum(krbContext, 0, key, 0, &data, &cksum);
    if (*minor != 0)
        return GSS_S_FAILURE;

    *cksumtype = cksum.checksum_type;

    krb5_free_checksum_contents(krbContext, &cksum);
#endif /* HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE */

    return GSS_S_COMPLETE;
}
