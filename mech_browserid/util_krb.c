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
 * Kerberos 5 helpers.
 */

#include "gssapiP_bid.h"

void
gssBidDestroyKrbContext(krb5_context context)
{
    if (context != NULL)
        krb5_free_context(context);
}

static krb5_error_code
initKrbContext(krb5_context *pKrbContext)
{
    krb5_context krbContext;
    krb5_error_code code;
    char *defaultRealm = NULL;

    *pKrbContext = NULL;

    code = krb5_init_context(&krbContext);
    if (code != 0)
        goto cleanup;

    krb5_appdefault_string(krbContext, "browserid_gss",
                           NULL, "default_realm", "", &defaultRealm);

    if (defaultRealm != NULL && defaultRealm[0] != '\0') {
        code = krb5_set_default_realm(krbContext, defaultRealm);
        if (code != 0)
            goto cleanup;
    }

    *pKrbContext = krbContext;

cleanup:
#ifdef HAVE_HEIMDAL_VERSION
    krb5_xfree(defaultRealm);
#else
    krb5_free_default_realm(krbContext, defaultRealm);
#endif

    if (code != 0 && krbContext != NULL)
        krb5_free_context(krbContext);

    return code;
}

OM_uint32
gssBidKerberosInit(OM_uint32 *minor, krb5_context *context)
{
    struct gss_bid_thread_local_data *tld;

    *minor = 0;
    *context = NULL;

    tld = gssBidGetThreadLocalData();
    if (tld != NULL) {
        if (tld->krbContext == NULL) {
            *minor = initKrbContext(&tld->krbContext);
            if (*minor != 0)
                tld->krbContext = NULL;
        }
        *context = tld->krbContext;
    } else {
        *minor = GSSBID_GET_LAST_ERROR();
    }

    GSSBID_ASSERT(*context != NULL || *minor != 0);

    return (*minor == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
gssBidRfc3961KeySize(OM_uint32 *minor,
                     krb5_enctype encryptionType,
                     size_t *keyLength)
{
    krb5_context krbContext;
    krb5_error_code code;
#ifndef HAVE_HEIMDAL_VERSION
    size_t randomLength;
#endif

    GSSBID_KRB_INIT(&krbContext);
    GSSBID_ASSERT(encryptionType != ENCTYPE_NULL);

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_enctype_keysize(krbContext, encryptionType, keyLength);
#else
    code = krb5_c_keylengths(krbContext, encryptionType,
                             &randomLength, keyLength);
#endif

    *minor = code;

    return (code == 0) ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

/*
 * Derive a key K for RFC 4121 use.
 *
 * The output must be freed by krb5_free_keyblock_contents(),
 * not GSSBID_FREE().
 */
OM_uint32
gssBidDeriveRfc3961Key(OM_uint32 *minor,
                       const unsigned char *inputKey,
                       size_t inputKeyLength,
                       krb5_enctype encryptionType,
                       krb5_keyblock *pKey)
{
    krb5_context krbContext;
#ifndef HAVE_HEIMDAL_VERSION
    krb5_data data;
#endif
    krb5_keyblock kd;
    krb5_error_code code;
    size_t randomLength, keyLength;

    GSSBID_KRB_INIT(&krbContext);
    GSSBID_ASSERT(encryptionType != ENCTYPE_NULL);

    KRB_KEY_INIT(pKey);
    KRB_KEY_INIT(&kd);
    KRB_KEY_TYPE(&kd) = encryptionType;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_enctype_keybits(krbContext, encryptionType, &randomLength);
    if (code != 0)
        goto cleanup;

    randomLength = (randomLength + 7) / 8; /* from mit_glue.c */

    code = krb5_enctype_keysize(krbContext, encryptionType, &keyLength);
    if (code != 0)
        goto cleanup;
#else
    code = krb5_c_keylengths(krbContext, encryptionType,
                             &randomLength, &keyLength);
    if (code != 0)
        goto cleanup;
#endif /* HAVE_HEIMDAL_VERSION */

    /* Convert BrowserID DH key into a Kerberos key */

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_random_to_key(krbContext, encryptionType, inputKey,
                              MIN(inputKeyLength, randomLength), &kd);
#else
    data.length = MIN(inputKeyLength, randomLength);
    data.data = (char *)inputKey;

    KRB_KEY_DATA(&kd) = KRB_MALLOC(keyLength);
    if (KRB_KEY_DATA(&kd) == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    KRB_KEY_LENGTH(&kd) = keyLength;

    code = krb5_c_random_to_key(krbContext, encryptionType, &data, &kd);
#endif /* HAVE_HEIMDAL_VERSION */
    if (code != 0)
        goto cleanup;

    *pKey = kd;

cleanup:
    if (code != 0)
        krb5_free_keyblock_contents(krbContext, &kd);

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
#if !defined(HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE) && !defined(HAVE_HEIMDAL_VERSION)
    krb5_data data;
    krb5_checksum cksum;
#endif
#ifdef HAVE_HEIMDAL_VERSION
    krb5_crypto krbCrypto = NULL;
#endif

    GSSBID_KRB_INIT(&krbContext);

#ifdef HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE
    *minor = krb5int_c_mandatory_cksumtype(krbContext, KRB_KEY_TYPE(key),
                                           cksumtype);
    if (*minor != 0)
        return GSS_S_FAILURE;
#elif defined(HAVE_HEIMDAL_VERSION)
    *minor = krb5_crypto_init(krbContext, key, 0, &krbCrypto);
    if (*minor != 0)
        return GSS_S_FAILURE;

    *minor = krb5_crypto_get_checksum_type(krbContext, krbCrypto, cksumtype);

    krb5_crypto_destroy(krbContext, krbCrypto);

    if (*minor != 0)
        return GSS_S_FAILURE;
#else
    KRB_DATA_INIT(&data);

    memset(&cksum, 0, sizeof(cksum));

    /*
     * This is a complete hack but it's the only way to work with
     * MIT Kerberos pre-1.9 without using private API, as it does
     * not support passing in zero as the checksum type.
     */
    *minor = krb5_c_make_checksum(krbContext, 0, key, 0, &data, &cksum);
    if (*minor != 0)
        return GSS_S_FAILURE;

    *cksumtype = KRB_CHECKSUM_TYPE(&cksum);

    krb5_free_checksum_contents(krbContext, &cksum);
#endif /* HAVE_KRB5INT_C_MANDATORY_CKSUMTYPE */

#ifdef HAVE_HEIMDAL_VERSION
    if (!krb5_checksum_is_keyed(krbContext, *cksumtype))
#else
    if (!krb5_c_is_keyed_cksum(*cksumtype))
#endif
    {
        *minor = (OM_uint32)KRB5KRB_AP_ERR_INAPP_CKSUM;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

krb5_error_code
krbCryptoLength(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                krb5_crypto krbCrypto,
#else
                krb5_keyblock *key,
#endif
                int type,
                size_t *length)
{
#ifdef HAVE_HEIMDAL_VERSION
    return krb5_crypto_length(krbContext, krbCrypto, type, length);
#else
    unsigned int len;
    krb5_error_code code;

    code = krb5_c_crypto_length(krbContext, KRB_KEY_TYPE(key), type, &len);
    if (code == 0)
        *length = (size_t)len;

    return code;
#endif
}

krb5_error_code
krbPaddingLength(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                 krb5_crypto krbCrypto,
#else
                 krb5_keyblock *key,
#endif
                 size_t dataLength,
                 size_t *padLength)
{
    krb5_error_code code;
#ifdef HAVE_HEIMDAL_VERSION
    size_t headerLength, paddingLength;

    code = krbCryptoLength(krbContext, krbCrypto,
                           KRB5_CRYPTO_TYPE_HEADER, &headerLength);
    if (code != 0)
        return code;

    dataLength += headerLength;

    code = krb5_crypto_length(krbContext, krbCrypto,
                              KRB5_CRYPTO_TYPE_PADDING, &paddingLength);
    if (code != 0)
        return code;

    if (paddingLength != 0 && (dataLength % paddingLength) != 0)
        *padLength = paddingLength - (dataLength % paddingLength);
    else
        *padLength = 0;

    return 0;
#else
    unsigned int pad;

    code = krb5_c_padding_length(krbContext, KRB_KEY_TYPE(key), dataLength, &pad);
    if (code == 0)
        *padLength = (size_t)pad;

    return code;
#endif /* HAVE_HEIMDAL_VERSION */
}

krb5_error_code
krbBlockSize(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                 krb5_crypto krbCrypto,
#else
                 krb5_keyblock *key,
#endif
                 size_t *blockSize)
{
#ifdef HAVE_HEIMDAL_VERSION
    return krb5_crypto_getblocksize(krbContext, krbCrypto, blockSize);
#else
    return krb5_c_block_size(krbContext, KRB_KEY_TYPE(key), blockSize);
#endif
}

krb5_error_code
krbEnctypeToString(
#ifdef HAVE_HEIMDAL_VERSION
                   krb5_context krbContext,
#else
                   krb5_context krbContext GSSBID_UNUSED,
#endif
                   krb5_enctype enctype,
                   const char *prefix,
                   gss_buffer_t string)
{
    krb5_error_code code;
#ifdef HAVE_HEIMDAL_VERSION
    char *enctypeBuf = NULL;
#else
    char enctypeBuf[128];
#endif
    size_t prefixLength, enctypeLength;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_enctype_to_string(krbContext, enctype, &enctypeBuf);
#else
    code = krb5_enctype_to_name(enctype, 0, enctypeBuf, sizeof(enctypeBuf));
#endif
    if (code != 0)
        return code;

    prefixLength = (prefix != NULL) ? strlen(prefix) : 0;
    enctypeLength = strlen(enctypeBuf);

    string->value = GSSBID_MALLOC(prefixLength + enctypeLength + 1);
    if (string->value == NULL) {
#ifdef HAVE_HEIMDAL_VERSION
        krb5_xfree(enctypeBuf);
#endif
        return ENOMEM;
    }

    if (prefixLength != 0)
        memcpy(string->value, prefix, prefixLength);
    memcpy((char *)string->value + prefixLength, enctypeBuf, enctypeLength);

    string->length = prefixLength + enctypeLength;
    ((char *)string->value)[string->length] = '\0';

#ifdef HAVE_HEIMDAL_VERSION
    krb5_xfree(enctypeBuf);
#endif

    return 0;
}
