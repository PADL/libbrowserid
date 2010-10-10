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

static OM_uint32
encodeExtensions(OM_uint32 *minor,
                 gss_buffer_set_t extensions,
                 OM_uint32 *types,
                 gss_buffer_t buffer);

static OM_uint32
decodeExtensions(OM_uint32 *minor,
                 const gss_buffer_t buffer,
                 gss_buffer_set_t *pExtensions,
                 OM_uint32 **pTypes);

/*
 * Initiator extensions
 */
static OM_uint32
makeGssChannelBindings(OM_uint32 *minor,
                       gss_cred_id_t cred,
                       gss_ctx_id_t ctx,
                       gss_channel_bindings_t chanBindings,
                       gss_buffer_t outputToken)
{
    OM_uint32 major;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS)
        buffer = chanBindings->application_data;

    major = gssEapWrap(minor, ctx, TRUE, GSS_C_QOP_DEFAULT,
                       &buffer, NULL, outputToken);
    if (GSS_ERROR(major))
        return major;

    return GSS_S_COMPLETE;
}

static OM_uint32
verifyGssChannelBindings(OM_uint32 *minor,
                         gss_cred_id_t cred,
                         gss_ctx_id_t ctx,
                         gss_channel_bindings_t chanBindings,
                         gss_buffer_t inputToken)
{
    OM_uint32 major, tmpMinor;
    gss_iov_buffer_desc iov[2];

    iov[0].type = GSS_IOV_BUFFER_TYPE_DATA | GSS_IOV_BUFFER_FLAG_ALLOCATE;
    iov[0].buffer.length = 0;
    iov[0].buffer.value = NULL;

    iov[1].type = GSS_IOV_BUFFER_TYPE_STREAM;
    iov[1].buffer = *inputToken;

    major = gssEapUnwrapOrVerifyMIC(minor, ctx, NULL, NULL,
                                    iov, 2, TOK_TYPE_WRAP);
    if (GSS_ERROR(major))
        return major;

    if (chanBindings != GSS_C_NO_CHANNEL_BINDINGS &&
        !bufferEqual(&iov[0].buffer, &chanBindings->application_data)) {
        major = GSS_S_BAD_BINDINGS;
    } else {
        major = GSS_S_COMPLETE;
    }

    gss_release_buffer(&tmpMinor, &iov[0].buffer);

    return major;
}

static struct gss_eap_extension_provider
eapGssInitExtensions[] = {
    {
        EXT_TYPE_GSS_CHANNEL_BINDINGS,
        1, /* critical */
        1, /* required */
        makeGssChannelBindings,
        verifyGssChannelBindings
    },
};

/*
 * Acceptor extensions
 */
static OM_uint32
makeReauthCreds(OM_uint32 *minor,
                gss_cred_id_t cred,
                gss_ctx_id_t ctx,
                gss_channel_bindings_t chanBindings,
                gss_buffer_t outputToken)
{
    OM_uint32 major = GSS_S_UNAVAILABLE;

#ifdef GSSEAP_ENABLE_REAUTH
    /*
     * If we're built with fast reauthentication enabled, then
     * fabricate a ticket from the initiator to ourselves.
     */
    major = gssEapMakeReauthCreds(minor, ctx, cred, outputToken);
#endif

    return major;
}

static OM_uint32
verifyReauthCreds(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_ctx_id_t ctx,
                  gss_channel_bindings_t chanBindings,
                  gss_buffer_t inputToken)
{
#ifdef GSSEAP_ENABLE_REAUTH
    return gssEapStoreReauthCreds(minor, ctx, cred, inputToken);
#else
    return GSS_S_UNAVAILABLE;
#endif
}

static struct gss_eap_extension_provider
eapGssAcceptExtensions[] = {
    {
        EXT_TYPE_REAUTH_CREDS,
        0, /* critical */
        0, /* required */
        makeReauthCreds,
        verifyReauthCreds
    },
};

OM_uint32
gssEapMakeExtensions(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t ctx,
                     gss_channel_bindings_t chanBindings,
                     gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    size_t i, j, nexts;
    gss_buffer_set_t extensions = GSS_C_NO_BUFFER_SET;
    OM_uint32 *types;
    const struct gss_eap_extension_provider *exts;

    if (CTX_IS_INITIATOR(ctx)) {
        exts = eapGssInitExtensions;
        nexts = sizeof(eapGssInitExtensions) / sizeof(eapGssInitExtensions[0]);
    } else {
        exts = eapGssAcceptExtensions;
        nexts = sizeof(eapGssAcceptExtensions) / sizeof(eapGssAcceptExtensions[0]);
    }

    assert(buffer != GSS_C_NO_BUFFER);

    buffer->length = 0;
    buffer->value = NULL;

    types = GSSEAP_CALLOC(nexts, sizeof(OM_uint32));
    if (types == NULL) {
        *minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    for (i = 0, j = 0; i < nexts; i++) {
        const struct gss_eap_extension_provider *ext = &exts[i];
        gss_buffer_desc extension = GSS_C_EMPTY_BUFFER;

        types[j] = ext->type;
        if (ext->critical)
            types[j] |= EXT_FLAG_CRITICAL;

        major = ext->make(minor, cred, ctx, chanBindings, &extension);
        if (GSS_ERROR(major)) {
            if (ext->critical)
                goto cleanup;
            else
                continue;
        }

        major = gss_add_buffer_set_member(minor, &extension, &extensions);
        if (GSS_ERROR(major))
            goto cleanup;

        j++;
    }

    assert(j == (extensions == GSS_C_NO_BUFFER_SET ? 0 : extensions->count));

    major = encodeExtensions(minor, extensions, types, buffer);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    gss_release_buffer_set(&tmpMinor, &extensions);
    if (types != NULL)
        GSSEAP_FREE(types);

    return major;
}

OM_uint32
gssEapVerifyExtensions(OM_uint32 *minor,
                       gss_cred_id_t cred,
                       gss_ctx_id_t ctx,
                       gss_channel_bindings_t chanBindings,
                       const gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_set_t extensions = GSS_C_NO_BUFFER_SET;
    OM_uint32 *types = NULL;
    size_t i, nexts;
    const struct gss_eap_extension_provider *exts;

    if (CTX_IS_INITIATOR(ctx)) {
        exts = eapGssAcceptExtensions;
        nexts = sizeof(eapGssAcceptExtensions) / sizeof(eapGssAcceptExtensions[0]);
    } else {
        exts = eapGssInitExtensions;
        nexts = sizeof(eapGssInitExtensions) / sizeof(eapGssInitExtensions[0]);
    }

    major = decodeExtensions(minor, buffer, &extensions, &types);
    if (GSS_ERROR(major))
        goto cleanup;

    for (i = 0; i < nexts; i++) {
        const struct gss_eap_extension_provider *ext = &exts[i];
        gss_buffer_t extension = GSS_C_NO_BUFFER;
        size_t j;

        for (j = 0; j < extensions->count; j++) {
            if ((types[j] & EXT_TYPE_MASK) == ext->type) {
                extension = &extensions->elements[j];
                break;
            }
        }

        if (extension != GSS_C_NO_BUFFER) {
            /* Process extension and mark as verified */
            major = ext->verify(minor, cred, ctx, chanBindings,
                                &extensions->elements[j]);
            if (GSS_ERROR(major))
                goto cleanup;

            types[j] |= EXT_FLAG_VERIFIED;
        } else if (ext->required) {
            /* Required extension missing */
            *minor = ENOENT;
            major = GSS_S_UNAVAILABLE;
            gssEapSaveStatusInfo(*minor,
                                 "Missing required GSS EAP extension %08x",
                                 ext->type);
            goto cleanup;
        }
    }

    /* Check we processed all critical extensions */
    for (i = 0; i < extensions->count; i++) {
        if ((types[i] & EXT_FLAG_CRITICAL) &&
            (types[i] & EXT_FLAG_VERIFIED) == 0) {
            *minor = ENOSYS;
            major = GSS_S_UNAVAILABLE;
            gssEapSaveStatusInfo(*minor,
                                 "Received unknown critical GSS EAP extension %08x",
                                 (types[i] & EXT_TYPE_MASK));
            goto cleanup;
        }
    }

    *minor = 0;
    major = GSS_S_COMPLETE;

cleanup:
    gss_release_buffer_set(&tmpMinor, &extensions);
    if (types != NULL)
        GSSEAP_FREE(types);

    return major;
}

static OM_uint32
encodeExtensions(OM_uint32 *minor,
                 gss_buffer_set_t extensions,
                 OM_uint32 *types,
                 gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    size_t required = 0, i;
    unsigned char *p;

    buffer->value = NULL;
    buffer->length = 0;

    if (extensions != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < extensions->count; i++) {
            required += 8 + extensions->elements[i].length;
        }
    }

    /*
     * We must always return a non-NULL token otherwise the calling state
     * machine assumes we are finished. Hence care in case malloc(0) does
     * return NULL.
     */
    buffer->value = GSSEAP_MALLOC(required ? required : 1);
    if (buffer->value == NULL) {
        *minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    buffer->length = required;
    p = (unsigned char *)buffer->value;

    if (extensions != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < extensions->count; i++) {
            gss_buffer_t extension = &extensions->elements[i];

            assert((types[i] & EXT_FLAG_VERIFIED) == 0); /* private flag */

             /*
              * Extensions are encoded as type-length-value, where the upper
              * bit of the type indicates criticality.
              */
            store_uint32_be(types[i], &p[0]);
            store_uint32_be(extension->length, &p[4]);
            memcpy(&p[8], extension->value, extension->length);

            p += 8 + extension->length;
        }
    }

    assert(p == (unsigned char *)buffer->value + required);
    assert(buffer->value != NULL);

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, buffer);
    }

    return major;
}

static OM_uint32
decodeExtensions(OM_uint32 *minor,
                 const gss_buffer_t buffer,
                 gss_buffer_set_t *pExtensions,
                 OM_uint32 **pTypes)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_set_t extensions = GSS_C_NO_BUFFER_SET;
    OM_uint32 *types = NULL;
    unsigned char *p;
    size_t remain;

    *pExtensions = GSS_C_NO_BUFFER_SET;
    *pTypes = NULL;

    major = gss_create_empty_buffer_set(minor, &extensions);
    if (GSS_ERROR(major))
        goto cleanup;

    if (buffer->length == 0) {
        major = GSS_S_COMPLETE;
        goto cleanup;
    }

    p = (unsigned char *)buffer->value;
    remain = buffer->length;

    do {
        OM_uint32 *ntypes;
        gss_buffer_desc extension;

        if (remain < 8) {
            major = GSS_S_DEFECTIVE_TOKEN;
            goto cleanup;
        }

        ntypes = GSSEAP_REALLOC(types,
                                (extensions->count + 1) * sizeof(OM_uint32));
        if (ntypes == NULL) {
            *minor = ENOMEM;
            major = GSS_S_FAILURE;
            goto cleanup;
        }
        types = ntypes;

        types[extensions->count] = load_uint32_be(&p[0]);
        extension.length = load_uint32_be(&p[4]);

        if (remain < 8 + extension.length) {
            major = GSS_S_DEFECTIVE_TOKEN;
            goto cleanup;
        }
        extension.value = &p[8];

        major = gss_add_buffer_set_member(minor, &extension, &extensions);
        if (GSS_ERROR(major))
            goto cleanup;

        p      += 8 + extension.length;
        remain -= 8 + extension.length;
    } while (remain != 0);

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_buffer_set(&tmpMinor, &extensions);
        if (types != NULL)
            GSSEAP_FREE(types);
    } else {
        *pExtensions = extensions;
        *pTypes = types;
    }

    return major;
}


