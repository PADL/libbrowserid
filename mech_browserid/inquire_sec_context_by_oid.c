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
 * Return extended properties of a context handle.
 */

#include "gssapiP_bid.h"

static OM_uint32
addEnctypeOidToBufferSet(OM_uint32 *minor,
                         krb5_enctype encryptionType,
                         gss_buffer_set_t *dataSet)
{
    OM_uint32 major;
    unsigned char oidBuf[16];
    gss_OID_desc oid;
    gss_buffer_desc buf;

    oid.length = sizeof(oidBuf);
    oid.elements = oidBuf;

    major = composeOid(minor,
                       "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04",
                       10,
                       encryptionType,
                       &oid);
    if (GSS_ERROR(major))
        return major;

    buf.length = oid.length;
    buf.value = oid.elements;

    major = gss_add_buffer_set_member(minor, &buf, dataSet);

    return major;
}

static void
zeroAndReleaseBufferSet(gss_buffer_set_t *dataSet)
{
    OM_uint32 tmpMinor;
    gss_buffer_set_t set = *dataSet;
    size_t i;

    if (set == GSS_C_NO_BUFFER_SET)
        return;

    for (i = 0; i <set->count; i++)
        memset(set->elements[i].value, 0, set->elements[i].length);

    gss_release_buffer_set(&tmpMinor, dataSet);
}

static OM_uint32
inquireSessionKey(OM_uint32 *minor,
                  const gss_ctx_id_t ctx,
                  const gss_OID desired_object GSSBID_UNUSED,
                  gss_buffer_set_t *dataSet)
{
    OM_uint32 major;
    gss_buffer_desc buf;

    if (ctx->encryptionType == ENCTYPE_NULL) {
        major = GSS_S_UNAVAILABLE;
        *minor = GSSBID_KEY_UNAVAILABLE;
        goto cleanup;
    }

    buf.length = KRB_KEY_LENGTH(&ctx->rfc3961Key);
    buf.value = KRB_KEY_DATA(&ctx->rfc3961Key);

    major = gss_add_buffer_set_member(minor, &buf, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    major = addEnctypeOidToBufferSet(minor, ctx->encryptionType, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        zeroAndReleaseBufferSet(dataSet);

    return major;
}

static OM_uint32
inquireNegoExKey(OM_uint32 *minor,
                  const gss_ctx_id_t ctx,
                  const gss_OID desired_object,
                  gss_buffer_set_t *dataSet)
{
    OM_uint32 major, tmpMinor;
    int bInitiatorKey;
    gss_buffer_desc salt;
    gss_buffer_desc key = GSS_C_EMPTY_BUFFER;
    size_t keySize;

    bInitiatorKey = CTX_IS_INITIATOR(ctx);

    if (ctx->encryptionType == ENCTYPE_NULL) {
        major = GSS_S_UNAVAILABLE;
        *minor = GSSBID_KEY_UNAVAILABLE;
        goto cleanup;
    }

    /*
     * If the caller supplied the verify key OID, then we need the acceptor
     * key if we are the initiator, and vice versa.
     */
    if (desired_object->length == 11 &&
        memcmp(desired_object->elements,
               "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x07", 11) == 0)
        bInitiatorKey ^= 1;

    if (bInitiatorKey) {
        salt.length = NEGOEX_INITIATOR_SALT_LEN;
        salt.value  = NEGOEX_INITIATOR_SALT;
    } else {
        salt.length = NEGOEX_ACCEPTOR_SALT_LEN;
        salt.value  = NEGOEX_ACCEPTOR_SALT;
    }

    keySize = KRB_KEY_LENGTH(&ctx->rfc3961Key);

    key.value = GSSBID_MALLOC(keySize);
    if (key.value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    key.length = keySize;

    major = gssBidPseudoRandom(minor, ctx, GSS_C_PRF_KEY_FULL, &salt, &key);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_add_buffer_set_member(minor, &key, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    major = addEnctypeOidToBufferSet(minor, ctx->encryptionType, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (key.value != NULL) {
        memset(key.value, 0, key.length);
        gss_release_buffer(&tmpMinor, &key);
    }
    if (GSS_ERROR(major))
        zeroAndReleaseBufferSet(dataSet);

    return major;
}

static struct {
    gss_OID_desc oid;
    OM_uint32 (*inquire)(OM_uint32 *, const gss_ctx_id_t,
                         const gss_OID, gss_buffer_set_t *);
} inquireCtxOps[] = {
    {
        /* GSS_C_INQ_SSPI_SESSION_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05" },
        inquireSessionKey
    },
    {
        /* GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT + v1 */
        { 12, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x06\x01" },
        gssBidExportLucidSecContext
    },
    {
        /* GSS_C_INQ_NEGOEX_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x06" },
        inquireNegoExKey
    },
    {
        /* GSS_C_INQ_NEGOEX_VERIFY_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x07" },
        inquireNegoExKey
    },
};

OM_uint32 GSSAPI_CALLCONV
gss_inquire_sec_context_by_oid(OM_uint32 *minor,
                               const gss_ctx_id_t ctx,
                               const gss_OID desired_object,
                               gss_buffer_set_t *data_set)
{
    OM_uint32 major;
    int i;

    *data_set = GSS_C_NO_BUFFER_SET;

    GSSBID_MUTEX_LOCK(&ctx->mutex);

#if 0
    if (!CTX_IS_ESTABLISHED(ctx)) {
        *minor = GSSBID_CONTEXT_INCOMPLETE;
        major = GSS_S_NO_CONTEXT;
        goto cleanup;
    }
#endif

    major = GSS_S_UNAVAILABLE;
    *minor = GSSBID_BAD_CONTEXT_OPTION;

    for (i = 0; i < sizeof(inquireCtxOps) / sizeof(inquireCtxOps[0]); i++) {
        if (oidEqual(&inquireCtxOps[i].oid, desired_object)) {
            major = (*inquireCtxOps[i].inquire)(minor, ctx,
                                                 desired_object, data_set);
            break;
        }
    }

    GSSBID_MUTEX_UNLOCK(&ctx->mutex);

    return major;
}
