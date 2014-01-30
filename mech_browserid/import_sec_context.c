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
 * Deserialise a context handle.
 */

#include "gssapiP_bid.h"

#define UPDATE_REMAIN(n)    do {                \
        p += (n);                               \
        remain -= (n);                          \
    } while (0)

#define CHECK_REMAIN(n)     do {                \
        if (remain < (n)) {                     \
            *minor = GSSBID_TOK_TRUNC;          \
            return GSS_S_DEFECTIVE_TOKEN;       \
        }                                       \
    } while (0)

static OM_uint32
importKerberosKey(OM_uint32 *minor,
                  unsigned char **pBuf,
                  size_t *pRemain,
                  krb5_cksumtype *checksumType,
                  krb5_enctype *pEncryptionType,
                  krb5_keyblock *pKey)
{
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    OM_uint32 encryptionType;
    OM_uint32 length;
    krb5_context krbContext;
    krb5_keyblock key;
    krb5_error_code code;

    GSSBID_KRB_INIT(&krbContext);

    KRB_KEY_INIT(pKey);

    if (remain < 12) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    *checksumType  = load_uint32_be(&p[0]);
    encryptionType = load_uint32_be(&p[4]);
    length         = load_uint32_be(&p[8]);

    if ((length != 0) != (encryptionType != ENCTYPE_NULL)) {
        *minor = GSSBID_BAD_CONTEXT_TOKEN;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (remain - 12 < length) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (encryptionType != ENCTYPE_NULL) {
        KRB_KEY_INIT(&key);

        KRB_KEY_TYPE(&key)   = encryptionType;
        KRB_KEY_LENGTH(&key) = length;
        KRB_KEY_DATA(&key)   = &p[12];

        code = krb5_copy_keyblock_contents(krbContext, &key, pKey);
        if (code != 0) {
            *minor = code;
            return GSS_S_FAILURE;
        }
    }

    *pBuf    += 12 + length;
    *pRemain -= 12 + length;
    *pEncryptionType = encryptionType;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
importName(OM_uint32 *minor,
           gss_OID mech,
           unsigned char **pBuf,
           size_t *pRemain,
           gss_name_t *pName)
{
    OM_uint32 major, tmpMinor, flags;
    unsigned char *p = *pBuf;
    size_t remain = *pRemain;
    gss_buffer_desc tmp;

    if (remain < 4) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    tmp.length = load_uint32_be(p);
    if (tmp.length != 0) {
        if (remain - 4 < tmp.length) {
            *minor = GSSBID_TOK_TRUNC;
            return GSS_S_DEFECTIVE_TOKEN;
        }

        tmp.value = p + 4;

        flags = EXPORT_NAME_FLAG_COMPOSITE;
        if (mech == GSS_C_NO_OID)
            flags |= EXPORT_NAME_FLAG_OID;

        major = gssBidImportNameInternal(minor, &tmp, pName, flags);
        if (GSS_ERROR(major))
            return major;

        if ((flags & EXPORT_NAME_FLAG_OID) == 0) {
            major = gssBidCanonicalizeOid(minor, mech, 0, &(*pName)->mechanismUsed);
            if (GSS_ERROR(major)) {
                gssBidReleaseName(&tmpMinor, pName);
                return major;
            }
        }
    }

    *pBuf    += 4 + tmp.length;
    *pRemain -= 4 + tmp.length;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidImportContext(OM_uint32 *minor,
                    gss_buffer_t token,
                    gss_ctx_id_t ctx)
{
    OM_uint32 major;
    unsigned char *p = (unsigned char *)token->value;
    size_t remain = token->length;

    if (remain < 16) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    if (load_uint32_be(&p[0]) != BROWSERID_EXPORT_CONTEXT_V1) {
        *minor = GSSBID_BAD_CONTEXT_TOKEN;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    ctx->state      = load_uint32_be(&p[4]);
    ctx->flags      = load_uint32_be(&p[8]);
    ctx->gssFlags   = load_uint32_be(&p[12]);
    p      += 16;
    remain -= 16;

    /* Validate state */
    if (GSSBID_SM_STATE(ctx) < GSSBID_STATE_INITIAL ||
        GSSBID_SM_STATE(ctx) > GSSBID_STATE_ESTABLISHED)
        return GSS_S_DEFECTIVE_TOKEN;

    /* Only acceptor can export partial context tokens */
    if (CTX_IS_INITIATOR(ctx) && !CTX_IS_ESTABLISHED(ctx))
        return GSS_S_DEFECTIVE_TOKEN;

    major = gssBidImportMechanismOid(minor, &p, &remain, &ctx->mechanismUsed);
    if (GSS_ERROR(major))
        return major;

    major = importKerberosKey(minor, &p, &remain,
                              &ctx->checksumType,
                              &ctx->encryptionType,
                              &ctx->rfc3961Key);
    if (GSS_ERROR(major))
        return major;

    /* Initiator name OID matches the context mechanism, so it's not encoded */
    major = importName(minor, ctx->mechanismUsed, &p, &remain, &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    major = importName(minor, GSS_C_NO_OID, &p, &remain, &ctx->acceptorName);
    if (GSS_ERROR(major))
        return major;

    /* Check that, if context is established, names are valid */
    if (CTX_IS_ESTABLISHED(ctx) &&
        (CTX_IS_INITIATOR(ctx) ? ctx->acceptorName == GSS_C_NO_NAME
                               : ctx->initiatorName == GSS_C_NO_NAME)) {
        return GSS_S_DEFECTIVE_TOKEN;
    }

    if (remain < 24 + sequenceSize(ctx->seqState)) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }
    ctx->expiryTime = (time_t)load_uint64_be(&p[0]);
    ctx->sendSeq    = load_uint64_be(&p[8]);
    ctx->recvSeq    = load_uint64_be(&p[16]);
    p      += 24;
    remain -= 24;

    major = sequenceInternalize(minor, &ctx->seqState, &p, &remain);
    if (GSS_ERROR(major))
        return major;

    major = GSS_S_COMPLETE;
    *minor = 0;

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_import_sec_context(OM_uint32 *minor,
                       gss_buffer_t interprocess_token,
                       gss_ctx_id_t *context_handle)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;

    *context_handle = GSS_C_NO_CONTEXT;

    if (interprocess_token == GSS_C_NO_BUFFER ||
        interprocess_token->length == 0) {
        *minor = GSSBID_TOK_TRUNC;
        return GSS_S_DEFECTIVE_TOKEN;
    }

    major = gssBidAllocContext(minor, FALSE, GSS_C_NO_OID, &ctx); /* XXX isInitiator */
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssBidImportContext(minor, interprocess_token, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    *context_handle = ctx;

cleanup:
    if (GSS_ERROR(major))
        gssBidReleaseContext(&tmpMinor, &ctx);

    return major;
}
