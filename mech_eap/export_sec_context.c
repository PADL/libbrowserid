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
 * Serialise a security context. On the acceptor, this may be partially
 * established.
 */

#include "gssapiP_eap.h"

#ifdef GSSEAP_ENABLE_ACCEPTOR
static OM_uint32
gssEapExportPartialContext(OM_uint32 *minor,
                           gss_ctx_id_t ctx,
                           gss_buffer_t token)
{
    OM_uint32 major, tmpMinor;
    size_t length, serverLen = 0;
    unsigned char *p;
    char serverBuf[MAXHOSTNAMELEN];
    if (ctx->acceptorCtx.radConn != NULL) {
        if (rs_conn_get_current_peer(ctx->acceptorCtx.radConn,
                                     serverBuf, sizeof(serverBuf)) != 0) {
#if 0
            return gssEapRadiusMapError(minor,
                                        rs_err_conn_pop(ctx->acceptorCtx.radConn));
#else
            serverBuf[0] = '\0'; /* not implemented yet */
#endif
        }
        serverLen = strlen(serverBuf);
    }
    length = 4 + serverLen + 4 + ctx->acceptorCtx.state.length;

    token->value = GSSEAP_MALLOC(length);
    if (token->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }
    token->length = length;

    p = (unsigned char *)token->value;

    store_uint32_be(serverLen, p);
    p += 4;
    if (serverLen != 0) {
        memcpy(p, serverBuf, serverLen);
        p += serverLen;
    }

    store_uint32_be(ctx->acceptorCtx.state.length, p);
    p += 4;
    if (ctx->acceptorCtx.state.length != 0) {
        memcpy(p, ctx->acceptorCtx.state.value,
               ctx->acceptorCtx.state.length);
        p += ctx->acceptorCtx.state.length;
    }

    GSSEAP_ASSERT(p == (unsigned char *)token->value + token->length);

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, token);

    return major;
}
#endif /* GSSEAP_ENABLE_ACCEPTOR */

OM_uint32
gssEapExportSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_buffer_t token)
{
    OM_uint32 major, tmpMinor;
    size_t length;
    gss_buffer_desc initiatorName = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc acceptorName = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc partialCtx = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc key;
    unsigned char *p;

    if ((CTX_IS_INITIATOR(ctx) && !CTX_IS_ESTABLISHED(ctx)) ||
        ctx->mechanismUsed == GSS_C_NO_OID) {
        *minor = GSSEAP_CONTEXT_INCOMPLETE;
        return GSS_S_NO_CONTEXT;
    }

    key.length = KRB_KEY_LENGTH(&ctx->rfc3961Key);
    key.value  = KRB_KEY_DATA(&ctx->rfc3961Key);

    /*
     * As a shortcut, we omit the mechanism OID of the initiator name because
     * we know it will match the context mechanism. The acceptor name mech OID
     * is always included.
     */
    if (ctx->initiatorName != GSS_C_NO_NAME) {
        major = gssEapExportNameInternal(minor, ctx->initiatorName,
                                         &initiatorName,
                                         EXPORT_NAME_FLAG_COMPOSITE);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (ctx->acceptorName != GSS_C_NO_NAME) {
        major = gssEapExportNameInternal(minor, ctx->acceptorName,
                                         &acceptorName,
                                         EXPORT_NAME_FLAG_OID | EXPORT_NAME_FLAG_COMPOSITE);
        if (GSS_ERROR(major))
            goto cleanup;
    }

#ifdef GSSEAP_ENABLE_ACCEPTOR
    /*
     * The partial context is only transmitted for unestablished acceptor
     * contexts.
     */
    if (!CTX_IS_INITIATOR(ctx) && !CTX_IS_ESTABLISHED(ctx) &&
        (ctx->flags & CTX_FLAG_KRB_REAUTH) == 0) {
        major = gssEapExportPartialContext(minor, ctx, &partialCtx);
        if (GSS_ERROR(major))
            goto cleanup;
    }
#endif

    length  = 16;                               /* version, state, flags, */
    length += 4 + ctx->mechanismUsed->length;   /* mechanismUsed */
    length += 12 + key.length;                  /* rfc3961Key.value */
    length += 4 + initiatorName.length;         /* initiatorName.value */
    length += 4 + acceptorName.length;          /* acceptorName.value */
    length += 24 + sequenceSize(ctx->seqState); /* seqState */

    if (partialCtx.value != NULL)
        length += 4 + partialCtx.length;        /* partialCtx.value */

#ifdef GSSEAP_SSP
    length += 4 + ctx->AccountName.MaximumLength; /* AccountName.value */
    length += 24;
#endif

    token->value = GSSEAP_MALLOC(length);
    if (token->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }
    token->length = length;

    p = (unsigned char *)token->value;

    store_uint32_be(EAP_EXPORT_CONTEXT_V1, &p[0]);        /* version */
    store_uint32_be(GSSEAP_SM_STATE(ctx),  &p[4]);
    store_uint32_be(ctx->flags,            &p[8]);
    store_uint32_be(ctx->gssFlags,         &p[12]);
    p = store_oid(ctx->mechanismUsed,      &p[16]);

    store_uint32_be(ctx->checksumType,     &p[0]);
    store_uint32_be(ctx->encryptionType,   &p[4]);
    p = store_buffer(&key,                 &p[8], FALSE);

    p = store_buffer(&initiatorName,       p, FALSE);
    p = store_buffer(&acceptorName,        p, FALSE);

    store_uint64_be(ctx->expiryTime,       &p[0]);
    store_uint64_be(ctx->sendSeq,          &p[8]);
    store_uint64_be(ctx->recvSeq,          &p[16]);
    p += 24;

    major = sequenceExternalize(minor, ctx->seqState, &p, &length);
    if (GSS_ERROR(major))
        goto cleanup;

    if (partialCtx.value != NULL)
        p = store_buffer(&partialCtx, p, FALSE);

#ifdef GSSEAP_SSP
    store_uint16_be(ctx->AccountName.Length,        &p[0]);
    store_uint16_be(ctx->AccountName.MaximumLength, &p[2]);
    memcpy(&p[4], ctx->AccountName.Buffer, ctx->AccountName.MaximumLength);
    p += 4 + ctx->AccountName.MaximumLength;

    store_uint32_be(ctx->LogonId.HighPart, &p[0]);
    store_uint32_be(ctx->LogonId.LowPart,  &p[4]);

    if (LsaSpFunctionTable != NULL && ctx->TokenHandle != NULL) {
        HANDLE Handle;

        if (LsaSpFunctionTable->DuplicateHandle(ctx->TokenHandle,
                                                &Handle) != STATUS_SUCCESS) {
            major = GSS_S_FAILURE;
            goto cleanup;
        }
        store_uint64_be((ULONG_PTR)Handle, &p[8]);
    } else {
        store_uint64_be(0UI64, &p[8]);
    }

    store_uint64_be(ctx->LsaHandle,        &p[16]);
    p += 24;
#endif /* GSSEAP_SSP */

    GSSEAP_ASSERT(p == (unsigned char *)token->value + token->length);

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        gss_release_buffer(&tmpMinor, token);
    gss_release_buffer(&tmpMinor, &initiatorName);
    gss_release_buffer(&tmpMinor, &acceptorName);
    gss_release_buffer(&tmpMinor, &partialCtx);

    return major;
}

#ifndef GSSEAP_SSP
OM_uint32 GSSAPI_CALLCONV
gss_export_sec_context(OM_uint32 *minor,
                       gss_ctx_id_t *context_handle,
                       gss_buffer_t interprocess_token)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = *context_handle;

    interprocess_token->length = 0;
    interprocess_token->value = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_NO_CONTEXT;
    }

    *minor = 0;

    GSSEAP_MUTEX_LOCK(&ctx->mutex);

    major = gssEapExportSecContext(minor, ctx, interprocess_token);
    if (GSS_ERROR(major)) {
        GSSEAP_MUTEX_UNLOCK(&ctx->mutex);
        return major;
    }

    *context_handle = GSS_C_NO_CONTEXT;

    GSSEAP_MUTEX_UNLOCK(&ctx->mutex);

    gssEapReleaseContext(&tmpMinor, &ctx);

    return GSS_S_COMPLETE;
}
#endif
