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
 * Utility routines for context handles.
 */

#include "gssapiP_bid.h"

/*
 * Set the re-authentication ticket and renewable lifetimes. By
 * default these match typical Kerberos defaults of 10 hours and
 * 7 days, respectively.
 *
 * XXX make this configurable.
 */
static OM_uint32
gssBidSetReauthPolicy(OM_uint32 *minor,
                      gss_ctx_id_t ctx)
{
    BIDError err;
    uint32_t ulTicketLifetime = 60 * 60 * 10;       /* 10 hours */
    uint32_t ulRenewLifetime = 60 * 60 * 24 * 7;    /* 7 days */

    err = BIDSetContextParam(ctx->bidContext, BID_PARAM_TICKET_LIFETIME,
                             &ulTicketLifetime);
    if (err != BID_S_OK)
        return gssBidMapError(minor, err);

    err = BIDSetContextParam(ctx->bidContext, BID_PARAM_RENEW_LIFETIME,
                             &ulRenewLifetime);
    if (err != BID_S_OK)
        return gssBidMapError(minor, err);

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidAllocContext(OM_uint32 *minor,
                   int isInitiator,
                   gss_const_OID mech,
                   gss_ctx_id_t *pCtx)
{
    OM_uint32 major, tmpMinor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    BIDError err;
    uint32_t contextParams;
    size_t cbKey = 0;

    GSSBID_ASSERT(*pCtx == GSS_C_NO_CONTEXT);

    ctx = (gss_ctx_id_t)GSSBID_CALLOC(1, sizeof(*ctx));
    if (ctx == GSS_C_NO_CONTEXT) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    if (GSSBID_MUTEX_INIT(&ctx->mutex) != 0) {
        major = GSS_S_FAILURE;
        *minor = GSSBID_GET_LAST_ERROR();
        goto cleanup;
    }

    if (isInitiator)
        ctx->flags |= CTX_FLAG_INITIATOR;
    ctx->state = GSSBID_STATE_INITIAL;

    if (mech != GSS_C_NO_OID) {
        major = gssBidCanonicalizeOid(minor,
                                      (gss_OID)mech,
                                      OID_FLAG_NULL_VALID | OID_FLAG_MAP_NULL_TO_DEFAULT_MECH,
                                      &ctx->mechanismUsed);
        if (GSS_ERROR(major))
            goto cleanup;

        /* Cache encryption type derived from selected mechanism OID */
        major = gssBidOidToEnctype(minor, ctx->mechanismUsed,
                                   &ctx->encryptionType);
        if (GSS_ERROR(major))
            goto cleanup;

        if (ctx->encryptionType != ENCTYPE_NULL) {
            major = gssBidRfc3961KeySize(minor, ctx->encryptionType, &cbKey);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

    contextParams = BID_CONTEXT_GSS | BID_CONTEXT_REAUTH;
    if (ctx->encryptionType != ENCTYPE_NULL)
        contextParams |= BID_CONTEXT_ECDH_KEYEX;
    if (isInitiator)
        contextParams |= BID_CONTEXT_USER_AGENT | BID_CONTEXT_BROWSER_SILENT | BID_CONTEXT_TICKET_CACHE;
    else
        contextParams |= BID_CONTEXT_RP | BID_CONTEXT_AUTHORITY_CACHE | BID_CONTEXT_REPLAY_CACHE;

    err = BIDAcquireContext(contextParams, &ctx->bidContext);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    if (ctx->encryptionType != ENCTYPE_NULL) {
        char *szCurve;

        if (cbKey >= 256)
            szCurve = BID_ECDH_CURVE_P521;
        else if (cbKey >= 192)
            szCurve = BID_ECDH_CURVE_P384;
        else
            szCurve = BID_ECDH_CURVE_P256;

        err = BIDSetContextParam(ctx->bidContext, BID_PARAM_ECDH_CURVE, szCurve);
        if (err != BID_S_OK) {
            major = gssBidMapError(minor, err);
            goto cleanup;
        }
    }

    /*
     * If we are doing mutual authentication, this is whether we store the
     * server certificate and private key.
     */
    BIDSetContextParam(ctx->bidContext, BID_PARAM_RP_CERT_CONFIG_NAME,
                       GSSBID_CONFIG_FILE);

    major = gssBidSetReauthPolicy(minor, ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    /*
     * Integrity, confidentiality, sequencing and replay detection are
     * always available.  Regardless of what flags are requested in
     * GSS_Init_sec_context, implementations MUST set the flag corresponding
     * to these services in the output of GSS_Init_sec_context and
     * GSS_Accept_sec_context.
    */
    ctx->gssFlags = GSS_C_TRANS_FLAG | GSS_C_REPLAY_FLAG;
    if (ctx->encryptionType != ENCTYPE_NULL) {
        ctx->gssFlags |= GSS_C_INTEG_FLAG    |   /* integrity */
                         GSS_C_CONF_FLAG     |   /* confidentiality */
                         GSS_C_SEQUENCE_FLAG;    /* sequencing */
    }

    major = GSS_S_COMPLETE;
    *minor = 0;
    *pCtx = ctx;

cleanup:
    if (GSS_ERROR(major))
        gssBidReleaseContext(&tmpMinor, &ctx);

    return major;
}

OM_uint32
gssBidReleaseContext(OM_uint32 *minor,
                     gss_ctx_id_t *pCtx)
{
    OM_uint32 tmpMinor;
    gss_ctx_id_t ctx = *pCtx;
    krb5_context krbContext = NULL;

    if (ctx == GSS_C_NO_CONTEXT) {
        return GSS_S_COMPLETE;
    }

    gssBidKerberosInit(&tmpMinor, &krbContext);

    if (ctx->bidContext != BID_C_NO_CONTEXT) {
        BIDReleaseIdentity(ctx->bidContext, ctx->bidIdentity);
        BIDReleaseContext(ctx->bidContext);
    }

    krb5_free_keyblock_contents(krbContext, &ctx->rfc3961Key);
    gssBidReleaseName(&tmpMinor, &ctx->initiatorName);
    gssBidReleaseName(&tmpMinor, &ctx->acceptorName);
    gssBidReleaseOid(&tmpMinor, &ctx->mechanismUsed);
    sequenceFree(&tmpMinor, &ctx->seqState);
    gssBidReleaseCred(&tmpMinor, &ctx->cred);

    gss_release_buffer(&tmpMinor, &ctx->initiatorCtx.serverSubject);
    gss_release_buffer(&tmpMinor, &ctx->initiatorCtx.serverHash);
    gss_release_buffer(&tmpMinor, &ctx->initiatorCtx.serverCert);

    GSSBID_MUTEX_DESTROY(&ctx->mutex);

    memset(ctx, 0, sizeof(*ctx));
    GSSBID_FREE(ctx);
    *pCtx = GSS_C_NO_CONTEXT;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidMakeToken(OM_uint32 *minor,
                gss_ctx_id_t ctx,
                const gss_buffer_t innerToken,
                enum gss_bid_token_type tokenType,
                int bOidWrapping,
                gss_buffer_t outputToken)
{
    unsigned char *p;
    gss_OID mech = GSS_C_NO_OID;

    /*
     * Only the initialContextToken contains the mechanism OID.
     */
    if (bOidWrapping)
        mech = ctx->mechanismUsed;

    outputToken->length = tokenSize(mech, innerToken->length);
    outputToken->value = GSSBID_MALLOC(outputToken->length);
    if (outputToken->value == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    p = (unsigned char *)outputToken->value;
    makeTokenHeader(mech, innerToken->length, &p, tokenType);
    memcpy(p, innerToken->value, innerToken->length);

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidVerifyToken(OM_uint32 *minor,
                  const gss_buffer_t inputToken,
                  enum gss_bid_token_type *actualToken,
                  gss_buffer_t innerInputToken,
                  gss_OID *mechanismUsed)
{
    OM_uint32 major;
    size_t bodySize;
    unsigned char *p = (unsigned char *)inputToken->value;
    gss_OID_desc oidBuf;
    gss_OID oid = GSS_C_NO_OID;

    if (*mechanismUsed == GSS_C_NO_OID) {
        oidBuf.elements = NULL;
        oidBuf.length = 0;
        oid = &oidBuf;
    }

    major = verifyTokenHeader(minor, oid, &bodySize, &p,
                              inputToken->length, actualToken);
    if (GSS_ERROR(major))
        return major;

    if (*mechanismUsed == GSS_C_NO_OID) {
        major = gssBidCanonicalizeOid(minor, oid, 0, mechanismUsed);
        if (GSS_ERROR(major))
            return major;
    }

    innerInputToken->length = bodySize;
    innerInputToken->value = p;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidContextTime(OM_uint32 *minor,
                  gss_ctx_id_t context_handle,
                  OM_uint32 *time_rec)
{
    *minor = 0;

    if (context_handle->expiryTime == 0) {
        *time_rec = GSS_C_INDEFINITE;
    } else {
        time_t now, lifetime;

        time(&now);
        lifetime = context_handle->expiryTime - now;
        if (lifetime <= 0) {
            *time_rec = 0;
            return GSS_S_CONTEXT_EXPIRED;
        }
        *time_rec = lifetime;
    }

    return GSS_S_COMPLETE;
}

/*
 * Mark an acceptor context as ready for cryptographic operations
 */
OM_uint32
gssBidContextReady(OM_uint32 *minor, gss_ctx_id_t ctx, gss_cred_id_t cred)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;
    BIDError err;
    const char *szSubject;
    unsigned char *pbSessionKey;
    size_t cbSessionKey;

    gssBidReleaseName(&tmpMinor, &ctx->initiatorName);

    err = BIDGetIdentitySubject(ctx->bidContext, ctx->bidIdentity, &szSubject);
    if (err != BID_S_OK)
        return gssBidMapError(minor, err);

    nameBuf.value = (void *)szSubject;
    nameBuf.length = strlen(szSubject);

    if (nameBuf.length == 0)
        ctx->gssFlags |= GSS_C_ANON_FLAG;

    major = gssBidImportName(minor, &nameBuf,
                             (ctx->gssFlags & GSS_C_ANON_FLAG) ?
                                GSS_C_NT_ANONYMOUS : GSS_C_NT_USER_NAME,
                             ctx->mechanismUsed,
                             &ctx->initiatorName);
    if (GSS_ERROR(major))
        return major;

    if (ctx->encryptionType != ENCTYPE_NULL) {
        err = BIDIdentityDeriveKey(ctx->bidContext, ctx->bidIdentity,
                                   (unsigned char *)"CRK", 3,
                                   &pbSessionKey, &cbSessionKey);
        if (err != BID_S_OK)
            return gssBidMapError(minor, err);

        major = gssBidDeriveRfc3961Key(minor, pbSessionKey, cbSessionKey,
                                       ctx->encryptionType, &ctx->rfc3961Key);

        BIDFreeIdentityDerivedKey(ctx->bidContext, ctx->bidIdentity,
                                  pbSessionKey, cbSessionKey);

        if (GSS_ERROR(major))
            return major;

        major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                          &ctx->checksumType);
        if (GSS_ERROR(major))
            return major;
    }

    major = sequenceInit(minor,
                         &ctx->seqState, ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        return major;

#ifdef GSSBID_ENABLE_ACCEPTOR
    if ((ctx->flags & CTX_FLAG_INITIATOR) == 0) {
        major = gssBidCreateAttrContext(minor, cred, ctx,
                                        &ctx->initiatorName->attrCtx,
                                        &ctx->expiryTime);
        if (GSS_ERROR(major))
            return major;
    }
#endif

    if (ctx->expiryTime != 0 && ctx->expiryTime < time(NULL)) {
        *minor = GSSBID_CRED_EXPIRED;
        return GSS_S_CREDENTIALS_EXPIRED;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}
