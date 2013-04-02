/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
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
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "gssapiP_bid.h"

OM_uint32
gssBidIndicateRPCerts(OM_uint32 *minor,
                      gss_ctx_id_t ctx,
                      gss_buffer_t outputToken)
{
    OM_uint32 major;
    gss_buffer_desc bufJson = GSS_C_EMPTY_BUFFER;
    json_t *response = NULL;
    json_t *iat = NULL;
    BIDError err;
    uint32_t ulReqFlags, ulRetFlags = 0;

    outputToken->length = 0;
    outputToken->value = NULL;

    response = json_object();
    if (response == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    ulReqFlags = BID_RP_FLAG_INITIAL;

    err = BIDMakeRPResponseToken(ctx->bidContext,
                                 BID_C_NO_IDENTITY,
                                 response,
                                 ulReqFlags,
                                 (char **)&bufJson.value,
                                 &bufJson.length,
                                 &ulRetFlags);
    if (err == BID_S_NO_KEY)
        err = BID_S_OK;
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    major = duplicateBuffer(minor, &bufJson, outputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    json_decref(iat);
    json_decref(response);
    BIDFreeData(ctx->bidContext, bufJson.value);

    return major;
}

OM_uint32
gssBidProcessRPCerts(OM_uint32 *minor,
                     gss_ctx_id_t ctx,
                     gss_buffer_t inputToken)
{
    OM_uint32 major;
    char *szAssertion = NULL;
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    json_t *x5c;

    major = bufferToString(minor, inputToken, &szAssertion);
    if (GSS_ERROR(major))
        goto cleanup;

    err = _BIDUnpackBackedAssertion(ctx->bidContext, szAssertion, &backedAssertion);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    x5c = json_object_get(backedAssertion->Assertion->Header, "x5c");
    if (x5c != NULL && json_is_array(x5c)) {
        const char *szCert = json_string_value(json_array_get(x5c, 0));

        err = _BIDBase64UrlDecode(szCert,
                                  (unsigned char **)&ctx->initiatorCtx.serverCert.value,
                                  &ctx->initiatorCtx.serverCert.length);
        if (err != BID_S_OK) {
            major = gssBidMapError(minor, err);
            goto cleanup;
        }
    }

    ctx->flags |= CTX_FLAG_CAN_MUTUAL_AUTH;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    BIDFreeData(ctx->bidContext, szAssertion);
    _BIDReleaseBackedAssertion(ctx->bidContext, backedAssertion);

    return major;
}
