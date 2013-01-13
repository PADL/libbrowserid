/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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
    BIDIdentity bidIdentity = BID_C_NO_IDENTITY;

    outputToken->length = 0;
    outputToken->value = NULL;

    response = json_object();
    if (response == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    ulReqFlags = BID_RP_FLAG_INITIAL;

    err = _BIDAllocIdentity(ctx->bidContext, NULL, &bidIdentity);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    err = BIDMakeRPResponseToken(ctx->bidContext,
                                 bidIdentity,
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

#ifdef GSSBID_DEBUG
    json_dumpf(response, stdout, JSON_INDENT(8));
    printf("\n");
#endif

    major = duplicateBuffer(minor, &bufJson, outputToken);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    json_decref(iat);
    json_decref(response);
    BIDFreeData(ctx->bidContext, bufJson.value);
    BIDReleaseIdentity(ctx->bidContext, bidIdentity);

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
