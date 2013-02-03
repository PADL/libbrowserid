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

#include "bid_private.h"

BIDError
_BIDIdentityComputeKey(
    BIDContext context,
    BIDIdentity identity)
{
    BIDError err;
    json_t *dh;
    json_t *params;

    if (identity->SecretHandle == NULL) {
        dh = json_object_get(identity->PrivateAttributes, "dh");
        if (dh == NULL) {
            err = BID_S_NO_KEY;
            goto cleanup;
        }

        params = json_object_get(dh, "params");

        err = _BIDComputeDHKey(context, dh, params, &identity->SecretHandle);
        BID_BAIL_ON_ERROR(err);
    } else
        err = BID_S_OK;

cleanup:
    return err;
}

BIDError
_BIDDeriveSessionSubkey(
    BIDContext context,
    BIDIdentity identity,
    const char *szSalt,
    BIDJWK *pDerivedKey)
{
    unsigned char *pbSubkey = NULL;
    size_t cbSubkey = 0;
    BIDError err;
    BIDJWK derivedKey = NULL;
    json_t *sk = NULL;

    *pDerivedKey = NULL;

    BID_ASSERT(szSalt != NULL);

    err = _BIDIdentityComputeKey(context, identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, identity->SecretHandle,
                        (unsigned char *)szSalt, strlen(szSalt), &pbSubkey, &cbSubkey);
    BID_BAIL_ON_ERROR(err);

    derivedKey = json_object();
    if (derivedKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonBinaryValue(context, pbSubkey, cbSubkey, &sk);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, derivedKey, "secret-key", sk, 0);
    BID_BAIL_ON_ERROR(err);

    *pDerivedKey = derivedKey;
    err = BID_S_OK;

cleanup:
    if (pbSubkey != NULL) {
        memset(pbSubkey, 0, cbSubkey);
        BIDFree(pbSubkey);
    }
    json_decref(sk);
    if (err != BID_S_OK)
        json_decref(derivedKey);

    return err;
}

int
_BIDIsLegacyJWK(
    BIDContext context BID_UNUSED,
    BIDJWK jwk)
{
    const char *version = json_string_value(json_object_get(jwk, "version"));

    return (version == NULL || strcmp(version, "2012.08.15") != 0);
}

static int
_BIDKeyMatchesP(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWK jwk)
{
    const char *alg;
    size_t keySize;
    int isSecretKey;

    if (jwk == NULL)
        return 0;

    isSecretKey = (json_object_get(jwk, "secret-key") != NULL);

    if (isSecretKey) {
        alg = "HS";
    } else {
        alg = json_string_value(json_object_get(jwk, "algorithm"));
        if (alg == NULL)
            alg = json_string_value(json_object_get(jwk, "alg"));
    }

    if (alg == NULL)
        return 0;

    if (strncmp(alg, algorithm->szKeyAlgID, 2) != 0)
        return 0;

    if (algorithm->cbKey) {
        if (algorithm->KeySize(algorithm, context, jwk, &keySize) != BID_S_OK)
            return 0;

        if (keySize != algorithm->cbKey)
            return 0;
    }

    return 1;
}

BIDError
_BIDFindKeyInKeyset(
    BIDContext context,
    BIDJWTAlgorithm algorithm,
    BIDJWKSet keyset,
    BIDJWK *pKey)
{
    BIDError err;
    json_t *keys;
    size_t i, cKeys;

    *pKey = NULL;

    if (keyset == NULL)
        return BID_S_INVALID_KEYSET;

    keys = json_object_get(keyset, "keys");
    if (keys == NULL) {
        BIDJWK jwk = json_object_get(keyset, "public-key");

        if (jwk == NULL) /* try directly without container */
            jwk = keyset;

        if (_BIDKeyMatchesP(context, algorithm, jwk)) {
            *pKey = json_incref(jwk);
            return BID_S_OK;
        }

        return BID_S_INVALID_KEYSET;
    }

    cKeys = json_array_size(keys);
    for (i = 0, err = BID_S_NO_KEY; i < cKeys; i++) {
        BIDJWK jwk = json_array_get(keys, i);

        err = _BIDFindKeyInKeyset(context, algorithm, jwk, pKey);
        if (err == BID_S_OK)
            break;
    }

    return err;
}

BIDError
_BIDImportSecretKey(
    BIDContext context,
    BIDJWK jwk,
    BIDSecretHandle *pSecretHandle)
{
    BIDError err;
    unsigned char *pbSecret = NULL;
    size_t cbSecret = 0;

    *pSecretHandle = NULL;

    err = _BIDGetJsonBinaryValue(context, jwk, "secret-key", &pbSecret, &cbSecret);
    BID_BAIL_ON_ERROR(err);

    err = _BIDImportSecretKeyData(context, pbSecret, cbSecret, pSecretHandle);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (pbSecret != NULL) {
        memset(pbSecret, 0, cbSecret);
        BIDFree(pbSecret);
    }

    return err;
}

BIDError
_BIDVerifierDHKeyEx(
    BIDContext context,
    BIDIdentity identity)
{
    BIDError err;
    json_t *dh;
    json_t *params;
    json_t *key = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_DH_KEYEX);
    BID_ASSERT(identity != BID_C_NO_IDENTITY);

    dh = json_object_get(identity->PrivateAttributes, "dh");
    if (dh == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    params = json_object_get(dh, "params");

    err = _BIDGenerateDHKey(context, params, &key);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, dh, "x", json_object_get(key, "x"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, dh, "y", json_object_get(key, "y"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(key);

    return err;
}

BIDError
_BIDGetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t **pY)
{
    BIDError err;
    json_t *dh = NULL;
    json_t *y = NULL;

    *pY = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (identity->PrivateAttributes == NULL                                   ||
        (dh     = json_object_get(identity->PrivateAttributes, "dh")) == NULL ||
        (y      = json_object_get(dh, "y")) == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    *pY = json_object();
    if (*pY == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, *pY, "y", y, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && *pY != NULL) {
        json_decref(*pY);
        *pY = NULL;
    }

    return err;
}

BIDError
BIDGetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    unsigned char **pY,
    size_t *pcbY)
{
    BIDError err;
    json_t *dh;

    *pY = NULL;
    *pcbY = 0;

    err = _BIDGetIdentityDHPublicValue(context, identity, &dh);
    if (err != BID_S_OK)
        return err;

    err = _BIDGetJsonBinaryValue(context, dh, "y", pY, pcbY);

    return err;
}

BIDError
_BIDSetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t *y)
{
    BIDError err;
    json_t *dh;
    json_t *params;

    BID_CONTEXT_VALIDATE(context);

    dh = json_object_get(identity->PrivateAttributes, "dh");
    if (dh == NULL)
        return BID_S_NO_KEY;

    params = json_object_get(dh, "params");
    if (params == NULL)
        return BID_S_NO_KEY;

    err = _BIDJsonObjectSet(context, params, "y", y, BID_JSON_FLAG_REQUIRED);
    if (err != BID_S_OK)
        return err;

    return BID_S_OK;
}

BIDError
BIDSetIdentityDHPublicValue(
    BIDContext context,
    BIDIdentity identity,
    const unsigned char *pY,
    size_t cbY)
{
    BIDError err;
    json_t *y;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDJsonBinaryValue(context, pY, cbY, &y);
    if (err != BID_S_OK)
        return err;

    err = _BIDSetIdentityDHPublicValue(context, identity, y);

    json_decref(y);

    return err;
}

BIDError
_BIDAcquireDefaultDHParamsCache(BIDContext context)
{
    return _BIDAcquireCacheForUser(context, "browserid.dhparams", &context->DHParamsCache);
}

BIDError
_BIDGetDHParams(
    BIDContext context,
    json_t **pDhParams)
{
    BIDError err = BID_S_CACHE_NOT_FOUND;

    *pDhParams = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_DH_KEYEX);

    /*
     * For common key sizes, use RFC 5114 fixed parameters.
     */
    err = _BIDGetFixedDHParams(context, pDhParams);
    if (err == BID_S_OK || err != BID_S_DH_PARAM_GENERATION_FAILURE)
        return err;

    if (context->DHParamsCache != NULL) {
        err = _BIDGetCacheObject(context, context->DHParamsCache,
                                 "params", pDhParams);
        if (err == BID_S_OK)
            return err;
    }

    err = _BIDGenerateDHParams(context, pDhParams);
    if (err == BID_S_OK && context->DHParamsCache != NULL)
        _BIDSetCacheObject(context, context->DHParamsCache, "params", *pDhParams);

    return err;
}

BIDError
_BIDSaveDHKeySize(
    BIDContext context,
    BIDIdentity identity,
    int publicKey,
    json_t *cred)
{
    BIDError err;
    unsigned char *pbDHKey = NULL;
    size_t cbDHKey = 0;

    err = _BIDGetJsonBinaryValue(context,
                                 json_object_get(identity->PrivateAttributes, "dh"),
                                 publicKey ? "y" : "x", &pbDHKey, &cbDHKey);
    if (err == BID_S_OK) {
        err = _BIDJsonObjectSet(context, cred, "dh-key-size",
                                json_integer(cbDHKey * 8),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    }

    if (pbDHKey != NULL) {
        memset(pbDHKey, 0, cbDHKey);
        BIDFree(pbDHKey);
    }

    return err;
}
