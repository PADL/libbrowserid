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
 *    how to obtain complete source code for the libbrowserid software
 *    and any accompanying software that uses the libbrowserid software.
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

static BIDError
_BIDGenerateECDHParams(
    BIDContext context,
    json_t **pEcDhParams)
{
    BIDError err;
    json_t *ecDhParams = NULL;
    char *szCurve;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_ECDH_KEYEX);
    BID_ASSERT(context->ECDHCurve != 0);

    err = _BIDAllocJsonObject(context, &ecDhParams);
    BID_BAIL_ON_ERROR(err);

    err = BIDGetContextParam(context, BID_PARAM_ECDH_CURVE, (void **)&szCurve);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ecDhParams, "kty", json_string("EC"),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, ecDhParams, "crv", json_string(szCurve),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pEcDhParams = ecDhParams;

cleanup:
    if (err != BID_S_OK)
        json_decref(ecDhParams);

    return err;
}

BIDError
_BIDIdentitySecretAgreement(
    BIDContext context,
    BIDIdentity identity)
{
    BIDError err;
    json_t *dh;
    json_t *params;
    ssize_t cbKey;

    if (identity->SecretHandle == NULL) {
        err = _BIDGetKeyAgreementObject(context, identity->PrivateAttributes, &dh);
        if (err != BID_S_OK)
            return err;

        if ((context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) == 0)
            return BID_S_NO_KEY;

        params = json_object_get(dh, "params");

        err = _BIDGetECDHCurve(context, params, &cbKey);
        if (err != BID_S_OK)
            return err;

        if (cbKey < context->ECDHCurve)
            return BID_S_INVALID_EC_CURVE;

        err = _BIDECDHSecretAgreement(context, dh, params, &identity->SecretHandle);
    } else {
        err = BID_S_OK;
    }

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

    err = _BIDIdentitySecretAgreement(context, identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, identity->SecretHandle,
                        (unsigned char *)szSalt, strlen(szSalt), &pbSubkey, &cbSubkey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDAllocJsonObject(context, &derivedKey);
    BID_BAIL_ON_ERROR(err);

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
_BIDVerifierKeyAgreement(
    BIDContext context,
    BIDIdentity identity)
{
    BIDError err;
    json_t *dh;
    json_t *params;
    json_t *key = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_ECDH_KEYEX);
    BID_ASSERT(identity != BID_C_NO_IDENTITY);

    err = _BIDGetKeyAgreementObject(context, identity->PrivateAttributes, &dh);
    BID_BAIL_ON_ERROR(err);

    params = json_object_get(dh, "params");

    err = _BIDGenerateECDHKey(context, params, &key);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, dh, "x", json_object_get(key, "x"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, dh, "y", json_object_get(key, "y"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, dh, "d", json_object_get(key, "d"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(key);

    return err;
}

BIDError
_BIDGetKeyAgreementPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t **pPublicValue)
{
    BIDError err;
    json_t *dh = NULL;
    json_t *y = NULL;
    json_t *x = NULL;

    *pPublicValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDGetKeyAgreementObject(context, identity->PrivateAttributes, &dh);
    BID_BAIL_ON_ERROR(err);

    x = json_object_get(dh, "x");
    if (x == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    y = json_object_get(dh, "y");
    if (y == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    err = _BIDAllocJsonObject(context, pPublicValue);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, *pPublicValue, "x", x, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, *pPublicValue, "y", y, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && *pPublicValue != NULL) {
        json_decref(*pPublicValue);
        *pPublicValue = NULL;
    }

    return err;
}

BIDError
_BIDSetKeyAgreementPublicValue(
    BIDContext context,
    BIDIdentity identity,
    json_t *peerDh)
{
    BIDError err;
    json_t *dh;
    json_t *params;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDGetKeyAgreementObject(context, identity->PrivateAttributes, &dh);
    BID_BAIL_ON_ERROR(err);

    params = json_object_get(dh, "params");
    if (params == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, params, "x", json_object_get(peerDh, "x"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, params, "y", json_object_get(peerDh, "y"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
_BIDGetKeyAgreementParams(
    BIDContext context,
    json_t **pDhParams)
{
    *pDhParams = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_ECDH_KEYEX);

    return _BIDGenerateECDHParams(context, pDhParams);
}

BIDError
_BIDSaveKeyAgreementStrength(
    BIDContext context,
    BIDIdentity identity,
    int publicKey BID_UNUSED,
    json_t *cred)
{
    BIDError err;
    unsigned char *pbDHKey = NULL;
    size_t cbDHKey = 0;
    json_t *dh;

    /*
     * If the key strength has already been saved, don't stomp on it.
     */
    if (json_object_get(cred, "crv") != NULL) {
        err = BID_S_OK;
        goto cleanup;
    }

    err = _BIDGetKeyAgreementObject(context, identity->PrivateAttributes, &dh);
    if (err == BID_S_NO_KEY) {
        /*
         * If it's a re-authentication context, then propagate EC curve
         */
        err = _BIDJsonObjectSet(context, cred, "crv",
                                json_object_get(identity->PrivateAttributes, "crv"), 0);
        BID_BAIL_ON_ERROR(err);
    } else if (context->ContextOptions & BID_CONTEXT_ECDH_KEYEX) {
        err = _BIDJsonObjectSet(context, cred, "crv",
                                json_object_get(json_object_get(dh, "params"), "crv"),
                                BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    if (pbDHKey != NULL) {
        memset(pbDHKey, 0, cbDHKey);
        BIDFree(pbDHKey);
    }

    return err;
}

BIDError
_BIDGetKeyAgreementObject(
    BIDContext context BID_UNUSED,
    json_t *json,
    json_t **pObject)
{
    *pObject = json_object_get(json, "epk");

    return (*pObject != NULL) ? BID_S_OK : BID_S_NO_KEY;
}

BIDError
_BIDSetKeyAgreementObject(
    BIDContext context,
    json_t *json,
    json_t *object)
{
    return _BIDJsonObjectSet(context, json, "epk", object, BID_JSON_FLAG_REQUIRED);
}

BIDError
_BIDGetECDHCurve(
    BIDContext context BID_UNUSED,
    json_t *ecDhParams,
    ssize_t *pcbKey)
{
    const char *szKeyType;
    const char *szCurve;
    ssize_t cbKey = 0;

    szKeyType = json_string_value(json_object_get(ecDhParams, "kty"));
    if (szKeyType == NULL || strcmp(szKeyType, "EC") != 0)
        return BID_S_UNKNOWN_ALGORITHM;

    szCurve = json_string_value(json_object_get(ecDhParams, "crv"));
    if (szCurve != NULL) {
        if (strcmp(szCurve, BID_ECDH_CURVE_P256) == 0) {
            cbKey = BID_CONTEXT_ECDH_CURVE_P256;
        } else if (strcmp(szCurve, BID_ECDH_CURVE_P384) == 0) {
            cbKey = BID_CONTEXT_ECDH_CURVE_P384;
        } else if (strcmp(szCurve, BID_ECDH_CURVE_P521) == 0) {
            cbKey = BID_CONTEXT_ECDH_CURVE_P521;
        }
    }

    *pcbKey = cbKey;

    return (cbKey == 0) ? BID_S_UNKNOWN_EC_CURVE : BID_S_OK;
}

BIDError
_BIDMakeDigest(
    BIDContext context,
    json_t *value,
    json_t **pDigestInfo)
{
    BIDError err;
    json_t *digestInfo = NULL;

    *pDigestInfo = NULL;

    if (!json_is_string(value)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDAllocJsonObject(context, &digestInfo);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, digestInfo, "alg", json_string("S256"),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeDigestInternal(context, value, digestInfo);
    BID_BAIL_ON_ERROR(err);

    *pDigestInfo = digestInfo;

cleanup:
    if (err != BID_S_OK)
        json_decref(digestInfo);

    return err;
}

BIDError
_BIDVerifyDigest(
    BIDContext context,
    json_t *value,
    json_t *assertedDigestInfo)
{
    BIDError err;
    json_t *digestInfo = NULL;

    if (!json_is_string(value)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDAllocJsonObject(context, &digestInfo);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, digestInfo, "alg",
                            json_object_get(assertedDigestInfo, "alg"),
                            BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeDigestInternal(context, value, digestInfo);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(json_string_value(json_object_get(digestInfo, "dig")) != NULL);

    if (json_equal(json_object_get(digestInfo, "dig"),
                   json_object_get(assertedDigestInfo, "dig"))) {
        err = BID_S_OK;
    } else {
        err = BID_S_INVALID_SIGNATURE;
    }

cleanup:
    json_decref(digestInfo);

    return err;
}

BIDError
_BIDDigestAssertion(
    BIDContext context,
    const char *szAssertion,
    json_t **pDigest)
{
    BIDError err;
    json_t *digestInfo = NULL;
    json_t *assertion = json_string(szAssertion);

    *pDigest = NULL;

    if (assertion == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDMakeDigest(context, assertion, &digestInfo);
    BID_BAIL_ON_ERROR(err);

    *pDigest = json_incref(json_object_get(digestInfo, "dig"));
    if (*pDigest == NULL) {
        err = BID_S_CRYPTO_ERROR;
        goto cleanup;
    }

cleanup:
    json_decref(digestInfo);
    json_decref(assertion);

    return err;
}
