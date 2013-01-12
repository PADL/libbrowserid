/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
_BIDDeriveSessionSubkey(
    BIDContext context,
    BIDIdentity identity,
    const char *szSalt,
    BIDJWK *pDerivedKey)
{
    unsigned char *pbSubkey = NULL;
    size_t cbSubkey;
    BIDError err;
    BIDJWK derivedKey = NULL;
    json_t *sk = NULL;

    *pDerivedKey = NULL;

    err = BIDGetIdentitySessionKey(context, identity, NULL, NULL);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, identity->SessionKey, identity->SessionKeyLength,
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
