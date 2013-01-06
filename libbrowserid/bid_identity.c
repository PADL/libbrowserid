/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

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
BIDVerifyAssertion(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    uint32_t ulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    *pVerifiedIdentity = BID_C_NO_IDENTITY;
    *pExpiryTime = 0;
    *pulRetFlags = 0;

    if (szAssertion == NULL || szAudience == NULL)
        return BID_S_INVALID_PARAMETER;

    if ((context->ContextOptions & BID_CONTEXT_RP) == 0)
        return BID_S_INVALID_USAGE;

    if (context->ContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        err = _BIDCheckReplayCache(context, replayCache, szAssertion, verificationTime);
        BID_BAIL_ON_ERROR(err);
    }

    if (context->ContextOptions & BID_CONTEXT_VERIFY_REMOTE)
        err = _BIDVerifyRemote(context, replayCache, szAssertion, szAudience,
                               pbChannelBindings, cbChannelBindings, verificationTime, ulReqFlags,
                               pVerifiedIdentity, pExpiryTime, &ulRetFlags);
    else
        err = _BIDVerifyLocal(context, replayCache, szAssertion, szAudience,
                              pbChannelBindings, cbChannelBindings, verificationTime, ulReqFlags,
                              pVerifiedIdentity, pExpiryTime, &ulRetFlags);
    BID_BAIL_ON_ERROR(err);

    if ((ulRetFlags & BID_VERIFY_FLAG_REAUTH) == 0 &&
        (context->ContextOptions & BID_CONTEXT_DH_KEYEX)) {
        err = _BIDVerifierDHKeyEx(context, *pVerifiedIdentity);
        BID_BAIL_ON_ERROR(err);
    }

    if (context->ContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        err = _BIDUpdateReplayCache(context, replayCache, *pVerifiedIdentity, szAssertion,
                                    verificationTime, ulRetFlags);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    *pulRetFlags = ulRetFlags;
    return err;
}

BIDError
BIDReleaseIdentity(
    BIDContext context,
    BIDIdentity identity)
{
    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY)
        return BID_S_INVALID_PARAMETER;

    if (identity->SessionKey != NULL) {
        memset(identity->SessionKey, 0, identity->SessionKeyLength);
        BIDFree(identity->SessionKey);
    }
    json_decref(identity->Attributes);
    json_decref(identity->PrivateAttributes);
    BIDFree(identity);

    return BID_S_OK;
}

BIDError
BIDGetIdentityAudience(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "aud", pValue);
}

BIDError
BIDGetIdentitySubject(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "sub", pValue);
}

BIDError
BIDGetIdentityIssuer(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "iss", pValue);
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
BIDGetIdentityAttribute(
    BIDContext context,
    BIDIdentity identity,
    const char *attribute,
    const char **pValue)
{
    BIDError err;
    json_t *value;

    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    value = json_object_get(identity->Attributes, attribute);
    if (value == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    *pValue = json_string_value(value);
    if (*pValue == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    return err;
}

BIDError
BIDGetIdentityJsonObject(
    BIDContext context,
    BIDIdentity identity,
    const char *attribute,
    json_t **pJsonValue)
{
    BIDError err;
    json_t *value;

    *pJsonValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (attribute != NULL) {
        value = json_object_get(identity->Attributes, attribute);
        if (value == NULL) {
            err = BID_S_UNKNOWN_ATTRIBUTE;
            goto cleanup;
        }
    } else {
        value = identity->Attributes;
    }

    *pJsonValue = json_incref(value);
    err = BID_S_OK;

cleanup:
    return err;
}

BIDError
_BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    json_t **pValue)
{
    BIDError err;
    json_t *value;

    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    value = json_object_get(identity->PrivateAttributes, "tkt");
    if (value == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    err = BID_S_OK;
    *pValue = json_incref(value);

cleanup:
    return err;
}

BIDError
BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    BIDError err;
    json_t *value = NULL;

    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDGetIdentityReauthTicket(context, identity, &value);
    BID_BAIL_ON_ERROR(err);

    *pValue = json_string_value(value);
    if (*pValue == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    json_decref(value);

    return err;
}

BIDError
BIDGetIdentitySessionKey(
    BIDContext context,
    BIDIdentity identity,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey)
{
    BIDError err;
    json_t *dh;
    json_t *params;

    if (ppbSessionKey != NULL) {
        *ppbSessionKey = NULL;
        *pcbSessionKey = 0;
    }

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (identity->SessionKey == NULL) {
        dh = json_object_get(identity->PrivateAttributes, "dh");
        if (dh == NULL) {
            err = BID_S_NO_KEY;
            goto cleanup;
        }

        params = json_object_get(dh, "params");

        err = _BIDComputeDHKey(context, dh, params, &identity->SessionKey, &identity->SessionKeyLength);
        BID_BAIL_ON_ERROR(err);
    }

    if (ppbSessionKey != NULL) {
        *ppbSessionKey = BIDMalloc(identity->SessionKeyLength);
        if (*ppbSessionKey == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        memcpy(*ppbSessionKey, identity->SessionKey, identity->SessionKeyLength);
        *pcbSessionKey = identity->SessionKeyLength;
    }

    err = BID_S_OK;

cleanup:
    return err;
}

BIDError
BIDFreeIdentitySessionKey(
    BIDContext context,
    BIDIdentity identity BID_UNUSED,
    unsigned char *pbSessionKey,
    size_t cbSessionKey)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (pbSessionKey == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    memset(pbSessionKey, 0, cbSessionKey);
    BIDFree(pbSessionKey);

cleanup:
    return BID_S_OK;
}

BIDError
BIDGetIdentityExpiryTime(
    BIDContext context,
    BIDIdentity identity,
    time_t *value)
{

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY)
        return BID_S_INVALID_PARAMETER;

    return _BIDGetJsonTimestampValue(context, identity->Attributes, "exp", value);
}

BIDError
_BIDAllocIdentity(
    BIDContext context,
    json_t *attributes,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;

    *pIdentity = BID_C_NO_IDENTITY;

    identity = BIDCalloc(1, sizeof(*identity));
    if (identity == BID_C_NO_IDENTITY) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (attributes != NULL)
        identity->Attributes = json_incref(attributes);
    else {
        identity->Attributes = json_object();
        if (identity->Attributes == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    identity->PrivateAttributes = json_object();
    if (identity->PrivateAttributes == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BID_S_OK;
    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

BIDError
_BIDPopulateIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    json_t *assertion = backedAssertion->Assertion->Payload;
    json_t *leafCert = _BIDLeafCert(context, backedAssertion);
    json_t *principal;

    *pIdentity = BID_C_NO_IDENTITY;

    principal = json_object_get(leafCert, "principal");
    if (principal == NULL ||
        json_object_get(principal, "email") == NULL) {
        err = BID_S_MISSING_PRINCIPAL;
        goto cleanup;
    }

    err = _BIDAllocIdentity(context, leafCert, &identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "sub",
                           json_object_get(principal, "email"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "aud",
                            json_object_get(assertion, "aud"), 0);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_DH_KEYEX) {
        json_t *params = json_object_get(backedAssertion->Claims, "dh");

        if (params != NULL) {
            json_t *dh = json_object();

            if (dh == NULL) {
                err = BID_S_NO_MEMORY;
                goto cleanup;
            }

            err = _BIDJsonObjectSet(context, dh, "params", params, 0);
            BID_BAIL_ON_ERROR(err);

            err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "dh", dh, 0);
            BID_BAIL_ON_ERROR(err);
        }
    }

    /* Assertion expiry time, internal use only */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "a-exp",
                            json_object_get(assertion, "exp"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}
