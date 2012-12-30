/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
BIDVerifyAssertion(
    BIDContext context,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime)
{
    BID_CONTEXT_VALIDATE(context);

    *pVerifiedIdentity = BID_C_NO_IDENTITY;

    if (szAssertion == NULL || szAudience == NULL)
        return BID_S_INVALID_PARAMETER;

    if ((context->ContextOptions & BID_CONTEXT_RP) == 0)
        return BID_S_INVALID_USAGE;

    if (context->ContextOptions & BID_CONTEXT_VERIFY_REMOTE)
        return _BIDVerifyRemote(context, szAssertion, szAudience,
                                pbChannelBindings, cbChannelBindings, verificationTime,
                                pVerifiedIdentity, pExpiryTime);
    else
        return _BIDVerifyLocal(context, szAssertion, szAudience,
                               pbChannelBindings, cbChannelBindings, verificationTime,
                               pVerifiedIdentity, pExpiryTime);
}

BIDError
BIDReleaseIdentity(
    BIDContext context,
    BIDIdentity identity)
{
    if (identity == BID_C_NO_IDENTITY)
        return BID_S_INVALID_PARAMETER;

    json_decref(identity->Attributes);
    BIDFree(identity);

    return BID_S_OK;
}

BIDError
_BIDValidateAudience(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings)
{
    BIDError err;
    json_t *assertion = backedAssertion->Assertion->Payload;
    const char *assertionAudience = json_string_value(json_object_get(assertion, "aud"));
    char *szAssertionSpn = NULL;
    unsigned char *pbAssertionCB = NULL;
    size_t cbAssertionCB = 0;

    if (assertionAudience == NULL)
        return BID_S_MISSING_AUDIENCE;

    err = _BIDUnpackAudience(context, assertionAudience, &szAssertionSpn, &pbAssertionCB, &cbAssertionCB);
    BID_BAIL_ON_ERROR(err);

    if (szAudienceOrSpn != NULL) {
        if (strcmp(szAudienceOrSpn, szAssertionSpn) != 0) {
            err = BID_S_BAD_AUDIENCE;
            goto cleanup;
        }
    }

    if (pbChannelBindings != NULL) {
        if (cbAssertionCB == 0) {
            err = BID_S_MISSING_CHANNEL_BINDINGS;
            goto cleanup;
        } else if (cbChannelBindings != cbAssertionCB ||
                   memcmp(pbChannelBindings, pbAssertionCB, cbAssertionCB) != 0) {
            err = BID_S_CHANNEL_BINDINGS_MISMATCH;
            goto cleanup;
        }
    }

    err = BID_S_OK;

cleanup:
    BIDFree(szAssertionSpn);
    BIDFree(pbAssertionCB);

    return err;
}

BIDError
BIDGetIdentityAudience(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "audience", pValue);
}

BIDError
BIDGetIdentityEmail(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "email", pValue);
}

BIDError
BIDGetIdentityIssuer(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "issuer", pValue);
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
BIDGetIdentitySessionKey(
    BIDContext context,
    BIDIdentity identity,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDGetJsonBinaryValue(context, identity->Attributes, "skey", ppbSessionKey, pcbSessionKey);
    if (err == BID_S_UNKNOWN_JSON_KEY)
        err = BID_S_NO_SESSION_KEY;

cleanup:
    return err;
}

BIDError
BIDFreeIdentitySessionKey(
    BIDContext context,
    BIDIdentity identity,
    unsigned char *pbSessionKey,
    size_t cbSessionKey)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (pbSessionKey == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    BIDFree(pbSessionKey);

cleanup:
    return BID_S_OK;
}