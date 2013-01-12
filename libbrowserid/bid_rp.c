/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

BIDError
BIDMakeRPResponseToken(
    BIDContext context,
    BIDIdentity identity,
    json_t *additionalClaims,
    uint32_t ulReqFlags,
    char **pszResponseToken,
    size_t *pchResponseToken,
    uint32_t *pulRetFlags)
{
    BIDError err;
    struct BIDJWTDesc jwt;
    struct BIDBackedAssertionDesc backedAssertion = { 0 };
    BIDJWK key = NULL;
    json_t *payload = NULL;
    json_t *certChain = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_RP);

    *pszResponseToken = NULL;
    *pchResponseToken = 0;
    *pulRetFlags = 0;

    payload = additionalClaims ? json_copy(additionalClaims) : json_object();
    if (payload == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    /* XXX this test is an abstraction violation, rename flags */
    if ((ulReqFlags & BID_RP_FLAG_INITIAL) &&           /* not reauth */
        (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY)) {  /* have session key */
        json_t *dh = NULL;
        json_t *ticket = NULL;

        err = _BIDJsonObjectSet(context, payload, "n", json_object_get(identity->PrivateAttributes, "n"), 0);
        BID_BAIL_ON_ERROR(err);

        err = _BIDGetIdentityDHPublicValue(context, identity, &dh);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, payload, "dh", dh, BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        if (_BIDGetIdentityReauthTicket(context, identity, &ticket) == BID_S_OK) {
            err = _BIDJsonObjectSet(context, payload, "tkt", ticket, BID_JSON_FLAG_CONSUME_REF);
            BID_BAIL_ON_ERROR(err);
        }
    }

    err = BID_S_NO_KEY;
    if (ulReqFlags & BID_RP_FLAG_INITIAL) {
        err = _BIDGetRPPrivateKey(context, &key, &certChain);
        if (err == BID_S_OK)
            *pulRetFlags |= BID_RP_FLAG_X509;
    }
    if (err != BID_S_OK &&
        (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY)) {
        err = _BIDDeriveSessionSubkey(context, identity, "RRK", &key);
        BID_BAIL_ON_ERROR(err);
    }

    jwt.EncData = NULL;
    jwt.EncDataLength = 0;
    jwt.Header = NULL;
    jwt.Payload = json_incref(payload);
    jwt.Signature = NULL;
    jwt.SignatureLength = 0;

    backedAssertion.Assertion = &jwt;
    backedAssertion.cCertificates = 0;

    err = _BIDPackBackedAssertion(context, &backedAssertion, key, certChain, pszResponseToken);
    BID_BAIL_ON_ERROR(err);

    *pchResponseToken = strlen(*pszResponseToken);

cleanup:
    json_decref(payload);
    json_decref(key);
    json_decref(certChain);
    _BIDReleaseJWTInternal(context, &jwt, 0);

    return err;
}

BIDError
BIDVerifyRPResponseToken(
    BIDContext context,
    BIDIdentity identity,
    const char *szAssertion,
    const char *szAudienceName,
    uint32_t ulReqFlags,
    json_t **pPayload,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDJWK verifyCred = NULL;
    BIDBackedAssertion backedAssertion = NULL;
    json_t *dh;
    uint32_t ulVerifyFlags = 0;

    *pulRetFlags = 0;

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    dh = json_object_get(backedAssertion->Assertion->Payload, "dh");
    if (dh != NULL) {
        err = _BIDSetIdentityDHPublicValue(context, identity, json_object_get(dh, "y"));
        BID_BAIL_ON_ERROR(err);
    }

    if (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY) {
        err = _BIDDeriveSessionSubkey(context, identity, "RRK", &verifyCred);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDVerifyLocal(context, NULL, backedAssertion, NULL, szAudienceName,
                          NULL, 0, time(NULL), BID_VERIFY_FLAG_RP, verifyCred,
                          NULL, &ulVerifyFlags);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);

    if (ulVerifyFlags & BID_VERIFY_FLAG_VALIDATED_CERTS)
        *pulRetFlags |= BID_RP_FLAG_VALIDATED_CERTS;
    if (ulVerifyFlags & BID_VERIFY_FLAG_X509)
        *pulRetFlags |= BID_RP_FLAG_X509;

    if (*pulRetFlags & BID_RP_FLAG_VALIDATED_CERTS) {
        /*
         * Re-authentication responses must signed with the RRK, not a certificate.
         */
        if ((ulReqFlags & BID_RP_FLAG_INITIAL) == 0) {
            err = BID_S_MISMATCHED_RP_RESPONSE;
            goto cleanup;
        }

        /*
         * Where the server was authenticated, the nonce must match.
         */
        if (ulReqFlags & BID_RP_FLAG_VERIFY_NONCE) {
            json_t *storedNonce   = json_object_get(identity->PrivateAttributes, "n");
            json_t *assertedNonce = json_object_get(backedAssertion->Assertion->Payload, "n");

            if (!json_equal(storedNonce, assertedNonce)) {
                err = BID_S_MISMATCHED_RP_RESPONSE;
                goto cleanup;
            }
        }
    }

cleanup:
    if (backedAssertion != NULL)
        *pPayload = json_incref(backedAssertion->Assertion->Payload);

    _BIDReleaseBackedAssertion(context, backedAssertion);
    json_decref(verifyCred);

    return err;
}
