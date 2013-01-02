/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

static BIDError
_BIDValidateCertIssuer(
    BIDContext context,
    BIDBackedAssertion backedAssertion)
{
    BIDError err;
    json_t *assertion;
    json_t *leafCert;
    json_t *principal;
    const char *szEmail;
    const char *szEmailIssuer;
    const char *szCertIssuer;

    if (backedAssertion->cCertificates == 0)
        return BID_S_MISSING_CERT;

    leafCert = _BIDLeafCert(context, backedAssertion);
    assertion = backedAssertion->Assertion->Payload;

    principal = json_object_get(leafCert, "principal");
    if (principal == NULL)
        return BID_S_MISSING_PRINCIPAL;

    szEmail = json_string_value(json_object_get(principal, "email"));
    if (szEmail == NULL)
        return BID_S_UNKNOWN_PRINCIPAL_TYPE;

    szEmailIssuer = strchr(szEmail, '@');
    if (szEmailIssuer == NULL)
        return BID_S_INVALID_ISSUER;

    szEmailIssuer++;

    szCertIssuer = json_string_value(json_object_get(leafCert, "iss"));
    if (szCertIssuer == NULL)
        return BID_S_MISSING_ISSUER;

    err = _BIDIssuerIsAuthoritative(context, szEmailIssuer, szCertIssuer);

    return err;
}

BIDError
_BIDValidateExpiry(
    BIDContext context,
    time_t verificationTime,
    json_t *assertion)
{
    time_t expiryTime;

    _BIDGetJsonTimestampValue(context, assertion, "exp", &expiryTime);

    if (expiryTime + context->Skew < verificationTime)
        return BID_S_EXPIRED_ASSERTION;
    else
        return BID_S_OK;
}

static BIDError
_BIDValidateCertChain(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime)
{
    BIDError err;
    BIDAuthority authority = NULL;
    BIDJWKSet rootKey = NULL, pKey = NULL;
    json_t *rootCert = _BIDRootCert(context, backedAssertion);
    const char *szCertIssuer;
    size_t i;

    if (backedAssertion->cCertificates == 0)
        return BID_S_MISSING_CERT;

    szCertIssuer = json_string_value(json_object_get(rootCert, "iss"));
    if (szCertIssuer == NULL) {
        err = BID_S_MISSING_ISSUER;
        goto cleanup;
    }

    err = _BIDAcquireAuthority(context, szCertIssuer, &authority);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetAuthorityPublicKey(context, authority, &rootKey);
    BID_BAIL_ON_ERROR(err);

    pKey = json_incref(rootKey);

    for (i = 0; i < backedAssertion->cCertificates; i++) {
        BIDJWT cert = backedAssertion->rCertificates[i];

        err = _BIDValidateExpiry(context, verificationTime, cert->Payload);
        BID_BAIL_ON_ERROR(err);

        /* XXX collate some attributes into identity object? */

        err = _BIDVerifySignature(context, cert, pKey);
        BID_BAIL_ON_ERROR(err);

        json_decref(pKey);
        pKey = json_incref(cert->Payload);
    }

cleanup:
    _BIDReleaseAuthority(context, authority);
    json_decref(rootKey);

    return err;
}

static BIDError
_BIDVerifyAssertionSignature(
    BIDContext context,
    BIDBackedAssertion backedAssertion)
{
    BIDError err;
    json_t *leafCert;

    BID_ASSERT(backedAssertion->cCertificates > 0);

    if (backedAssertion->cCertificates == 0)
        return BID_S_INVALID_ASSERTION;

    leafCert = backedAssertion->rCertificates[backedAssertion->cCertificates - 1]->Payload;

    err = _BIDVerifySignature(context, backedAssertion->Assertion, leafCert);

    return err;
}

/*
 * Local verifier
 */
BIDError
_BIDVerifyLocal(
    BIDContext context,
    const char *szAssertion,
    const char *szAudience,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;

    BID_CONTEXT_VALIDATE(context);

    /*
     * Split backed identity assertion out into
     * <cert-1>~...<cert-n>~<identityAssertion>
     */
    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion != NULL);
    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);
    BID_ASSERT(backedAssertion->Claims != NULL);

    err = _BIDValidateAudience(context, backedAssertion, szAudience, pbChannelBindings, cbChannelBindings);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateExpiry(context, verificationTime, backedAssertion->Assertion->Payload);
    BID_BAIL_ON_ERROR(err);

    /* Only allow one certificate for now */
    if (backedAssertion->cCertificates != 1) {
        err = BID_S_TOO_MANY_CERTS;
        goto cleanup;
    }

    err = _BIDValidateCertIssuer(context, backedAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateCertChain(context, backedAssertion, verificationTime);
    BID_BAIL_ON_ERROR(err);

    err = _BIDVerifyAssertionSignature(context, backedAssertion);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        err = _BIDCheckReplayCache(context, szAssertion, verificationTime);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDPopulateIdentity(context, backedAssertion, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetJsonTimestampValue(context, backedAssertion->Assertion->Payload, "exp", pExpiryTime);
    if (err != BID_S_OK)
        *pExpiryTime = verificationTime + 300; /* default expires in 5 minutes */

    if (context->ContextOptions & BID_CONTEXT_REPLAY_CACHE) {
        json_t *expiryTime; /* preserve precision */

        expiryTime = json_object_get(backedAssertion->Assertion->Payload, "exp");

        err = _BIDUpdateReplayCache(context, szAssertion, verificationTime, expiryTime);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);
    
    return err;
}
