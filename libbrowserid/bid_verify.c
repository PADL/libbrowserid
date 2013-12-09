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

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If the exp date of the assertion is earlier than the current time by more
 * a certain interval, the assertion has expired and must be rejected. A
 * Party MAY choose the length of that interval, though it is recommended
 * it be less than 5 minutes.
 */
BIDError
_BIDValidateExpiry(
    BIDContext context,
    time_t verificationTime,
    json_t *jwt)
{
    BIDError err = BID_S_OK;
    time_t issueTime = 0, notBefore = 0, expiryTime = 0;

    err = _BIDGetJsonTimestampValue(context, jwt, "iat", &issueTime);
    if (err == BID_S_OK && issueTime - verificationTime > context->Skew) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    err = _BIDGetJsonTimestampValue(context, jwt, "nbf", &notBefore);
    if (err == BID_S_OK && notBefore - verificationTime > context->Skew) {
        err = BID_S_ASSERTION_NOT_YET_VALID;
        goto cleanup;
    }

    err = _BIDGetJsonTimestampValue(context, jwt, "exp", &expiryTime);
    if (err == BID_S_UNKNOWN_JSON_KEY && issueTime != 0) {
        /* XXX use Skew as default lifetime as well as clock skew */
        expiryTime = issueTime + context->Skew;
        err = BID_S_OK;
    }
    BID_BAIL_ON_ERROR(err);

    if (verificationTime - expiryTime > context->Skew) {
        err = BID_S_EXPIRED_ASSERTION;
        goto cleanup;
    }

cleanup:
    return err;
}

static BIDError
_BIDValidateAudienceHostAlias(
    BIDContext context,
    const char *szAudienceOrSpn,
    const char *szAssertionSpn)
{
    BIDError err = BID_S_BAD_AUDIENCE;

    /*
     * If audience is a GSS SPN beginning with "host/", then just
     * match on the remainder of the SPN.
     */
    if (strncmp(szAssertionSpn, "host/", 5) == 0) {
        char *szHostSpnAudience = NULL;

        err = _BIDHostifySpn(context, szAudienceOrSpn, &szHostSpnAudience);
        BID_BAIL_ON_ERROR(err);

        if (strcmp(szAssertionSpn, szHostSpnAudience) == 0)
            err = BID_S_OK;
        else
            err = BID_S_BAD_AUDIENCE;

        BIDFree(szHostSpnAudience);
    }

cleanup:
    return err;
}

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If the audience field of the assertion does not match the Relying Party's
 * origin (including scheme and optional non-standard port), reject the assertion.
 * A domain that includes the standard port, of 80 for HTTP and 443 for HTTPS,
 * SHOULD be treated as equivalent to a domain that matches the protocol but does
 * not include the port. (XXX: Can we find an RFC that defines this equality
 * test?)
 */
BIDError
_BIDValidateAudience(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings)
{
    BIDError err;
    unsigned char *pbAssertionCB = NULL;
    size_t cbAssertionCB = 0;
    json_t *userClaims = backedAssertion->Assertion->Payload;

    if (userClaims == NULL)
        return BID_S_MISSING_AUDIENCE;

    if (szAudienceOrSpn != NULL) {
        const char *szAssertionSpn = json_string_value(json_object_get(userClaims, "aud"));

        if (szAssertionSpn == NULL) {
            err = BID_S_MISSING_AUDIENCE;
        } else if (strcmp(szAudienceOrSpn, szAssertionSpn) == 0) {
            err = BID_S_OK;
        } else if (context->ContextOptions & BID_CONTEXT_HOST_SPN_ALIAS) {
            err = _BIDValidateAudienceHostAlias(context, szAudienceOrSpn, szAssertionSpn);
        } else {
            err = BID_S_BAD_AUDIENCE;
        }
        BID_BAIL_ON_ERROR(err);
    }

    if (pbChannelBindings != NULL) {
        err = _BIDGetJsonBinaryValue(context, userClaims, "cb", &pbAssertionCB, &cbAssertionCB);
        if (err == BID_S_UNKNOWN_JSON_KEY)
            err = BID_S_MISSING_CHANNEL_BINDINGS;
        BID_BAIL_ON_ERROR(err);

        if (cbChannelBindings != cbAssertionCB ||
            memcmp(pbChannelBindings, pbAssertionCB, cbAssertionCB) != 0) {
            err = BID_S_CHANNEL_BINDINGS_MISMATCH;
            goto cleanup;
        }
    }

    err = BID_S_OK;

cleanup:
    BIDFree(pbAssertionCB);

    return err;
}

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If the Identity Assertion's signature does not verify against the
 * public-key within the last Identity Certificate, reject the assertion.
 */
static BIDError
_BIDVerifyAssertionSignature(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    BIDJWK verifyCred)
{
    return _BIDVerifySignature(context, backedAssertion->Assertion, verifyCred);
}

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If the first certificate (or only certificate when
 * there is only one) is not properly signed by the expected issuer's public key,
 * reject the assertion. The expected issuer is either the domain of the certified
 * email address in the last certificate, or the issuer listed in the first
 * certificate if the email-address domain does not support BrowserID.
 */
static BIDError
_BIDValidateCertIssuer(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime,
    uint32_t ulReqFlags)
{
    json_t *leafCert;
    json_t *principal;
    const char *szAuthority;
    const char *szCertIssuer;

    if (backedAssertion->cCertificates == 0)
        return BID_S_MISSING_CERT;

    leafCert = _BIDLeafCert(context, backedAssertion);

    principal = json_object_get(leafCert, "principal");
    if (principal == NULL)
        return BID_S_MISSING_PRINCIPAL;

    /*
     * For host certificates, the asserted authority is the hostname itself.
     */
    if (ulReqFlags & BID_VERIFY_FLAG_RP) {
        szAuthority = json_string_value(json_object_get(principal, "hostname"));
    } else {
        const char *szEmail;

        szEmail = json_string_value(json_object_get(principal, "email"));
        if (szEmail == NULL)
            return BID_S_UNKNOWN_PRINCIPAL_TYPE;

        szAuthority = strchr(szEmail, '@');
        if (szAuthority != NULL)
            szAuthority++;
    }

    if (szAuthority == NULL)
        return BID_S_INVALID_ISSUER;

    szCertIssuer = json_string_value(json_object_get(leafCert, "iss"));
    if (szCertIssuer == NULL)
        return BID_S_MISSING_ISSUER;

    return _BIDIssuerIsAuthoritative(context, szAuthority, szCertIssuer,
                                     verificationTime);
}

/*
 * From https://github.com/mozilla/id-specs/blob/prod/browserid/index.md:
 *
 * If there is more than one Identity Certificate, then reject the assertion
 * unless each certificate after the first one is properly signed by the prior
 * certificate's public key.
 */
static BIDError
_BIDValidateCertChain(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime,
    BIDJWKSet *pCertSigningKey)
{
    BIDError err;
    BIDAuthority authority = NULL;
    BIDJWKSet rootKey = NULL, pKey = NULL;
    json_t *rootCert = _BIDRootCert(context, backedAssertion);
    const char *szCertIssuer;
    size_t i;

    *pCertSigningKey = NULL;

    if (backedAssertion->cCertificates == 0)
        return BID_S_MISSING_CERT;

    szCertIssuer = json_string_value(json_object_get(rootCert, "iss"));
    if (szCertIssuer == NULL) {
        err = BID_S_MISSING_ISSUER;
        goto cleanup;
    }

    err = _BIDAcquireAuthority(context, szCertIssuer, verificationTime, &authority);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetAuthorityPublicKey(context, authority, &rootKey);
    BID_BAIL_ON_ERROR(err);

    pKey = json_incref(rootKey);

    for (i = 0; i < backedAssertion->cCertificates; i++) {
        BIDJWT cert = backedAssertion->rCertificates[i];

        err = _BIDValidateExpiry(context, verificationTime, cert->Payload);
        BID_BAIL_ON_ERROR(err);

        err = _BIDVerifySignature(context, cert, pKey);
        BID_BAIL_ON_ERROR(err);

        if (i == backedAssertion->cCertificates - 1)
            *pCertSigningKey = json_incref(pKey);

        json_decref(pKey);
        pKey = json_incref(cert->Payload);
    }

cleanup:
    switch (err) {
    case BID_S_ASSERTION_NOT_YET_VALID:
        err = BID_S_CERT_NOT_YET_VALID;
        break;
    case BID_S_EXPIRED_ASSERTION:
        err = BID_S_EXPIRED_CERT;
        break;
    default:
        break;
    }

    _BIDReleaseAuthority(context, authority);
    json_decref(rootKey);

    return err;
}

/*
 * Local verifier. This code path is used in the following cases:
 *
 * (1) Verifying an assertion from the initiator
 *     (a) Using certificate from backed assertion
 *     (b) Using symmetric ticket key (ARK)
 *     (c) Using embedded X.509 certificate (not tested)
 *
 * (2) Verifying the RP response token from the acceptor
 *     (a) Using session subkey (RRK)
 *     (b) Using acceptor X.509 certificate
 *     (c) Using JSON certificate from backed assertion (not tested)
 *
 * When making changes to this function, be careful that all the
 * paths above still work.
 *
 * In case (1)(b), BID_VERIFY_FLAG_REAUTH will be set on input.
 * In case (2), BID_VERIFY_FLAG_RP will always be set on input.
 */
BIDError
_BIDVerifyLocal(
    BIDContext context,
    BIDReplayCache replayCache,
    BIDBackedAssertion backedAssertion,
    const char *szAudience,
    const char *szSubjectName,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDJWK verifyCred,
    json_t *certAnchors,
    BIDIdentity *pVerifiedIdentity,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDIdentity verifiedIdentity = BID_C_NO_IDENTITY;
    json_t *x509Certificate = NULL;
    BIDJWKSet certSigningKey = NULL;
    json_t *attrCertClaims = NULL;

    if (pVerifiedIdentity != NULL)
        *pVerifiedIdentity = BID_C_NO_IDENTITY;
    *pulRetFlags = 0;

    BID_CONTEXT_VALIDATE(context);

    BID_ASSERT(backedAssertion->Assertion != NULL);
    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);
    BID_ASSERT((ulReqFlags & BID_VERIFY_FLAG_RP) || szSubjectName == NULL);

    if ((ulReqFlags & BID_VERIFY_FLAG_REAUTH) &&
        (context->ContextOptions & BID_CONTEXT_REAUTH) == 0)
        ulReqFlags &= ~(BID_VERIFY_FLAG_REAUTH);
    if (ulReqFlags & BID_VERIFY_FLAG_RP)
        *pulRetFlags |= BID_VERIFY_FLAG_RP;

    json_incref(verifyCred);

    if (backedAssertion->cCertificates == 0) {
        x509Certificate = json_object_get(backedAssertion->Assertion->Header, "x5c");

        if (x509Certificate != NULL) {
            /* Maybe it's an X.509 signed assertion */
            err = _BIDValidateX509(context, x509Certificate,
                                   certAnchors, verificationTime);
            BID_BAIL_ON_ERROR(err);

            verifyCred = json_incref(backedAssertion->Assertion->Header);
            *pulRetFlags |= BID_VERIFY_FLAG_X509 | BID_VERIFY_FLAG_VALIDATED_CERTS;
        } else if (ulReqFlags & BID_VERIFY_FLAG_REAUTH) {
            BID_ASSERT(verifyCred == NULL);
            BID_ASSERT((ulReqFlags & BID_VERIFY_FLAG_RP) == 0);

            err = _BIDVerifyReauthAssertion(context, replayCache,
                                            backedAssertion, verificationTime,
                                            &verifiedIdentity, &verifyCred, pulRetFlags);
            BID_BAIL_ON_ERROR(err);
        } else if ((ulReqFlags & BID_VERIFY_FLAG_RP) == 0) {
            err = BID_S_INVALID_ASSERTION;
            goto cleanup;
        }
    }

    err = _BIDValidateAudience(context, backedAssertion, szAudience, pbChannelBindings, cbChannelBindings);
    BID_BAIL_ON_ERROR(err);

    err = _BIDValidateExpiry(context, verificationTime, backedAssertion->Assertion->Payload);
    BID_BAIL_ON_ERROR(err);

    /* Only allow one certificate for now */
    if (backedAssertion->cCertificates > 1) {
        err = BID_S_TOO_MANY_CERTS;
        goto cleanup;
    }

    if (backedAssertion->cCertificates > 0) {
        err = _BIDValidateCertIssuer(context, backedAssertion, verificationTime, ulReqFlags);
        BID_BAIL_ON_ERROR(err);

        err = _BIDValidateCertChain(context, backedAssertion, verificationTime, &certSigningKey);
        BID_BAIL_ON_ERROR(err);

        verifyCred = backedAssertion->rCertificates[backedAssertion->cCertificates - 1]->Payload;
        *pulRetFlags |= BID_VERIFY_FLAG_VALIDATED_CERTS;

        err = _BIDValidateAttributeCertificates(context, backedAssertion, verificationTime,
                                                ulReqFlags, certSigningKey, &attrCertClaims);
        BID_BAIL_ON_ERROR(err);
   }

    BID_ASSERT(verifyCred != NULL);

    err = _BIDVerifyAssertionSignature(context, backedAssertion, verifyCred);
    BID_BAIL_ON_ERROR(err);

    if (verifiedIdentity == BID_C_NO_IDENTITY) {
        err = _BIDPopulateIdentity(context, backedAssertion, *pulRetFlags, &verifiedIdentity);
        BID_BAIL_ON_ERROR(err);

        if (attrCertClaims != NULL) {
            if (ulReqFlags & BID_VERIFY_FLAG_FLATTEN_ATTR_CERTS)
                json_object_update(verifiedIdentity->Attributes, attrCertClaims);
            else
                json_object_set(verifiedIdentity->Attributes, "attr-certs", attrCertClaims);
            *pulRetFlags |= BID_VERIFY_FLAG_ATTRIBUTE_CERTS;
        }
    }

    if (*pulRetFlags & BID_VERIFY_FLAG_VALIDATED_CERTS) {
        err = _BIDValidateSubject(context, verifiedIdentity, szSubjectName, ulReqFlags);
        BID_BAIL_ON_ERROR(err);
    }

    if ((ulReqFlags & BID_VERIFY_FLAG_RP) == 0) {
        err = _BIDParseProtocolOpts(context,
                                    json_object_get(backedAssertion->Assertion->Payload, "opts"),
                                    pulRetFlags);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;
    if (pVerifiedIdentity != NULL)
        *pVerifiedIdentity = verifiedIdentity;

cleanup:
    if (err != BID_S_OK || pVerifiedIdentity == NULL)
        BIDReleaseIdentity(context, verifiedIdentity);
    json_decref(verifyCred);
    json_decref(certSigningKey);
    json_decref(attrCertClaims);

    return err;
}
