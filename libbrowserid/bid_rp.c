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
    struct BIDJWTDesc jwt = { 0 };
    struct BIDBackedAssertionDesc backedAssertion = { 0 };
    BIDJWK key = NULL;
    json_t *payload = NULL;
    json_t *certChain = NULL;
    json_t *dh = NULL;
    json_t *ticket = NULL;
    json_t *jti = NULL;
    uint32_t ulProtoOpts = 0;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_RP);

    *pszResponseToken = NULL;
    *pchResponseToken = 0;
    *pulRetFlags = 0;

    payload = additionalClaims ? json_copy(additionalClaims) : json_object();
    if (payload == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY) {
        if (ulReqFlags & BID_RP_FLAG_INITIAL) {
            err = _BIDGetKeyAgreementPublicValue(context, identity, &dh);
            BID_BAIL_ON_ERROR(err);

            err = _BIDSetKeyAgreementObject(context, payload, dh);
            BID_BAIL_ON_ERROR(err);
        }

        if (_BIDGetIdentityReauthTicket(context, identity, &ticket) == BID_S_OK) {
            err = _BIDJsonObjectSet(context, payload, "tkt", ticket, BID_JSON_FLAG_CONSUME_REF);
            BID_BAIL_ON_ERROR(err);
        }
    }

    if (identity != NULL && json_object_size(identity->PrivateAttributes)) {
        err = _BIDParseProtocolOpts(context,
                                    json_object_get(identity->PrivateAttributes, "opts"),
                                    &ulProtoOpts);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_NO_KEY;
    if ((ulReqFlags & BID_RP_FLAG_INITIAL) &&
        (ulProtoOpts & BID_VERIFY_FLAG_MUTUAL_AUTH)) {
        err = _BIDGetRPPrivateKey(context, &key, &certChain);
        if (err == BID_S_OK)
            *pulRetFlags |= BID_RP_FLAG_X509;
    }
    if (err != BID_S_OK &&
        (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY)) {
        err = _BIDDeriveSessionSubkey(context, identity, "RRK", &key);
        BID_BAIL_ON_ERROR(err);
    }

    /*
     * Echo back nonce to initiator if we are doing mutual authentication
     * with certificates.
     *
     * Only do this if we are actually signing a valid payload (this is to
     * make NegoEx certificate advertisement work).
     */
    if (identity != NULL && json_object_size(identity->PrivateAttributes)) {
        if ((ulReqFlags & BID_RP_FLAG_FORCE_EXTRA_ROUND_TRIP) ||
            (ulProtoOpts & BID_VERIFY_FLAG_EXTRA_ROUND_TRIP)) {
            err = _BIDGenerateNonce(context, &jti);
            BID_BAIL_ON_ERROR(err);

            err = _BIDJsonObjectSet(context, payload, "jti", jti, 0);
            BID_BAIL_ON_ERROR(err);

            err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "jti", jti, 0);
            BID_BAIL_ON_ERROR(err);
        }

        if (*pulRetFlags & BID_RP_FLAG_X509) {
            err = _BIDJsonObjectSet(context, payload, "nonce",
                                    json_object_get(identity->PrivateAttributes, "nonce"),
                                    BID_JSON_FLAG_REQUIRED);
            if (err == BID_S_UNKNOWN_JSON_KEY)
                err = BID_S_MISSING_NONCE;
            BID_BAIL_ON_ERROR(err);
        }
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
    json_decref(dh);
    json_decref(ticket);
    json_decref(jti);
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
    json_t *certParams;
    json_t *jti;
    uint32_t ulVerifyReqFlags = 0;
    uint32_t ulVerifyRetFlags = 0;

    *pulRetFlags = 0;

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetKeyAgreementObject(context, backedAssertion->Assertion->Payload, &dh);
    if (err == BID_S_OK) {
        err = _BIDSetKeyAgreementPublicValue(context, identity, dh);
        BID_BAIL_ON_ERROR(err);
    }

    if (ulReqFlags & BID_RP_FLAG_HAVE_SESSION_KEY) {
        err = _BIDDeriveSessionSubkey(context, identity, "RRK", &verifyCred);
        BID_BAIL_ON_ERROR(err);
    }

    certParams = json_object_get(identity->PrivateAttributes, "anchors");

    ulVerifyReqFlags = BID_VERIFY_FLAG_RP;
    if ((ulReqFlags & BID_RP_FLAG_HOSTNAME_MATCH_OK) ||
        (context->ContextOptions & BID_CONTEXT_HOST_SPN_ALIAS))
        ulVerifyReqFlags |= BID_VERIFY_FLAG_HOSTNAME_MATCH_OK;

    err = _BIDVerifyLocal(context, NULL, backedAssertion, NULL, szAudienceName,
                          NULL, 0, time(NULL), ulVerifyReqFlags, verifyCred,
                          certParams, NULL, &ulVerifyRetFlags);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);

    if (json_object_get(backedAssertion->Assertion->Payload, "aud") != NULL) {
        /*
         * Check audience is absent to avoid reflection attacks.
         */
        err = BID_S_REFLECTED_RP_RESPONSE;
        goto cleanup;
    }

    if (ulVerifyRetFlags & BID_VERIFY_FLAG_VALIDATED_CERTS)
        *pulRetFlags |= BID_RP_FLAG_VALIDATED_CERTS;
    if (ulVerifyRetFlags & BID_VERIFY_FLAG_X509)
        *pulRetFlags |= BID_RP_FLAG_X509;

    if (*pulRetFlags & BID_RP_FLAG_VALIDATED_CERTS) {
        /*
         * When doing mutual authentication with certificates, the nonce must
         * match that asserted by the initiator, to guard against replayed response
         * assertions.
         */
        json_t *storedNonce   = json_object_get(identity->PrivateAttributes, "nonce");
        json_t *assertedNonce = json_object_get(backedAssertion->Assertion->Payload, "nonce");

        if (assertedNonce == NULL) {
            err = BID_S_MISSING_NONCE;
            goto cleanup;
        } else if (!json_equal(storedNonce, assertedNonce)) {
            err = BID_S_MISMATCHED_RP_RESPONSE;
            goto cleanup;
        }

        /*
         * Re-authentication responses must signed with the RRK, not a certificate.
         */
        if ((ulReqFlags & BID_RP_FLAG_INITIAL) == 0) {
            err = BID_S_MISMATCHED_RP_RESPONSE;
            goto cleanup;
        }
    }

    jti = json_object_get(backedAssertion->Assertion->Payload, "jti");
    if (jti != NULL) {
        err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "jti", jti, 0);
        BID_BAIL_ON_ERROR(err);

        /* indicate to the caller that the RP supported the XRT option */
        *pulRetFlags |= BID_RP_FLAG_EXTRA_ROUND_TRIP;
    }

cleanup:
    if (backedAssertion != NULL)
        *pPayload = json_incref(backedAssertion->Assertion->Payload);

    _BIDReleaseBackedAssertion(context, backedAssertion);
    json_decref(verifyCred);

    return err;
}
