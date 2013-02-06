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
    json_t *certParams;
    uint32_t ulVerifyReqFlags = 0;
    uint32_t ulVerifyRetFlags = 0;

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

    certParams = json_object_get(identity->PrivateAttributes, "anchors");

    ulVerifyReqFlags = BID_VERIFY_FLAG_RP;
    if (ulReqFlags & BID_RP_FLAG_HOSTNAME_MATCH_OK)
        ulVerifyReqFlags |= BID_VERIFY_FLAG_HOSTNAME_MATCH_OK;

    err = _BIDVerifyLocal(context, NULL, backedAssertion, NULL, szAudienceName,
                          NULL, 0, time(NULL), ulVerifyReqFlags, verifyCred,
                          certParams, NULL, &ulVerifyRetFlags);
    BID_BAIL_ON_ERROR(err);

    BID_ASSERT(backedAssertion->Assertion->Payload != NULL);

    if (ulVerifyRetFlags & BID_VERIFY_FLAG_VALIDATED_CERTS)
        *pulRetFlags |= BID_RP_FLAG_VALIDATED_CERTS;
    if (ulVerifyRetFlags & BID_VERIFY_FLAG_X509)
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
