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

static BIDError
_BIDDeriveXRTKey(
    BIDContext context,
    BIDIdentity identity,
    json_t **pSignKey)
{
    BIDError err;
    unsigned char *pbSalt = NULL;
    size_t cbSalt = 0;
    unsigned char *pbXRTK = NULL;
    size_t cbXRTK = 0;
    BIDSecretHandle newCMK = NULL;
    json_t *signKey = NULL;
    json_t *sk = NULL;

    err = _BIDGetJsonBinaryValue(context, identity->PrivateAttributes, "jti", &pbSalt, &cbSalt);
    BID_BAIL_ON_ERROR(err);

    err = _BIDIdentitySecretAgreement(context, identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, identity->SecretHandle, pbSalt, cbSalt, &pbXRTK, &cbXRTK);
    BID_BAIL_ON_ERROR(err);

    err = _BIDImportSecretKeyData(context, pbXRTK, cbXRTK, &newCMK);
    BID_BAIL_ON_ERROR(err);

    signKey = json_object();
    if (signKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonBinaryValue(context, pbXRTK, cbXRTK, &sk);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, signKey, "secret-key", sk, 0);
    BID_BAIL_ON_ERROR(err);

    _BIDDestroySecret(context, identity->SecretHandle);
    identity->SecretHandle = newCMK;

    err = BID_S_OK;
    *pSignKey = signKey;

cleanup:
    BIDFree(pbSalt);
    if (pbXRTK != NULL) {
        memset(pbXRTK, 0, cbXRTK);
        BIDFree(pbXRTK);
    }
    json_decref(sk);
    if (err != BID_S_OK) {
        _BIDDestroySecret(context, newCMK);
        json_decref(signKey);
    }

    return err;
}

/*
 * A token sent by the initiator indicating that it shares a session key with
 * the acceptor.
 */
BIDError
BIDMakeXRTToken(
    BIDContext context,
    BIDIdentity identity,
    json_t *additionalClaims,
    uint32_t ulReqFlags BID_UNUSED,
    char **pszResponseToken,
    size_t *pchResponseToken,
    uint32_t *pulRetFlags)
{
    BIDError err;
    struct BIDJWTDesc jwt = { 0 };
    struct BIDBackedAssertionDesc backedAssertion = { 0 };
    BIDJWK key = NULL;
    json_t *payload = NULL;

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_USER_AGENT);

    *pszResponseToken = NULL;
    *pchResponseToken = 0;
    *pulRetFlags = 0;

    payload = additionalClaims ? json_copy(additionalClaims) : json_object();
    if (payload == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDDeriveXRTKey(context, identity, &key);
    BID_BAIL_ON_ERROR(err);

    jwt.EncData = NULL;
    jwt.EncDataLength = 0;
    jwt.Header = NULL;
    jwt.Payload = json_incref(payload);
    jwt.Signature = NULL;
    jwt.SignatureLength = 0;

    backedAssertion.Assertion = &jwt;
    backedAssertion.cCertificates = 0;

    err = _BIDPackBackedAssertion(context, &backedAssertion, key, NULL, pszResponseToken);
    BID_BAIL_ON_ERROR(err);

    *pchResponseToken = strlen(*pszResponseToken);

cleanup:
    json_decref(payload);
    json_decref(key);
    _BIDReleaseJWTInternal(context, &jwt, 0);

    return err;
}

BIDError
BIDVerifyXRTToken(
    BIDContext context,
    BIDIdentity identity,
    const char *szAssertion,
    uint32_t ulReqFlags BID_UNUSED,
    json_t **pPayload,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDJWK verifyCred = NULL;
    BIDBackedAssertion backedAssertion = NULL;

    *pulRetFlags = 0;

    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    if (backedAssertion->cCertificates != 0) {
        err = BID_S_TOO_MANY_CERTS;
        goto cleanup;
    }

    err = _BIDDeriveXRTKey(context, identity, &verifyCred);
    BID_BAIL_ON_ERROR(err);

    err = _BIDVerifySignature(context, backedAssertion->Assertion, verifyCred);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (backedAssertion != NULL && pPayload != NULL)
        *pPayload = json_incref(backedAssertion->Assertion->Payload);

    _BIDReleaseBackedAssertion(context, backedAssertion);
    json_decref(verifyCred);

    return err;
}
