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
 * Support for selectively disclosed supplementary claims. These are encoded
 * as IdP-signed JWTs in the submitted assertion.
 */

static BIDError
_BIDValidateSupplementaryClaim(
    BIDContext context,
    json_t *suppCert,
    time_t verificationTime,
    BIDJWKSet certSigningKey,
    json_t *certHash,
    json_t **pClaims)
{
    BIDError err;
    BIDJWT suppCertJWT = NULL;
    json_t *certBinding = NULL;
    json_t *claims = NULL;

    *pClaims = NULL;

    if (!json_is_string(suppCert)) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    err = _BIDParseJWT(context, json_string_value(suppCert), &suppCertJWT);
    BID_BAIL_ON_ERROR(err);

    if (json_object_get(suppCertJWT->Payload, "exp") != NULL) {
        /* Inherit certificate expirty time unless explicitly specified */
        err = _BIDValidateExpiry(context, verificationTime, suppCertJWT->Payload);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDVerifySignature(context, suppCertJWT, certSigningKey);
    BID_BAIL_ON_ERROR(err);

    certBinding = json_object_get(suppCertJWT->Payload, "cb");
    if (certBinding == NULL) {
        err = BID_S_MISSING_CHANNEL_BINDINGS;
        goto cleanup;
    }

    if (!json_equal(certHash, certBinding)) {
        err = BID_S_CHANNEL_BINDINGS_MISMATCH;
        goto cleanup;
    }

    claims = json_copy(suppCertJWT->Payload);

    err = _BIDJsonObjectDel(context, claims, "cb", 0);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;
    *pClaims = json_incref(claims);

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

    _BIDReleaseJWT(context, suppCertJWT);
    json_decref(claims);

    return err;
}

BIDError
_BIDValidateSupplementaryClaims(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime,
    BIDJWKSet certSigningKey,
    json_t **pSuppClaims)
{
    BIDError err;
    json_t *suppCerts, *suppClaims = NULL;
    BIDJWT leafCert;
    unsigned char hash[32];
    size_t cbHash = sizeof(hash);
    json_t *certHash = NULL;
    size_t i, cSuppCerts;

    *pSuppClaims = NULL;

    suppCerts = json_object_get(backedAssertion->Assertion->Payload, "udc");
    if (suppCerts == NULL) {
        err = BID_S_OK;
        goto cleanup;
    }

    /*
     * suppCerts is an array of string JWTs signed in the IdP's public key.
     */
    if (!json_is_array(suppCerts)) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    cSuppCerts = json_array_size(suppCerts);
    if (cSuppCerts == 0) {
        err = BID_S_OK;;
        goto cleanup;
    }

    leafCert = backedAssertion->rCertificates[backedAssertion->cCertificates - 1];

    err = _BIDDigestAssertion(context, leafCert->EncData, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonBinaryValue(context, hash, cbHash, &certHash);
    BID_BAIL_ON_ERROR(err);

    suppClaims = json_object();
    if (suppClaims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 0; i < cSuppCerts; i++) {
        json_t *suppCert = json_array_get(suppCerts, i);
        json_t *suppCertClaims = NULL;

        err = _BIDValidateSupplementaryClaim(context, suppCert, verificationTime,
                                             certSigningKey, certHash, &suppCertClaims);
        BID_BAIL_ON_ERROR(err);

        json_object_update(suppClaims, suppCertClaims);
        json_decref(suppCertClaims);
    }

    err = BID_S_OK;
    *pSuppClaims = json_incref(suppClaims);

cleanup:
    json_decref(certHash);
    json_decref(suppClaims);

    return err;
}
