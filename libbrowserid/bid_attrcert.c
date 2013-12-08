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
 * Support for selectively disclosed attribute certificates. These are encoded
 * as IdP-signed JWTs in the submitted assertion.
 */

static const char *
_BIDReservedClaims[] = {
    "aud",
    "cb",
    "dn",
    "exp",
    "iat",
    "id",
    "iss",
    "jti",
    "nbf",
    "principal",
    "public-key",
    "sub"
};

static BIDError
_BIDValidateAttributeCertificate(
    BIDContext context,
    json_t *attrCert,
    time_t verificationTime,
    BIDJWKSet certVerifyKey,
    json_t *certHash,
    json_t *certIssuer,
    json_t **pClaims)
{
    BIDError err;
    BIDJWT attrCertJWT = NULL;
    json_t *certBinding = NULL;
    json_t *claims = NULL;
    json_t *iss = NULL;
    size_t i;

    *pClaims = NULL;

    if (!json_is_string(attrCert)) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    err = _BIDParseJWT(context, json_string_value(attrCert), &attrCertJWT);
    BID_BAIL_ON_ERROR(err);

    if (json_object_get(attrCertJWT->Payload, "exp") != NULL) {
        /* Inherit certificate expirty time unless explicitly specified */
        err = _BIDValidateExpiry(context, verificationTime, attrCertJWT->Payload);
        BID_BAIL_ON_ERROR(err);
    }

    iss = json_object_get(attrCertJWT->Payload, "iss");
    if (iss != NULL && !json_equal(iss, certIssuer)) {
        /* Attribute certificate must be issued by same party at present */
        err = BID_S_INVALID_ISSUER;
        goto cleanup;
    }

    err = _BIDVerifySignature(context, attrCertJWT, certVerifyKey);
    BID_BAIL_ON_ERROR(err);

    certBinding = json_object_get(attrCertJWT->Payload, "cb");
    if (certBinding == NULL) {
        err = BID_S_MISSING_CERT_BINDING;
        goto cleanup;
    }

    if (!json_equal(certHash, certBinding)) {
        err = BID_S_CERT_BINDING_MISMATCH;
        goto cleanup;
    }

    claims = json_copy(attrCertJWT->Payload);

    /*
     * Because we flatten the attributes in the top-level certificate, avoid
     * stomping on any well known names. We should probably revisit this, it
     * is pretty ugly.
     */
    for (i = 0; i < sizeof(_BIDReservedClaims) / sizeof(_BIDReservedClaims[0]); i++)
        _BIDJsonObjectDel(context, claims, _BIDReservedClaims[i], 0);

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

    _BIDReleaseJWT(context, attrCertJWT);
    json_decref(claims);

    return err;
}

BIDError
_BIDValidateAttributeCertificates(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime,
    BIDJWKSet certVerifyKey,
    json_t **pAllAttrCertClaims)
{
    BIDError err;
    json_t *attrCerts, *allAttrCertClaims = NULL;
    BIDJWT leafCert;
    unsigned char hash[32];
    size_t cbHash = sizeof(hash);
    json_t *certHash = NULL;
    json_t *iss = NULL;
    size_t i, cAttrCerts;

    *pAllAttrCertClaims = NULL;

    attrCerts = json_object_get(backedAssertion->Assertion->Payload, "attr-certs");
    if (attrCerts == NULL) {
        err = BID_S_OK;
        goto cleanup;
    }

    /*
     * attrCerts is an array of string JWTs signed in the IdP's public key.
     */
    if (!json_is_array(attrCerts)) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    cAttrCerts = json_array_size(attrCerts);
    if (cAttrCerts == 0) {
        err = BID_S_OK;;
        goto cleanup;
    }

    leafCert = backedAssertion->rCertificates[backedAssertion->cCertificates - 1];

    iss = json_object_get(leafCert->Payload, "iss");
    BID_ASSERT(iss != NULL);

    err = _BIDDigestAssertion(context, leafCert->EncData, hash, &cbHash);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonBinaryValue(context, hash, cbHash, &certHash);
    BID_BAIL_ON_ERROR(err);

    allAttrCertClaims = json_object();
    if (allAttrCertClaims == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    for (i = 0; i < cAttrCerts; i++) {
        json_t *attrCert = json_array_get(attrCerts, i);
        json_t *attrCertClaims = NULL;

        /* Currently, we just ignore attributes we cannot validate */
        err = _BIDValidateAttributeCertificate(context, attrCert, verificationTime,
                                               certVerifyKey, certHash, iss,
                                               &attrCertClaims);
        if (err != BID_S_OK)
            continue;

        json_object_update(allAttrCertClaims, attrCertClaims);
        json_decref(attrCertClaims);
    }

    err = BID_S_OK;
    *pAllAttrCertClaims = json_incref(allAttrCertClaims);

cleanup:
    json_decref(certHash);
    json_decref(allAttrCertClaims);

    return err;
}
