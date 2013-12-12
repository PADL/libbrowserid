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

static BIDError
_BIDValidateAttributeCertificate(
    BIDContext context,
    json_t *encodedAttrCert,
    time_t verificationTime,
    BIDJWKSet certVerifyKey,
    json_t *certData,
    json_t *certIssuer,
    json_t **pScope,
    json_t **pClaims)
{
    BIDError err;
    BIDJWT attrCert = NULL;
    json_t *certBinding = NULL;
    json_t *iss = NULL;
    json_t *scope = NULL;
    json_t *claims = NULL;

    *pScope = NULL;
    *pClaims = NULL;

    if (!json_is_string(encodedAttrCert)) {
        err = BID_S_INVALID_ASSERTION;
        goto cleanup;
    }

    err = _BIDParseJWT(context, json_string_value(encodedAttrCert), &attrCert);
    BID_BAIL_ON_ERROR(err);

    if (json_object_get(attrCert->Payload, "exp") != NULL) {
        /* Inherit certificate expirty time unless explicitly specified */
        err = _BIDValidateExpiry(context, verificationTime, attrCert->Payload);
        BID_BAIL_ON_ERROR(err);
    }

    iss = json_object_get(attrCert->Payload, "iss");
    if (iss != NULL && !json_equal(iss, certIssuer)) {
        /* Attribute certificate must be issued by same party at present */
        err = BID_S_INVALID_ISSUER;
        goto cleanup;
    }

    scope = json_object_get(attrCert->Payload, "scope");
    if (!json_is_string(scope)) {
        err = BID_S_MISSING_SCOPE;
        goto cleanup;
    }

    err = _BIDVerifySignature(context, attrCert, certVerifyKey);
    BID_BAIL_ON_ERROR(err);

    certBinding = json_object_get(attrCert->Payload, "cdi");
    if (certBinding == NULL) {
        err = BID_S_MISSING_CERT_BINDING;
        goto cleanup;
    }

    err = _BIDVerifyDigest(context, certData, certBinding);
    BID_BAIL_ON_ERROR(err);

    err = _BIDFilterReservedClaims(context, attrCert->Payload, &claims);
    BID_BAIL_ON_ERROR(err);

    *pScope = json_incref(scope);
    *pClaims = claims;

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

    if (err != BID_S_OK)
        json_decref(claims);

    _BIDReleaseJWT(context, attrCert);

    return err;
}

static BIDError
_BIDAggregateAttributeCertificateClaims(
    BIDContext context,
    json_t *aggregateClaims,
    json_t *attrCertScope,
    json_t *attrCert,
    json_t *attrCertClaims)
{
    BIDError err;
    json_t *claimNames = NULL;
    json_t *claimSources = NULL;
    json_t *claimSource = NULL;
    void *iter = NULL;

    if (json_object_update(aggregateClaims, attrCertClaims) != 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    claimNames = json_incref(json_object_get(aggregateClaims, "_claim_names"));
    if (claimNames == NULL) {
        err = _BIDAllocJsonObject(context, &claimNames);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, aggregateClaims, "_claim_names",
                                claimNames, BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    for (iter = json_object_iter(attrCertClaims);
         iter != NULL;
         iter = json_object_iter_next(attrCertClaims, iter))
        json_object_set(claimNames, json_object_iter_key(iter), attrCertScope);

    claimSources = json_incref(json_object_get(aggregateClaims, "_claim_sources"));
    if (claimSources == NULL) {
        err = _BIDAllocJsonObject(context, &claimSources);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, aggregateClaims, "_claim_sources",
                                claimSources, BID_JSON_FLAG_REQUIRED);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDAllocJsonObject(context, &claimSource);
    BID_BAIL_ON_ERROR(err);

    json_object_set(claimSource, "JWT", attrCert);

    err = _BIDJsonObjectSet(context, claimSources, json_string_value(attrCertScope),
                             claimSource, BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(claimNames);
    json_decref(claimSources);
    json_decref(claimSource);

    return err;
}

BIDError
_BIDValidateAttributeCertificates(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDJWKSet certVerifyKey,
    json_t **pAllAttrCertClaims)
{
    BIDError err;
    json_t *attrCerts, *allAttrCertClaims = NULL;
    BIDJWT leafCert;
    json_t *iss = NULL;
    json_t *leafCertData = NULL;
    size_t i, cAttrCerts;

    *pAllAttrCertClaims = NULL;

    attrCerts = json_object_get(backedAssertion->Assertion->Payload, "attribute_certs");
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

    leafCertData = json_string(leafCert->EncData);
    if (leafCertData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDAllocJsonObject(context, &allAttrCertClaims);
    BID_BAIL_ON_ERROR(err);

    for (i = 0; i < cAttrCerts; i++) {
        json_t *attrCert = json_array_get(attrCerts, i);
        json_t *attrCertClaims = NULL;
        json_t *attrCertScope = NULL;

        /* Currently, we just ignore attributes we cannot validate */
        err = _BIDValidateAttributeCertificate(context, attrCert, verificationTime,
                                               certVerifyKey, leafCertData, iss,
                                               &attrCertScope, &attrCertClaims);
        if (err != BID_S_OK)
            continue;

        if (ulReqFlags & BID_VERIFY_FLAG_AGGREGATE_ATTR_CERTS) {
            err = _BIDAggregateAttributeCertificateClaims(context, allAttrCertClaims,
                                                          attrCertScope, attrCert, attrCertClaims);
            BID_BAIL_ON_ERROR(err);
        } else {
            if (json_object_get(allAttrCertClaims, json_string_value(attrCertScope)) != NULL) {
                err = BID_S_DUPLICATE_SCOPE;
                goto cleanup;
            }
            json_object_set(allAttrCertClaims, json_string_value(attrCertScope), attrCertClaims);
        }
        json_decref(attrCertClaims);
        json_decref(attrCertScope);
    }

    err = BID_S_OK;
    *pAllAttrCertClaims = json_incref(allAttrCertClaims);

cleanup:
    json_decref(leafCertData);
    json_decref(allAttrCertClaims);

    return err;
}
