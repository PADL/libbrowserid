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

BIDError
BIDVerifyAssertion(
    BIDContext context,
    BIDReplayCache replayCache,
    const char *szAssertion,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    time_t verificationTime,
    uint32_t ulReqFlags,
    BIDIdentity *pVerifiedIdentity,
    time_t *pExpiryTime,
    uint32_t *pulRetFlags)
{
    BIDError err;
    BIDBackedAssertion backedAssertion = NULL;
    uint32_t ulRetFlags = 0;
    int bUseReplayCache;

    BID_CONTEXT_VALIDATE(context);

    *pVerifiedIdentity = BID_C_NO_IDENTITY;
    *pExpiryTime = 0;
    *pulRetFlags = 0;

    if (szAssertion == NULL)
        return BID_S_INVALID_PARAMETER;

    if ((context->ContextOptions & BID_CONTEXT_RP) == 0)
        return BID_S_INVALID_USAGE;

    if (replayCache == BID_C_NO_REPLAY_CACHE)
        replayCache = context->ReplayCache;

    /*
     * Split backed identity assertion out into
     * <cert-1>~...<cert-n>~<identityAssertion>
     */
    err = _BIDUnpackBackedAssertion(context, szAssertion, &backedAssertion);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_VERIFY_REMOTE)
        err = _BIDVerifyRemote(context, replayCache, backedAssertion, szAudienceOrSpn, NULL,
                               pbChannelBindings, cbChannelBindings, verificationTime, ulReqFlags,
                               pVerifiedIdentity, &ulRetFlags);
    else
        err = _BIDVerifyLocal(context, replayCache, backedAssertion, szAudienceOrSpn, NULL,
                              pbChannelBindings, cbChannelBindings, verificationTime, ulReqFlags,
                              NULL, NULL, pVerifiedIdentity, &ulRetFlags);
    BID_BAIL_ON_ERROR(err);

    bUseReplayCache =
        (ulRetFlags & BID_VERIFY_FLAG_EXTRA_ROUND_TRIP) == 0 &&
        (context->ContextOptions & BID_CONTEXT_REPLAY_CACHE);

    /* If we are doing an extra round trip, we can avoid checking the replay cache */
    if (bUseReplayCache && (ulReqFlags & BID_VERIFY_FLAG_NO_REPLAY_CACHE) == 0) {
        err = _BIDCheckReplayCache(context, replayCache, szAssertion, verificationTime);
        BID_BAIL_ON_ERROR(err);
    }

    if ((ulRetFlags & BID_VERIFY_FLAG_REAUTH) == 0 &&
        (context->ContextOptions & BID_CONTEXT_KEYEX_MASK)) {
        err = _BIDVerifierKeyAgreement(context, *pVerifiedIdentity);
        BID_BAIL_ON_ERROR(err);
    }

    if ((bUseReplayCache || (context->ContextOptions & BID_CONTEXT_REAUTH)) &&
        (ulReqFlags & BID_VERIFY_FLAG_NO_REPLAY_CACHE) == 0) {
        err = _BIDUpdateReplayCache(context, replayCache, *pVerifiedIdentity, szAssertion,
                                    verificationTime, ulRetFlags);
        BID_BAIL_ON_ERROR(err);
    }

    _BIDGetJsonTimestampValue(context, (*pVerifiedIdentity)->Attributes, "exp", pExpiryTime);

cleanup:
    _BIDReleaseBackedAssertion(context, backedAssertion);

    *pulRetFlags = ulRetFlags;
    return err;
}

void
_BIDFinalizeIdentity(BIDIdentity identity)
{
    json_decref(identity->Attributes);
    json_decref(identity->PrivateAttributes);
    _BIDDestroySecret(BID_C_NO_CONTEXT /* XXX */, identity->SecretHandle);
}

BIDError
BIDReleaseIdentity(
    BIDContext context,
    BIDIdentity identity)
{
    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY)
        return BID_S_INVALID_PARAMETER;

#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H
    CFRelease(identity);
#else
    _BIDFinalizeIdentity(identity);
    BIDFree(identity);
#endif

    return BID_S_OK;
}

BIDError
BIDGetIdentityAudience(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "aud", pValue);
}

BIDError
BIDGetIdentitySubject(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "sub", pValue);
}

BIDError
BIDGetIdentityIssuer(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    return BIDGetIdentityAttribute(context, identity, "iss", pValue);
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
_BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    json_t **pValue)
{
    BIDError err;
    json_t *value;

    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    value = json_object_get(identity->PrivateAttributes, "tkt");
    if (value == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    err = BID_S_OK;
    *pValue = json_incref(value);

cleanup:
    return err;
}

BIDError
BIDGetIdentityReauthTicket(
    BIDContext context,
    BIDIdentity identity,
    const char **pValue)
{
    BIDError err;
    json_t *value = NULL;

    *pValue = NULL;

    BID_CONTEXT_VALIDATE(context);

    err = _BIDGetIdentityReauthTicket(context, identity, &value);
    BID_BAIL_ON_ERROR(err);

    *pValue = json_string_value(value);
    if (*pValue == NULL) {
        err = BID_S_UNKNOWN_ATTRIBUTE;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    json_decref(value);

    return err;
}

BIDError
BIDIdentityDeriveKey(
    BIDContext context,
    BIDIdentity identity,
    const unsigned char *pbSalt,
    size_t cbSalt,
    unsigned char **ppbSessionKey,
    size_t *pcbSessionKey)
{
    BIDError err;

    *ppbSessionKey = NULL;
    *pcbSessionKey = 0;

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDIdentitySecretAgreement(context, identity);
    BID_BAIL_ON_ERROR(err);

    err = _BIDDeriveKey(context, identity->SecretHandle, pbSalt, cbSalt,
                        ppbSessionKey, pcbSessionKey);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

BIDError
BIDFreeIdentityDerivedKey(
    BIDContext context,
    BIDIdentity identity BID_UNUSED,
    unsigned char *pbSessionKey,
    size_t cbSessionKey)
{
    BIDError err;

    BID_CONTEXT_VALIDATE(context);

    if (pbSessionKey == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    memset(pbSessionKey, 0, cbSessionKey);
    BIDFree(pbSessionKey);

    err = BID_S_OK;

cleanup:
    return err;
}

BIDError
BIDGetIdentityExpiryTime(
    BIDContext context,
    BIDIdentity identity,
    time_t *value)
{

    if (identity == BID_C_NO_IDENTITY)
        return BID_S_INVALID_PARAMETER;

    return _BIDGetJsonTimestampValue(context, identity->Attributes, "exp", value);
}

BIDError
_BIDAllocIdentity(
    BIDContext context,
    json_t *attributes,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;

    *pIdentity = BID_C_NO_IDENTITY;

#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H
    identity = (BIDIdentity)_CFRuntimeCreateInstance(kCFAllocatorDefault, BIDIdentityGetTypeID(),
                                                     sizeof(*identity) - sizeof(CFRuntimeBase), NULL);
#else
    identity = BIDCalloc(1, sizeof(*identity));
#endif
    if (identity == BID_C_NO_IDENTITY) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (attributes != NULL)
        identity->Attributes = json_incref(attributes);
    else {
        identity->Attributes = json_object();
        if (identity->Attributes == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }
    }

    identity->PrivateAttributes = json_object();
    if (identity->PrivateAttributes == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BID_S_OK;
    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

BIDError
_BIDPopulateIdentity(
    BIDContext context,
    BIDBackedAssertion backedAssertion,
    uint32_t ulFlags,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;
    json_t *assertion = backedAssertion->Assertion->Payload;
    json_t *leafCert = _BIDLeafCert(context, backedAssertion);
    json_t *principal;
    json_t *dh = NULL;

    *pIdentity = BID_C_NO_IDENTITY;

    err = _BIDAllocIdentity(context, leafCert, &identity);
    BID_BAIL_ON_ERROR(err);

    if (ulFlags & BID_VERIFY_FLAG_X509) {
        err = _BIDPopulateX509Identity(context, backedAssertion, identity, ulFlags);
        BID_BAIL_ON_ERROR(err);

        leafCert = identity->Attributes;
    }

    if (ulFlags & BID_VERIFY_FLAG_RP) {
        err = BID_S_OK;
        goto cleanup;
    }

    principal = json_object_get(leafCert, "principal");
    if (principal == NULL ||
        json_object_get(principal, "email") == NULL) {
        err = BID_S_MISSING_PRINCIPAL;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, identity->Attributes, "sub",
                            json_object_get(principal, "email"), 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, identity->Attributes, "aud",
                            json_object_get(assertion, "aud"), 0);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_KEYEX_MASK) {
        json_t *params;

        err = _BIDGetKeyAgreementObject(context, backedAssertion->Assertion->Payload, &params);
        if (err == BID_S_OK) {
            dh = json_object();

            if (dh == NULL) {
                err = BID_S_NO_MEMORY;
                goto cleanup;
            }

            err = _BIDJsonObjectSet(context, dh, "params", params, 0);
            BID_BAIL_ON_ERROR(err);

            err = _BIDSetKeyAgreementObject(context, identity->PrivateAttributes, dh);
            BID_BAIL_ON_ERROR(err);
        }
    }

    /* Assertion expiry time, internal use only */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "a-exp",
                            json_object_get(assertion, "exp"), BID_JSON_FLAG_REQUIRED);
    BID_BAIL_ON_ERROR(err);

    /* Save optional nonce, internal use only */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "nonce",
                            json_object_get(assertion, "nonce"), 0);
    BID_BAIL_ON_ERROR(err);

    /* Save protocol options, internal use only */
    err = _BIDJsonObjectSet(context, identity->PrivateAttributes, "opts",
                            json_object_get(assertion, "opts"), 0);
    BID_BAIL_ON_ERROR(err);

    err = BID_S_OK;

cleanup:
    if (err == BID_S_OK)
        *pIdentity = identity;
    else
        BIDReleaseIdentity(context, identity);

    json_decref(dh);

    return err;
}

/*
 * If we are validating a hostname subject (as is the case with an
 * RP response assertion), then we can do a case-insensitive comparison
 * on the (hopefully ASCII) subject name.
 *
 * Otherwise, an exact match is required.
 */
static int
_BIDSubjectCompare(
    const char *a1,
    const char *a2,
    uint32_t ulReqFlags)
{
    int cmp;

    if (ulReqFlags & BID_VERIFY_FLAG_RP) {
        cmp = strcasecmp(a1, a2);
    } else {
        cmp = strcmp(a1, a2);
    }

    return cmp;
}

static int
_BIDSubjectEqualP(
    json_t *assertedSubject,
    const char *szSubject,
    uint32_t ulReqFlags)
{
    int cmp = -1;

    if (json_is_string(assertedSubject)) {
        cmp = _BIDSubjectCompare(json_string_value(assertedSubject), szSubject, ulReqFlags);
    } else if (json_is_array(assertedSubject)) {
        size_t i;

        for (i = 0; i < json_array_size(assertedSubject); i++) {
            json_t *sub = json_array_get(assertedSubject, i);

            if (!json_is_string(sub))
                continue;

            cmp = _BIDSubjectCompare(json_string_value(sub), szSubject, ulReqFlags);
            if (cmp == 0)
                break;
        }
    }

    return (cmp == 0);
}

/*
 * XXX this transformation is incomplete as it does not handle
 * differences between IANA Assigned Numbers and GSS/SASL service
 * name registries, nor does it handle domain-based service names.
 */
static int
_BIDSRVNameEqualP(
    const char *szSRVName,
    const char *szSubjectName)
{
    const char *p, *q;
    int cmp;
    size_t n;

    if (szSRVName == NULL || szSRVName[0] != '_')
        return 0;

    p = strchr(&szSRVName[1], '.');
    q = strchr(szSubjectName, '/');

    if (p == NULL || q == NULL)
        return 0;

    n = (p - szSRVName) - 1;

    if (n != (q - szSubjectName))
        return 0;

    cmp = strncasecmp(&szSRVName[1], szSubjectName, n);
    /* XXX this does terminate the comparison at service-specifics */
    if (cmp == 0)
        cmp = _BIDSubjectCompare(p + 1, q + 1, BID_VERIFY_FLAG_RP);

    return (cmp == 0);
}

/*
 * Match a RFC 4985 service name against a GSS service principal name.
 */
static int
_BIDOtherNameEqualP(
    json_t *assertedOtherName,
    const char *szSubjectName)
{
    int bMatched = 0, i;

    if (!json_is_array(assertedOtherName))
        return 0;

    for (i = 0; i < json_array_size(assertedOtherName); i++) {
        json_t *otherName = json_array_get(assertedOtherName, i);
        json_t *oid = json_object_get(otherName, "oid");
        json_t *srv = json_object_get(otherName, "value");

        /* Only the dnsSRV (RFC 4985) OtherName type is supported so far */
        if (oid == NULL ||
            strcmp(json_string_value(oid), BID_OID_PKIX_ON_DNSSRV) != 0)
            continue;

        if (!json_is_string(srv))
            continue;

        if (_BIDSRVNameEqualP(json_string_value(srv), szSubjectName)) {
            bMatched++;
            break;
        }
    }

    return bMatched;
}

static struct {
    const char *szOid;
    const char *szServiceName;
    size_t cchServiceName;
} _BIDEKUMap[] = {
    { BID_OID_PKIX_KP_SERVER_AUTH,          "http/",    sizeof("http/") - 1 },
};

static int
_BIDEKUIsPresentP(
    BIDContext context BID_UNUSED,
    json_t *eku,
    const char *szDesiredOid)
{
    size_t i;

    BID_ASSERT(eku != NULL);

    for (i = 0; i < json_array_size(eku); i++) {
        json_t *oid = json_array_get(eku, i);
        const char *szOid;

        szOid = json_string_value(oid);
        if (szOid == NULL)
            continue;

        if (strcmp(szOid, szDesiredOid) == 0)
            return 1;
    }

    return 0;
}

static BIDError
_BIDValidateEKUs(
    BIDContext context,
    BIDIdentity identity,
    const char *szSubjectName,
    uint32_t ulReqFlags BID_UNUSED)
{
    json_t *eku;
    int valid = 0;

    eku = json_object_get(identity->Attributes, "eku");
    if (eku == NULL ||
        (json_array_size(eku) == 1 &&
         _BIDEKUIsPresentP(context, eku, BID_OID_ANY_ENHANCED_KEY_USAGE))) {
        /* No EKU or any EKU OID is present */
        valid++;
    } else {
        if (context->ContextOptions & BID_CONTEXT_GSS) {
            size_t i;
            int cmp;

            for (i = 0; i < sizeof(_BIDEKUMap) / sizeof(_BIDEKUMap[0]); i++) {
                cmp = strncasecmp(szSubjectName,
                                  _BIDEKUMap[i].szServiceName, _BIDEKUMap[i].cchServiceName);
                if (cmp == 0) {
                    valid++;
                    break;
                }
            }
        } else {
            /* For HTTP, just check for serverAuth EKU */
            valid = _BIDEKUIsPresentP(context, eku, BID_OID_PKIX_KP_SERVER_AUTH);
        }
    }

    return valid ? BID_S_OK : BID_S_BAD_SUBJECT;
}

BIDError
_BIDValidateSubject(
    BIDContext context BID_UNUSED,
    BIDIdentity identity,
    const char *szSubjectName,
    uint32_t ulReqFlags)
{
    BIDError err;
    char *szHostnameAudience = NULL;
    const char *p = NULL;
    json_t *assertedPrincipal = NULL;
    json_t *assertedPrincipalValue = NULL;
    json_t *assertedSubject = NULL;
    int bMatchedSubject = 0;
    int bMatchedServiceName = 0;

    BID_ASSERT(identity != BID_C_NO_IDENTITY);

    if (szSubjectName == NULL) {
        err = BID_S_OK;
        bMatchedSubject++;
        goto cleanup;
    }

    assertedPrincipal = json_object_get(identity->Attributes, "principal");
    if (assertedPrincipal == NULL) {
        err = BID_S_MISSING_PRINCIPAL;
        goto cleanup;
    }

    /*
     * BID_VERIFY_FLAG_RP denotes that we are verifying a server
     * (acceptor) rather than client certificate.
     */
    if (ulReqFlags & BID_VERIFY_FLAG_RP) {
        json_t *assertedOtherName;

        if (context->ContextOptions & BID_CONTEXT_GSS) {
            err = _BIDHostifySpn(context, szSubjectName, &szHostnameAudience);
            BID_BAIL_ON_ERROR(err);

            BID_ASSERT(strncmp(szHostnameAudience, "host/", 5) == 0);

            p = &szHostnameAudience[5];
        } else {
            if (strncmp(szSubjectName, "http://", 7) == 0)
                p = &szSubjectName[7];
            else if (strncmp(szSubjectName, "https://", 8) == 0)
                p = &szSubjectName[8];
            else {
                err = BID_S_BAD_AUDIENCE;
                goto cleanup;
            }
        }

        assertedOtherName = json_object_get(assertedPrincipal, "othername");
        if (_BIDOtherNameEqualP(assertedOtherName, szSubjectName)) {
            bMatchedSubject++;
            bMatchedServiceName++;
        } else if (assertedOtherName != NULL) {
            /* If an OtherName SAN was present, we require a match. */
            err = BID_S_BAD_SUBJECT;
            goto cleanup;
        }

        assertedPrincipalValue = json_object_get(assertedPrincipal, "hostname");
    } else {
        assertedPrincipalValue = json_object_get(assertedPrincipal, "email");
        p = szSubjectName;
    }

    BID_ASSERT(p != NULL);

    if (_BIDSubjectEqualP(assertedPrincipalValue, p, ulReqFlags))
        bMatchedSubject++;

    assertedSubject = json_object_get(identity->Attributes, "sub");
    if (_BIDSubjectEqualP(assertedSubject, p, ulReqFlags))
        bMatchedSubject++;

    if (bMatchedSubject && (ulReqFlags & BID_VERIFY_FLAG_RP) &&
        bMatchedServiceName == 0) {
        err = _BIDValidateEKUs(context, identity, szSubjectName, ulReqFlags);
        BID_BAIL_ON_ERROR(err);
    }

    err = BID_S_OK;

cleanup:
    /*
     * If there was no error otherwise, but we didn't match the subject,
     * return BAD_SUBJECT.
     */
    if (err == BID_S_OK && bMatchedSubject == 0)
        err = BID_S_BAD_SUBJECT;

    BIDFree(szHostnameAudience);

    return err;
}
