/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#ifdef __APPLE__
#include <pwd.h>
#include <sys/stat.h>
#endif

/*
 * Fast reauthentication support
 */

BIDError
_BIDAcquireDefaultTicketCache(BIDContext context)
{
    BIDError err;
    char szFileName[PATH_MAX];

#ifdef __APPLE__
    struct passwd *pw, pwd;
    char pwbuf[BUFSIZ];
    struct stat sb;

    if (getpwuid_r(geteuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) < 0 ||
        pw == NULL ||
        pw->pw_dir == NULL) {
        err = BID_S_CACHE_OPEN_ERROR;
        goto cleanup;
    }

    snprintf(szFileName, sizeof(szFileName), "%s/Library/Caches/com.padl.gss.BrowserID", pw->pw_dir);

    if (stat(szFileName, &sb) < 0)
        mkdir(szFileName, 0700);

    snprintf(szFileName, sizeof(szFileName), "%s/Library/Caches/com.padl.gss.BrowserID/browserid.tickets.json", pw->pw_dir);
#else
    snprintf(szFileName, sizeof(szFileName), "/tmp/.browserid.tickets.%d.json", geteuid());
#endif

    err = _BIDAcquireCache(context, szFileName, &context->TicketCache);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}

static BIDError
_BIDMakeTicketCacheKey(
    BIDContext context,
    const char *szAudienceOrSpn,
    const char *szEmail,
    char **pszCacheKey)
{
    BIDError err;
    char *szCacheKey = NULL;

    *pszCacheKey = NULL;

#if 0
    size_t cchAudienceOrSpn;
    size_t cchEmail;
    char *p;

    if (szAudienceOrSpn == NULL || szEmail == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    cchEmail = strlen(szEmail);
    cchAudienceOrSpn = strlen(szAudienceOrSpn);

    p = szCacheKey = BIDMalloc(cchEmail + 1 + cchAudienceOrSpn + 1);
    if (szCacheKey == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    memcpy(p, szEmail, cchEmail);
    p += cchEmail;
    *p++ = ' ';
    memcpy(p, szAudienceOrSpn, cchAudienceOrSpn);
    p += cchAudienceOrSpn;
    *p++ = '\0';
#else
    if (szAudienceOrSpn == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    err = _BIDDuplicateString(context, szAudienceOrSpn, &szCacheKey);
    BID_BAIL_ON_ERROR(err);
#endif

    err = BID_S_OK;
    *pszCacheKey = szCacheKey;

cleanup:
    return err;
}

BIDError
_BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    json_t *ticket)
{
    BIDError err;
    json_t *cred = NULL;
    BIDJWK ark = NULL;
    const char *szEmail = NULL;
    char *szCacheKey = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (identity == BID_C_NO_IDENTITY ||
        szAudienceOrSpn == NULL ||
        ticket == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    if (context->TicketCache == NULL) {
        err = BID_S_NO_TICKET_CACHE;
        goto cleanup;
    }

    err = _BIDDeriveAuthenticatorRootKey(context, identity, &ark);
    BID_BAIL_ON_ERROR(err);

    cred = json_copy(identity->Attributes);
    if (cred == NULL                                ||
        json_object_set(cred, "ticket", ticket) < 0 ||
        json_object_set(cred, "r-ark", ark) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BIDGetIdentityEmail(context, identity, &szEmail);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeTicketCacheKey(context, szAudienceOrSpn, szEmail, &szCacheKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDSetCacheObject(context, context->TicketCache, szCacheKey, cred);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(cred);
    json_decref(ark);
    BIDFree(szCacheKey);

    return err;
}

BIDError
BIDStoreTicketInCache(
    BIDContext context,
    BIDIdentity identity,
    const char *szAudienceOrSpn,
    const char *szTicket)
{
    json_t *ticket = json_string(szTicket);
    BIDError err = _BIDStoreTicketInCache(context, identity, szAudienceOrSpn, ticket);

    json_decref(ticket);

    return err;
}

static BIDError
_BIDMakeAuthenticator(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    json_t *tkt,
    BIDJWT *pAuthenticator,
    time_t *pTimestamp)
{
    BIDError err;
    BIDJWT ap;
    json_t *ts = NULL;
    json_t *n = NULL;
    json_t *aud = NULL;
    json_t *cbt = NULL;

    *pAuthenticator = NULL;

    BID_CONTEXT_VALIDATE(context);

    if (tkt == NULL) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    *pTimestamp = time(NULL);
    ts = json_integer(*pTimestamp);
    if (ts == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDGenerateNonce(context, &n);
    BID_BAIL_ON_ERROR(err);

    aud = json_string(szAudienceOrSpn);
    if (aud == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (pbChannelBindings != NULL) {
        err = _BIDJsonBinaryValue(context, pbChannelBindings, cbChannelBindings, &cbt);
        BID_BAIL_ON_ERROR(err);
    }

    ap = BIDCalloc(1, sizeof(*ap));
    if (ap == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    ap->Payload = json_object();
    if (ap->Payload == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (       json_object_set(ap->Payload, "ts", ts) < 0          ||
               json_object_set(ap->Payload, "n", n) < 0            ||
               json_object_set(ap->Payload, "tkt", tkt) < 0        ||
               json_object_set(ap->Payload, "aud", aud) < 0        ||
        (cbt ? json_object_set(ap->Payload, "cbt", cbt) : 0) < 0) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    *pAuthenticator = ap;

cleanup:
    if (err != BID_S_OK)
        _BIDReleaseJWT(context, ap);
    json_decref(ts);
    json_decref(n);
    json_decref(aud);
    json_decref(cbt);

    return err;
}

static BIDError
_BIDMakeReauthIdentity(
    BIDContext context,
    json_t *cred,
    BIDJWT ap,
    BIDIdentity *pIdentity)
{
    BIDError err;
    BIDIdentity identity = BID_C_NO_IDENTITY;

    *pIdentity = NULL;

    identity = BIDCalloc(1, sizeof(*identity));
    if (identity == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    identity->Attributes = json_copy(cred);
    json_object_del(identity->Attributes, "ticket");
    json_object_del(identity->Attributes, "r-ark");

    err = _BIDDeriveAuthenticatorSessionKey(context, json_object_get(cred, "r-ark"), ap,
                                            &identity->SessionKey, &identity->SessionKeyLength);
    BID_BAIL_ON_ERROR(err);

    *pIdentity = identity;

cleanup:
    if (err != BID_S_OK)
        BIDReleaseIdentity(context, identity);

    return err;
}

/*
 * Try to make a reauthentication assertion.
 */
BIDError
_BIDGetReauthAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    const unsigned char *pbChannelBindings,
    size_t cbChannelBindings,
    char **pAssertion,
    BIDIdentity *pAssertedIdentity,
    time_t *ptExpiryTime)
{
    BIDError err;
    char *szCacheKey = NULL;
    json_t *cred = NULL;
    json_t *tkt = NULL;
    BIDJWT ap = NULL;
    struct BIDBackedAssertionDesc backedAssertion = { 0 };
    time_t ts = 0;

    BID_CONTEXT_VALIDATE(context);
    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REAUTH);

    *pAssertion = NULL;
    *pAssertedIdentity = NULL;
    *ptExpiryTime = 0;

    err = _BIDMakeTicketCacheKey(context, szAudienceOrSpn, NULL, &szCacheKey);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCacheObject(context, context->TicketCache, szCacheKey, &cred);
    BID_BAIL_ON_ERROR(err);

    tkt = json_object_get(cred, "ticket");
    if (tkt == NULL) {
        err = BID_S_BAD_TICKET_CACHE;
        goto cleanup;
    }

    err = _BIDMakeAuthenticator(context, szAudienceOrSpn, pbChannelBindings, cbChannelBindings, tkt, &ap, &ts);
    BID_BAIL_ON_ERROR(err);

    backedAssertion.Assertion = ap;
    backedAssertion.cCertificates = 0;
    backedAssertion.Claims = NULL;

    err = _BIDPackBackedAssertion(context, &backedAssertion, json_object_get(cred, "r-ark"), pAssertion);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeReauthIdentity(context, cred, ap, pAssertedIdentity);
    BID_BAIL_ON_ERROR(err);

    /* Guess, we will update this later. */
    *ptExpiryTime = ts + context->TicketLifetime;

cleanup:
    BIDFree(szCacheKey);
    json_decref(cred);
    _BIDReleaseJWT(context, ap);

    return err;
}

BIDError
_BIDVerifyReauthAssertion(
    BIDContext context,
    BIDBackedAssertion assertion,
    BIDIdentity *pVerifiedIdentity,
    BIDJWK *pVerifierCred)
{
    BIDError err;
    BIDJWT ap = assertion->Assertion;
    const char *szTicket;
    json_t *cred = NULL;

    *pVerifiedIdentity = BID_C_NO_IDENTITY;
    *pVerifierCred = NULL;

    BID_CONTEXT_VALIDATE(context);

    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REPLAY_CACHE);
    BID_ASSERT(context->ContextOptions & BID_CONTEXT_REAUTH);
    BID_ASSERT(assertion->cCertificates == 0);

    szTicket = json_string_value(json_object_get(ap->Payload, "tkt"));

    err = _BIDGetCacheObject(context, context->ReplayCache, szTicket, &cred);
    if (err == BID_S_CACHE_KEY_NOT_FOUND)
        err = BID_S_INVALID_ASSERTION;
    BID_BAIL_ON_ERROR(err);

    *pVerifierCred = json_incref(json_object_get(cred, "r-ark"));

    err = _BIDVerifySignature(context, ap, *pVerifierCred);
    BID_BAIL_ON_ERROR(err);

    err = _BIDMakeReauthIdentity(context, cred, ap, pVerifiedIdentity);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(cred);

    return err;
}