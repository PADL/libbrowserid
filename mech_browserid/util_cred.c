/*
 * Copyright (c) 2011, JANET(UK)
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
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Utility routines for credential handles.
 */

#include "gssapiP_bid.h"

#ifdef WIN32
# include <shlobj.h>     /* may need to use ShFolder.h instead */
# include <stdio.h>
#else
# include <pwd.h>
#endif

OM_uint32
gssBidAllocCred(OM_uint32 *minor, gss_cred_id_t *pCred)
{
    OM_uint32 tmpMinor;
    gss_cred_id_t cred;

    *pCred = GSS_C_NO_CREDENTIAL;

    cred = (gss_cred_id_t)GSSBID_CALLOC(1, sizeof(*cred));
    if (cred == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSBID_MUTEX_INIT(&cred->mutex) != 0) {
        *minor = GSSBID_GET_LAST_ERROR();
        gssBidReleaseCred(&tmpMinor, &cred);
        return GSS_S_FAILURE;
    }

    *pCred = cred;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred)
{
    OM_uint32 tmpMinor;
    gss_cred_id_t cred = *pCred;
    krb5_context krbContext = NULL;

    if (cred == GSS_C_NO_CREDENTIAL) {
        return GSS_S_COMPLETE;
    }

    GSSBID_KRB_INIT(&krbContext);

    gssBidReleaseName(&tmpMinor, &cred->name);
    gssBidReleaseName(&tmpMinor, &cred->target);
    gss_release_buffer(&tmpMinor, &cred->assertion);

    GSSBID_MUTEX_DESTROY(&cred->mutex);
    memset(cred, 0, sizeof(*cred));
    GSSBID_FREE(cred);
    *pCred = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}

gss_OID
gssBidPrimaryMechForCred(gss_cred_id_t cred)
{
    gss_OID credMech = GSS_C_NO_OID;

    if (cred != GSS_C_NO_CREDENTIAL &&
        cred->mechanisms != GSS_C_NO_OID_SET &&
        cred->mechanisms->count == 1)
        credMech = &cred->mechanisms->elements[0];

    return credMech;
}

OM_uint32
gssBidAcquireCred(OM_uint32 *minor,
                  const gss_name_t desiredName,
                  OM_uint32 timeReq GSSBID_UNUSED,
                  const gss_OID_set desiredMechs,
                  int credUsage,
                  gss_cred_id_t *pCred,
                  gss_OID_set *pActualMechs,
                  OM_uint32 *timeRec)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t cred;

    /* XXX TODO validate with changed set_cred_option API */
    *pCred = GSS_C_NO_CREDENTIAL;

    major = gssBidAllocCred(minor, &cred);
    if (GSS_ERROR(major))
        goto cleanup;

    switch (credUsage) {
    case GSS_C_BOTH:
        cred->flags |= CRED_FLAG_INITIATE | CRED_FLAG_ACCEPT;
        break;
    case GSS_C_INITIATE:
        cred->flags |= CRED_FLAG_INITIATE;
        break;
    case GSS_C_ACCEPT:
        cred->flags |= CRED_FLAG_ACCEPT;
        break;
    default:
        major = GSS_S_FAILURE;
        *minor = GSSBID_BAD_USAGE;
        goto cleanup;
        break;
    }

    major = gssBidValidateMechs(minor, desiredMechs);
    if (GSS_ERROR(major))
        goto cleanup;

    major = duplicateOidSet(minor, desiredMechs, &cred->mechanisms);
    if (GSS_ERROR(major))
        goto cleanup;

    if (desiredName != GSS_C_NO_NAME) {
        GSSBID_MUTEX_LOCK(&desiredName->mutex);

        major = gssBidDuplicateName(minor, desiredName, &cred->name);
        if (GSS_ERROR(major)) {
            GSSBID_MUTEX_UNLOCK(&desiredName->mutex);
            goto cleanup;
        }

        GSSBID_MUTEX_UNLOCK(&desiredName->mutex);
    }

    if (pActualMechs != NULL) {
        major = duplicateOidSet(minor, cred->mechanisms, pActualMechs);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (timeRec != NULL)
        *timeRec = GSS_C_INDEFINITE;

    *pCred = cred;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        gssBidReleaseCred(&tmpMinor, &cred);

    return major;
}

/*
 * Return TRUE if cred available for mechanism. Caller need no acquire
 * lock because mechanisms list is immutable.
 */
int
gssBidCredAvailable(gss_cred_id_t cred, gss_OID mech)
{
    OM_uint32 minor;
    int present = 0;

    GSSBID_ASSERT(mech != GSS_C_NO_OID);

    if (cred == GSS_C_NO_CREDENTIAL || cred->mechanisms == GSS_C_NO_OID_SET)
        return TRUE;

    gss_test_oid_set_member(&minor, mech, cred->mechanisms, &present);

    return present;
}

OM_uint32
gssBidInquireCred(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_name_t *name,
                  OM_uint32 *pLifetime,
                  gss_cred_usage_t *cred_usage,
                  gss_OID_set *mechanisms)
{
    OM_uint32 major;
    time_t now, lifetime;

    if (name != NULL) {
        if (cred->name != GSS_C_NO_NAME) {
            major = gssBidDuplicateName(minor, cred->name, name);
            if (GSS_ERROR(major))
                goto cleanup;
        } else
            *name = GSS_C_NO_NAME;
    }

    if (cred_usage != NULL) {
        OM_uint32 flags = (cred->flags & (CRED_FLAG_INITIATE | CRED_FLAG_ACCEPT));

        switch (flags) {
        case CRED_FLAG_INITIATE:
            *cred_usage = GSS_C_INITIATE;
            break;
        case CRED_FLAG_ACCEPT:
            *cred_usage = GSS_C_ACCEPT;
            break;
        default:
            *cred_usage = GSS_C_BOTH;
            break;
        }
    }

    if (mechanisms != NULL) {
        if (cred->mechanisms != GSS_C_NO_OID_SET)
            major = duplicateOidSet(minor, cred->mechanisms, mechanisms);
        else
            major = gssBidIndicateMechs(minor, mechanisms);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (cred->expiryTime == 0) {
        lifetime = GSS_C_INDEFINITE;
    } else  {
        now = time(NULL);
        lifetime = now - cred->expiryTime;
        if (lifetime < 0)
            lifetime = 0;
    }

    if (pLifetime != NULL) {
        *pLifetime = lifetime;
    }

    if (lifetime == 0) {
        major = GSS_S_CREDENTIALS_EXPIRED;
        *minor = GSSBID_CRED_EXPIRED;
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

OM_uint32
gssBidSetCredAssertion(OM_uint32 *minor,
                      gss_cred_id_t cred,
                      const gss_buffer_t assertion)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc newAssertion = GSS_C_EMPTY_BUFFER;

    if (cred->flags & CRED_FLAG_RESOLVED) {
        major = GSS_S_FAILURE;
        *minor = GSSBID_CRED_RESOLVED;
        goto cleanup;
    }

    if (assertion != GSS_C_NO_BUFFER) {
        major = duplicateBuffer(minor, assertion, &newAssertion);
        if (GSS_ERROR(major))
            goto cleanup;

        cred->flags |= CRED_FLAG_ASSERTION;
    } else {
        cred->flags &= ~(CRED_FLAG_ASSERTION);
    }

    gss_release_buffer(&tmpMinor, &cred->assertion);
    cred->assertion = newAssertion;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

OM_uint32
gssBidSetCredService(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     const gss_name_t target)
{
    OM_uint32 major, tmpMinor;
    gss_name_t newTarget = GSS_C_NO_NAME;

    if (cred->flags & CRED_FLAG_RESOLVED) {
        major = GSS_S_FAILURE;
        *minor = GSSBID_CRED_RESOLVED;
        goto cleanup;
    }

    if (target != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, target, &newTarget);
        if (GSS_ERROR(major))
            goto cleanup;

        cred->flags |= CRED_FLAG_TARGET;
    } else {
        cred->flags &= ~(CRED_FLAG_TARGET);
    }

    gssBidReleaseName(&tmpMinor, &cred->target);
    cred->target = newTarget;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

static OM_uint32
gssBidDuplicateCred(OM_uint32 *minor,
                    const gss_cred_id_t src,
                    gss_cred_id_t *pDst)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t dst = GSS_C_NO_CREDENTIAL;

    *pDst = GSS_C_NO_CREDENTIAL;

    major = gssBidAllocCred(minor, &dst);
    if (GSS_ERROR(major))
        goto cleanup;

    dst->flags = src->flags;

    if (src->name != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, src->name, &dst->name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (src->target != GSS_C_NO_NAME) {
        major = gssBidDuplicateName(minor, src->target, &dst->target);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (src->assertion.value != NULL) {
        major = duplicateBuffer(minor, &src->assertion, &dst->assertion);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = duplicateOidSet(minor, src->mechanisms, &dst->mechanisms);
    if (GSS_ERROR(major))
        goto cleanup;

    dst->expiryTime = src->expiryTime;

    *pDst = dst;
    dst = GSS_C_NO_CREDENTIAL;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gssBidReleaseCred(&tmpMinor, &dst);

    return major;
}

OM_uint32
gssBidResolveInitiatorCred(OM_uint32 *minor,
                           const gss_cred_id_t cred,
                           gss_ctx_id_t ctx,
                           const gss_name_t targetName,
                           const gss_channel_bindings_t channelBindings,
                           gss_cred_id_t *pResolvedCred)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t resolvedCred = GSS_C_NO_CREDENTIAL;
    BIDError err;
    gss_buffer_desc bufAudienceOrSpn = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc bufEmail = GSS_C_EMPTY_BUFFER;
    gss_name_t identityName = GSS_C_NO_NAME;
    const unsigned char *pbChannelBindings = NULL;
    size_t cbChannelBindings = 0;
    char *szAssertion = NULL;

    *pResolvedCred = GSS_C_NO_CREDENTIAL;

    if (cred == GSS_C_NO_CREDENTIAL) {
        major = gssBidAcquireCred(minor,
                                  GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET,
                                  GSS_C_INITIATE,
                                  &resolvedCred,
                                  NULL,
                                  NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    } else {
        if ((cred->flags & CRED_FLAG_INITIATE) == 0) {
            major = GSS_S_NO_CRED;
            *minor = GSSBID_CRED_USAGE_MISMATCH;
            goto cleanup;
        }

        major = gssBidDuplicateCred(minor, cred, &resolvedCred);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    GSSBID_ASSERT((resolvedCred->assertion.length != 0) == (resolvedCred->flags & CRED_FLAG_RESOLVED) != 0);

    /* XXX API is not a good fit here, but we will rework later */
    if (resolvedCred->flags & CRED_FLAG_RESOLVED) {
        err = BIDAcquireAssertion(ctx->bidContext,
                                  (const char *)resolvedCred->assertion.value,
                                  &ctx->bidIdentity,
                                  &resolvedCred->expiryTime);
    } else {
        if (channelBindings != GSS_C_NO_CHANNEL_BINDINGS) {
            pbChannelBindings = (const unsigned char *)channelBindings->application_data.value;
            cbChannelBindings = channelBindings->application_data.length;
        }

        major = gssBidDisplayName(minor, targetName, &bufAudienceOrSpn, NULL);
        if (GSS_ERROR(major))
            goto cleanup;


        err = BIDAcquireAssertionInteractive(ctx->bidContext,
                                             (const char *)bufAudienceOrSpn.value,
                                             pbChannelBindings,
                                             cbChannelBindings,
                                             &szAssertion,
                                             &ctx->bidIdentity,
                                             &resolvedCred->expiryTime);
    }

    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    if (szAssertion != NULL) {
        major = makeStringBuffer(minor, szAssertion, &resolvedCred->assertion);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    err = BIDGetIdentityEmail(ctx->bidContext, ctx->bidIdentity, (const char **)&bufEmail.value);
    if (err != BID_S_OK) {
        major = gssBidMapError(minor, err);
        goto cleanup;
    }

    bufEmail.length = strlen((const char *)bufEmail.value);

    major = gssBidImportName(minor, &bufEmail, GSS_C_NT_USER_NAME, GSS_C_NULL_OID, &identityName);
    if (GSS_ERROR(major))
        goto cleanup;

    if (resolvedCred->name != GSS_C_NO_NAME) {
        int nameEqual;

        major = gssBidCompareName(minor, resolvedCred->name, identityName, 0, &nameEqual);
        if (GSS_ERROR(major))
            goto cleanup;

        if (!nameEqual) {
            major = GSS_S_NO_CRED;
            *minor = GSSBID_BAD_INITIATOR_NAME;
            goto cleanup;
        }
    } else {
        resolvedCred->name = identityName;
        identityName = GSS_C_NO_NAME;
    }

    resolvedCred->flags |= CRED_FLAG_RESOLVED;

    *pResolvedCred = resolvedCred;
    resolvedCred = GSS_C_NO_CREDENTIAL;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gssBidReleaseCred(&tmpMinor, &resolvedCred);
    gssBidReleaseName(&tmpMinor, &identityName);
    gss_release_buffer(&tmpMinor, &bufAudienceOrSpn);
    BIDFreeAssertion(ctx->bidContext, szAssertion);

    return major;
}