/*
 * Copyright (c) 2010, JANET(UK)
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

#include "gssapiP_eap.h"

OM_uint32
gssEapAllocCred(OM_uint32 *minor, gss_cred_id_t *pCred)
{
    OM_uint32 tmpMinor;
    gss_cred_id_t cred;

    *pCred = GSS_C_NO_CREDENTIAL;

    cred = (gss_cred_id_t)GSSEAP_CALLOC(1, sizeof(*cred));
    if (cred == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    if (GSSEAP_MUTEX_INIT(&cred->mutex) != 0) {
        *minor = errno;
        gssEapReleaseCred(&tmpMinor, &cred);
        return GSS_S_FAILURE;
    }

    *pCred = cred;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred)
{
    OM_uint32 tmpMinor;
    gss_cred_id_t cred = *pCred;

    if (cred == GSS_C_NO_CREDENTIAL) {
        return GSS_S_COMPLETE;
    }

    gssEapReleaseName(&tmpMinor, &cred->name);

    if (cred->password.value != NULL) {
        memset(cred->password.value, 0, cred->password.length);
        GSSEAP_FREE(cred->password.value);
    }

    GSSEAP_MUTEX_DESTROY(&cred->mutex);
    memset(cred, 0, sizeof(*cred));
    GSSEAP_FREE(cred);
    *pCred = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapAcquireCred(OM_uint32 *minor,
                  const gss_name_t desiredName,
                  const gss_buffer_t password,
                  OM_uint32 timeReq,
                  const gss_OID_set desiredMechs,
                  int credUsage,
                  gss_cred_id_t *pCred,
                  gss_OID_set *pActualMechs,
                  OM_uint32 *timeRec)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t cred;

    *pCred = GSS_C_NO_CREDENTIAL;

    major = gssEapAllocCred(minor, &cred);
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
        goto cleanup;
        break;
    }

    if (desiredName != GSS_C_NO_NAME) {
        major = gss_duplicate_name(minor, desiredName, &cred->name);
        if (GSS_ERROR(major))
            goto cleanup;
    } else {
        if (cred->flags & CRED_FLAG_INITIATE) {
            gss_buffer_desc buf;

            buf.value = getlogin(); /* XXX */
            buf.length = strlen((char *)buf.value);

            major = gss_import_name(minor, &buf,
                                    GSS_C_NT_USER_NAME, &cred->name);
            if (GSS_ERROR(major))
                goto cleanup;
        }

        cred->flags |= CRED_FLAG_DEFAULT_IDENTITY;
    }

    if (password != GSS_C_NO_BUFFER) {
        major = duplicateBuffer(minor, password, &cred->password);
        if (GSS_ERROR(major))
            goto cleanup;

        cred->flags |= CRED_FLAG_PASSWORD;
    }

    major = gssEapValidateMechs(minor, desiredMechs);
    if (GSS_ERROR(major))
        goto cleanup;

    major = duplicateOidSet(minor, desiredMechs, &cred->mechanisms);
    if (GSS_ERROR(major))
        goto cleanup;

    if (pActualMechs != NULL) {
        major = duplicateOidSet(minor, cred->mechanisms, pActualMechs);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (timeRec != NULL)
        *timeRec = GSS_C_INDEFINITE;

    *pCred = cred;
    major = GSS_S_COMPLETE;

cleanup:
    if (GSS_ERROR(major))
        gssEapReleaseCred(&tmpMinor, &cred);

    return major;
}

int
gssEapCredAvailable(gss_cred_id_t cred, gss_OID mech)
{
    OM_uint32 minor;
    int present = 0;

    assert(mech != GSS_C_NO_OID);

    if (cred == GSS_C_NO_CREDENTIAL || cred->mechanisms == GSS_C_NO_OID_SET)
        return TRUE;

    gss_test_oid_set_member(&minor, mech, cred->mechanisms, &present);

    return present;
}
