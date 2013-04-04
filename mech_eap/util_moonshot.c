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

#include "gssapiP_eap.h"

#ifdef HAVE_MOONSHOT_GET_IDENTITY
#include <libmoonshot.h>

static OM_uint32
libMoonshotMapError(OM_uint32 *minor,
                    MoonshotError **pError)
{
    MoonshotError *error = *pError;

    GSSEAP_ASSERT(error != NULL);

    switch (error->code) {
    case MOONSHOT_ERROR_UNABLE_TO_START_SERVICE:
        *minor = GSSEAP_UNABLE_TO_START_IDENTITY_SERVICE;
        break;
    case MOONSHOT_ERROR_NO_IDENTITY_SELECTED:
        *minor = GSSEAP_NO_IDENTITY_SELECTED;
        break;
    case MOONSHOT_ERROR_INSTALLATION_ERROR:
        *minor = GSSEAP_IDENTITY_SERVICE_INSTALL_ERROR;
        break;
    case MOONSHOT_ERROR_OS_ERROR:
        *minor = GSSEAP_IDENTITY_SERVICE_OS_ERROR;
        break;
    case MOONSHOT_ERROR_IPC_ERROR:
        *minor = GSSEAP_IDENTITY_SERVICE_IPC_ERROR;
        break;
    default:
        *minor = GSSEAP_IDENTITY_SERVICE_UNKNOWN_ERROR;
        break;
    }

    gssEapSaveStatusInfo(*minor, error->message);
    moonshot_error_free(error);
    *pError = NULL;

    return GSS_S_CRED_UNAVAIL;
}

OM_uint32
libMoonshotResolveDefaultIdentity(OM_uint32 *minor,
                                  const gss_cred_id_t cred,
                                  gss_name_t *pName)
{
    OM_uint32 major, tmpMinor;
    gss_OID nameMech = gssEapPrimaryMechForCred(cred);
    gss_name_t name = GSS_C_NO_NAME;
    gss_buffer_desc tmpBuffer = GSS_C_EMPTY_BUFFER;
    char *nai = NULL;
    char *password = NULL;
    char *serverCertificateHash = NULL;
    char *caCertificate = NULL;
    char *subjectNameConstraint = NULL;
    char *subjectAltNameConstraint = NULL;
    MoonshotError *error = NULL;

    *pName = GSS_C_NO_NAME;

    if (!moonshot_get_default_identity(&nai,
                                       &password,
                                       &serverCertificateHash,
                                       &caCertificate,
                                       &subjectNameConstraint,
                                       &subjectAltNameConstraint,
                                       &error)) {
        if (error->code == MOONSHOT_ERROR_NO_IDENTITY_SELECTED) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSEAP_NO_DEFAULT_IDENTITY;
            moonshot_error_free(error);
        } else
            major = libMoonshotMapError(minor, &error);
        goto cleanup;
    }

    tmpBuffer.value = nai;
    tmpBuffer.length = strlen(nai);

    major = gssEapImportName(minor, &tmpBuffer, GSS_C_NT_USER_NAME, nameMech, &name);
    if (GSS_ERROR(major))
        goto cleanup;

    *pName = name;
    name = GSS_C_NO_NAME;

cleanup:
    moonshot_free(nai);
    moonshot_free(password);
    moonshot_free(serverCertificateHash);
    moonshot_free(caCertificate);
    moonshot_free(subjectNameConstraint);
    moonshot_free(subjectAltNameConstraint);

    gssEapReleaseName(&tmpMinor, &name);

    return major;
}

static int stringEmpty(const char * s)
{
    if (s == NULL)
      return 1;
    if (strlen(s) > 0)
	return 0;
    return 1;
}

OM_uint32
libMoonshotResolveInitiatorCred(OM_uint32 *minor,
                                gss_cred_id_t cred,
                                const gss_name_t targetName)
{
    OM_uint32 major, tmpMinor;
    gss_OID nameMech = gssEapPrimaryMechForCred(cred);
    gss_buffer_desc initiator = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc tmpBuffer = GSS_C_EMPTY_BUFFER;
    char *nai = NULL;
    char *password = NULL;
    char *serverCertificateHash = NULL;
    char *caCertificate = NULL;
    char *subjectNameConstraint = NULL;
    char *subjectAltNameConstraint = NULL;
    MoonshotError *error = NULL;

    if (cred->name != GSS_C_NO_NAME) {
      major = gssEapDisplayName(minor, cred->name, &initiator, NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (targetName != GSS_C_NO_NAME) {
      major = gssEapDisplayName(minor, targetName, &target, NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (!moonshot_get_identity((const char *)initiator.value,
                               (const char *)cred->password.value,
                               (const char *)target.value,
                               &nai,
                               &password,
                               &serverCertificateHash,
                               &caCertificate,
                               &subjectNameConstraint,
                               &subjectAltNameConstraint,
                               &error)) {
        major = libMoonshotMapError(minor, &error);
        goto cleanup;
    }

    gssEapReleaseName(&tmpMinor, &cred->name);

    tmpBuffer.value = nai;
    tmpBuffer.length = strlen(nai);

    major = gssEapImportName(minor, &tmpBuffer, GSS_C_NT_USER_NAME,
                             nameMech, &cred->name);
    if (GSS_ERROR(major))
        goto cleanup;

    tmpBuffer.value = password;
    tmpBuffer.length = strlen(password);

    major = gssEapSetCredPassword(minor, cred, &tmpBuffer);
    if (GSS_ERROR(major))
        goto cleanup;

    gss_release_buffer(&tmpMinor, &cred->caCertificate);
    gss_release_buffer(&tmpMinor, &cred->subjectNameConstraint);
    gss_release_buffer(&tmpMinor, &cred->subjectAltNameConstraint);

    if (!stringEmpty(serverCertificateHash)) {
        size_t len = strlen(serverCertificateHash);

        #define HASH_PREFIX             "hash://server/sha256/"
        #define HASH_PREFIX_LEN         (sizeof(HASH_PREFIX) - 1)

        cred->caCertificate.value = GSSEAP_MALLOC(HASH_PREFIX_LEN + len + 1);
        if (cred->caCertificate.value == NULL) {
            major = GSS_S_FAILURE;
            *minor = ENOMEM;
            goto cleanup;
        }

        memcpy(cred->caCertificate.value, HASH_PREFIX, HASH_PREFIX_LEN);
        memcpy((char *)cred->caCertificate.value + HASH_PREFIX_LEN, serverCertificateHash, len);

        ((char *)cred->caCertificate.value)[HASH_PREFIX_LEN + len] = '\0';

        cred->caCertificate.length = HASH_PREFIX_LEN + len;
    } else if (!stringEmpty(caCertificate)) {
        makeStringBufferOrCleanup(caCertificate, &cred->caCertificate);
    }

    if (!stringEmpty(subjectNameConstraint))
        makeStringBufferOrCleanup(subjectNameConstraint, &cred->subjectNameConstraint);
    if (!stringEmpty(subjectAltNameConstraint))
        makeStringBufferOrCleanup(subjectAltNameConstraint, &cred->subjectAltNameConstraint);

cleanup:
    moonshot_free(nai);
    moonshot_free(password);
    moonshot_free(serverCertificateHash);
    moonshot_free(caCertificate);
    moonshot_free(subjectNameConstraint);
    moonshot_free(subjectAltNameConstraint);

    gss_release_buffer(&tmpMinor, &initiator);
    gss_release_buffer(&tmpMinor, &target);

    return major;
}
#endif /* HAVE_MOONSHOT_GET_IDENTITY */
