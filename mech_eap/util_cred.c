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

#include "gssapiP_eap.h"

#ifdef WIN32
# include <shlobj.h>     /* may need to use ShFolder.h instead */
# include <stdio.h>
#else
# include <pwd.h>
#endif
#include "openssl/err.h"
#ifdef HAVE_MOONSHOT_GET_IDENTITY
#include "libmoonshot.h"
#endif

#include <openssl/opensslv.h>

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
        *minor = GSSEAP_GET_LAST_ERROR();
        gssEapReleaseCred(&tmpMinor, &cred);
        return GSS_S_FAILURE;
    }

    *pCred = cred;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static void
zeroAndReleasePassword(gss_buffer_t password)
{
    GSSEAP_ASSERT(password != GSS_C_NO_BUFFER);

    if (password->value != NULL) {
        memset(password->value, 0, password->length);
        GSSEAP_FREE(password->value);
    }

    password->value = NULL;
    password->length = 0;
}

OM_uint32
gssEapReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred)
{
    OM_uint32 tmpMinor;
    gss_cred_id_t cred = *pCred;
    krb5_context krbContext = NULL;

    if (cred == GSS_C_NO_CREDENTIAL) {
        return GSS_S_COMPLETE;
    }

    GSSEAP_KRB_INIT(&krbContext);

    gssEapReleaseName(&tmpMinor, &cred->name);
    gssEapReleaseName(&tmpMinor, &cred->target);

    zeroAndReleasePassword(&cred->password);

    gss_release_buffer(&tmpMinor, &cred->radiusConfigFile);
    gss_release_buffer(&tmpMinor, &cred->radiusConfigStanza);
    gss_release_buffer(&tmpMinor, &cred->caCertificate);
    gss_release_buffer(&tmpMinor, &cred->caCertificateBlob);
    gss_release_buffer(&tmpMinor, &cred->subjectNameConstraint);
    gss_release_buffer(&tmpMinor, &cred->subjectAltNameConstraint);
    gss_release_buffer(&tmpMinor, &cred->clientCertificate);
    gss_release_buffer(&tmpMinor, &cred->privateKey);

#ifdef GSSEAP_ENABLE_REAUTH
    if (cred->krbCredCache != NULL) {
        if (cred->flags & CRED_FLAG_DEFAULT_CCACHE)
            krb5_cc_close(krbContext, cred->krbCredCache);
        else
            krb5_cc_destroy(krbContext, cred->krbCredCache);
    }
    if (cred->reauthCred != GSS_C_NO_CREDENTIAL)
        gssReleaseCred(&tmpMinor, &cred->reauthCred);
#endif

    GSSEAP_MUTEX_DESTROY(&cred->mutex);
    memset(cred, 0, sizeof(*cred));
    GSSEAP_FREE(cred);
    *pCred = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
readStaticIdentityFile(OM_uint32 *minor,
                       gss_buffer_t defaultIdentity,
                       gss_buffer_t defaultPassword,
                       gss_buffer_t certFingerprint)
{
    OM_uint32 major, tmpMinor;
    FILE *fp = NULL;
    char buf[BUFSIZ];
    char *ccacheName;
    int i = 0;
#ifndef WIN32
    struct passwd *pw = NULL, pwd;
    char pwbuf[BUFSIZ];
#endif

    if (defaultIdentity != GSS_C_NO_BUFFER) {
        defaultIdentity->length = 0;
        defaultIdentity->value = NULL;
    }

    if (defaultPassword != GSS_C_NO_BUFFER) {
        defaultPassword->length = 0;
        defaultPassword->value = NULL;
    }

    if (certFingerprint != GSS_C_NO_BUFFER) {
        certFingerprint->length = 0;
        certFingerprint->value = NULL;
    }

    ccacheName = getenv("GSSEAP_IDENTITY");
    if (ccacheName == NULL) {
#ifdef WIN32
        TCHAR szPath[MAX_PATH];

        if (!SUCCEEDED(SHGetFolderPath(NULL,
                                       CSIDL_APPDATA, /* |CSIDL_FLAG_CREATE */
                                       NULL, /* User access token */
                                       0,    /* SHGFP_TYPE_CURRENT */
                                       szPath))) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSEAP_GET_LAST_ERROR(); /* XXX */
            goto cleanup;
        }

        snprintf(buf, sizeof(buf), "%s/.gss_eap_id", szPath);
#else
        if (getpwuid_r(getuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) != 0 ||
            pw == NULL || pw->pw_dir == NULL) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSEAP_GET_LAST_ERROR();
            goto cleanup;
        }

        snprintf(buf, sizeof(buf), "%s/.gss_eap_id", pw->pw_dir);
#endif /* WIN32 */
        ccacheName = buf;
    }

    fp = fopen(ccacheName, "r");
    if (fp == NULL) {
        major = GSS_S_CRED_UNAVAIL;
        *minor = GSSEAP_NO_DEFAULT_CRED;
        goto cleanup;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        gss_buffer_desc src, *dst;

        src.length = strlen(buf);
        src.value = buf;

        if (src.length == 0)
            break;

        if (buf[src.length - 1] == '\n') {
            buf[src.length - 1] = '\0';
            if (--src.length == 0)
                break;
        }

        if (i == 0)
            dst = defaultIdentity;
        else if (i == 1)
            dst = defaultPassword;
        else if (i == 2)
            dst = certFingerprint;
        else
            break;

        if (dst != GSS_C_NO_BUFFER) {
            major = duplicateBuffer(minor, &src, dst);
            if (GSS_ERROR(major))
                goto cleanup;
        }

        i++;
    }

    if (defaultIdentity != GSS_C_NO_BUFFER && defaultIdentity->length == 0) {
        major = GSS_S_CRED_UNAVAIL;
        *minor = GSSEAP_NO_DEFAULT_CRED;
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (fp != NULL)
        fclose(fp);

    if (GSS_ERROR(major)) {
        if (defaultIdentity != GSS_C_NO_BUFFER)
            gss_release_buffer(&tmpMinor, defaultIdentity);
        if (defaultPassword != GSS_C_NO_BUFFER)
            zeroAndReleasePassword(defaultPassword);
        if (certFingerprint != GSS_C_NO_BUFFER)
            gss_release_buffer(&tmpMinor, certFingerprint);
    }

    memset(buf, 0, sizeof(buf));

    return major;
}

gss_OID
gssEapPrimaryMechForCred(gss_cred_id_t cred)
{
    gss_OID credMech = GSS_C_NO_OID;

    if (cred != GSS_C_NO_CREDENTIAL &&
        cred->mechanisms != GSS_C_NO_OID_SET &&
        cred->mechanisms->count == 1)
        credMech = &cred->mechanisms->elements[0];

    return credMech;
}

OM_uint32
gssEapAcquireCred(OM_uint32 *minor,
                  gss_const_name_t desiredName,
                  OM_uint32 timeReq GSSEAP_UNUSED,
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
        *minor = GSSEAP_BAD_USAGE;
        goto cleanup;
        break;
    }

    major = gssEapValidateMechs(minor, desiredMechs);
    if (GSS_ERROR(major))
        goto cleanup;

    major = duplicateOidSet(minor, desiredMechs, &cred->mechanisms);
    if (GSS_ERROR(major))
        goto cleanup;

    if (desiredName != GSS_C_NO_NAME) {
        GSSEAP_MUTEX_LOCK(&((gss_name_t)desiredName)->mutex);

        major = gssEapDuplicateName(minor, desiredName, &cred->name);
        if (GSS_ERROR(major)) {
            GSSEAP_MUTEX_UNLOCK(&((gss_name_t)desiredName)->mutex);
            goto cleanup;
        }

        GSSEAP_MUTEX_UNLOCK(&((gss_name_t)desiredName)->mutex);
    }

#ifdef GSSEAP_ENABLE_ACCEPTOR
    if (cred->flags & CRED_FLAG_ACCEPT) {
        struct rs_context *radContext;

        major = gssEapCreateRadiusContext(minor, cred, &radContext);
        if (GSS_ERROR(major))
            goto cleanup;

        rs_context_destroy(radContext);
    }
#endif

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
        gssEapReleaseCred(&tmpMinor, &cred);

    gssEapTraceStatus("gss_acquire_cred", major, *minor);

    return major;
}

/*
 * Return TRUE if cred available for mechanism. Caller need no acquire
 * lock because mechanisms list is immutable.
 */
int
gssEapCredAvailable(gss_const_cred_id_t cred, gss_OID mech)
{
    OM_uint32 minor;
    int present = 0;

    GSSEAP_ASSERT(mech != GSS_C_NO_OID);

    if (cred == GSS_C_NO_CREDENTIAL || cred->mechanisms == GSS_C_NO_OID_SET)
        return TRUE;

    gss_test_oid_set_member(&minor, mech, cred->mechanisms, &present);

    return present;
}

static OM_uint32
staticIdentityFileResolveDefaultIdentity(OM_uint32 *minor,
                                         const gss_cred_id_t cred,
                                         gss_name_t *pName)
{
    OM_uint32 major, tmpMinor;
    gss_OID nameMech = gssEapPrimaryMechForCred(cred);
    gss_buffer_desc defaultIdentity = GSS_C_EMPTY_BUFFER;

    *pName = GSS_C_NO_NAME;

    major = readStaticIdentityFile(minor, &defaultIdentity, GSS_C_NO_BUFFER, GSS_C_NO_BUFFER);
    if (major == GSS_S_COMPLETE) {
        major = gssEapImportName(minor, &defaultIdentity, GSS_C_NT_USER_NAME,
                                 nameMech, pName);
    }

    gss_release_buffer(&tmpMinor, &defaultIdentity);

    return major;
}

static OM_uint32
gssEapResolveCredIdentity(OM_uint32 *minor,
                          gss_cred_id_t cred)
{
    OM_uint32 major;
    gss_OID nameMech = gssEapPrimaryMechForCred(cred);

    if (cred->name != GSS_C_NO_NAME) {
        *minor = 0;
        return GSS_S_COMPLETE;
    }

    if (cred->flags & CRED_FLAG_ACCEPT) {
        gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;
        char serviceName[5 + MAXHOSTNAMELEN];

        /* default host-based service is host@localhost */
        memcpy(serviceName, "host@", 5);
        if (gethostname(&serviceName[5], MAXHOSTNAMELEN) != 0) {
            *minor = GSSEAP_NO_HOSTNAME;
            return GSS_S_FAILURE;
        }

        nameBuf.value = serviceName;
        nameBuf.length = strlen((char *)nameBuf.value);

        major = gssEapImportName(minor, &nameBuf, GSS_C_NT_HOSTBASED_SERVICE,
                                 nameMech, &cred->name);
        if (GSS_ERROR(major))
            return major;
    } else if (cred->flags & CRED_FLAG_INITIATE) {
#ifdef HAVE_MOONSHOT_GET_IDENTITY
        major = libMoonshotResolveDefaultIdentity(minor, cred, &cred->name);
        if (major == GSS_S_CRED_UNAVAIL)
#endif
            major = staticIdentityFileResolveDefaultIdentity(minor, cred, &cred->name);
        if (major != GSS_S_CRED_UNAVAIL)
            return major;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapInquireCred(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_name_t *name,
                  OM_uint32 *pLifetime,
                  gss_cred_usage_t *cred_usage,
                  gss_OID_set *mechanisms)
{
    OM_uint32 major;
    time_t now, lifetime;

    if (name != NULL) {
        major = gssEapResolveCredIdentity(minor, cred);
        if (GSS_ERROR(major))
            goto cleanup;

        if (cred->name != GSS_C_NO_NAME) {
            major = gssEapDuplicateName(minor, cred->name, name);
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
            major = gssEapIndicateMechs(minor, mechanisms);
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
        *minor = GSSEAP_CRED_EXPIRED;
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

OM_uint32
gssEapSetCredPassword(OM_uint32 *minor,
                      gss_cred_id_t cred,
                      const gss_buffer_t password)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc newPassword = GSS_C_EMPTY_BUFFER;

    if (cred->flags & CRED_FLAG_RESOLVED) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_CRED_RESOLVED;
        goto cleanup;
    }

    if (password != GSS_C_NO_BUFFER) {
        major = duplicateBuffer(minor, password, &newPassword);
        if (GSS_ERROR(major))
            goto cleanup;

        cred->flags |= CRED_FLAG_PASSWORD;
    } else {
        cred->flags &= ~(CRED_FLAG_PASSWORD);
    }

    gss_release_buffer(&tmpMinor, &cred->password);
    cred->password = newPassword;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

/*
 * Currently only the privateKey path is exposed to the application
 * (via gss_set_cred_option() or the third line in ~/.gss_eap_id).
 * At some point in the future we may add support for setting the
 * client certificate separately.
 */
OM_uint32
gssEapSetCredClientCertificate(OM_uint32 *minor,
                              gss_cred_id_t cred,
                              const gss_buffer_t clientCert,
                              const gss_buffer_t privateKey)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc newClientCert = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc newPrivateKey = GSS_C_EMPTY_BUFFER;

    if (cred->flags & CRED_FLAG_RESOLVED) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_CRED_RESOLVED;
        goto cleanup;
    }

    if (clientCert == GSS_C_NO_BUFFER &&
        privateKey == GSS_C_NO_BUFFER) {
        cred->flags &= ~(CRED_FLAG_CERTIFICATE);
        major = GSS_S_COMPLETE;
        *minor = 0;
        goto cleanup;
    }

    if (clientCert != GSS_C_NO_BUFFER) {
        major = duplicateBuffer(minor, clientCert, &newClientCert);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (privateKey != GSS_C_NO_BUFFER) {
        major = duplicateBuffer(minor, privateKey, &newPrivateKey);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    cred->flags |= CRED_FLAG_CERTIFICATE;

    gss_release_buffer(&tmpMinor, &cred->clientCertificate);
    cred->clientCertificate = newClientCert;

    gss_release_buffer(&tmpMinor, &cred->privateKey);
    cred->privateKey = newPrivateKey;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, &newClientCert);
        gss_release_buffer(&tmpMinor, &newPrivateKey);
    }

    return major;
}

OM_uint32
gssEapSetCredService(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_const_name_t target)
{
    OM_uint32 major, tmpMinor;
    gss_name_t newTarget = GSS_C_NO_NAME;

    if (cred->flags & CRED_FLAG_RESOLVED) {
        major = GSS_S_FAILURE;
        *minor = GSSEAP_CRED_RESOLVED;
        goto cleanup;
    }

    if (target != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, target, &newTarget);
        if (GSS_ERROR(major))
            goto cleanup;

        cred->flags |= CRED_FLAG_TARGET;
    } else {
        cred->flags &= ~(CRED_FLAG_TARGET);
    }

    gssEapReleaseName(&tmpMinor, &cred->target);
    cred->target = newTarget;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    return major;
}

static OM_uint32
gssEapDuplicateCred(OM_uint32 *minor,
                    const gss_cred_id_t src,
                    gss_cred_id_t *pDst)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t dst = GSS_C_NO_CREDENTIAL;

    *pDst = GSS_C_NO_CREDENTIAL;

    major = gssEapAllocCred(minor, &dst);
    if (GSS_ERROR(major))
        goto cleanup;

    dst->flags = src->flags;

    if (src->name != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, src->name, &dst->name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (src->target != GSS_C_NO_NAME) {
        major = gssEapDuplicateName(minor, src->target, &dst->target);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (src->password.value != NULL) {
        major = duplicateBuffer(minor, &src->password, &dst->password);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    major = duplicateOidSet(minor, src->mechanisms, &dst->mechanisms);
    if (GSS_ERROR(major))
        goto cleanup;

    dst->expiryTime = src->expiryTime;

    if (src->radiusConfigFile.value != NULL)
        duplicateBufferOrCleanup(&src->radiusConfigFile, &dst->radiusConfigFile);
    if (src->radiusConfigStanza.value != NULL)
        duplicateBufferOrCleanup(&src->radiusConfigStanza, &dst->radiusConfigStanza);
    if (src->caCertificate.value != NULL)
        duplicateBufferOrCleanup(&src->caCertificate, &dst->caCertificate);
    if (src->caCertificateBlob.value != NULL)
        duplicateBufferOrCleanup(&src->caCertificateBlob, &dst->caCertificateBlob);
    if (src->subjectNameConstraint.value != NULL)
        duplicateBufferOrCleanup(&src->subjectNameConstraint, &dst->subjectNameConstraint);
    if (src->subjectAltNameConstraint.value != NULL)
        duplicateBufferOrCleanup(&src->subjectAltNameConstraint, &dst->subjectAltNameConstraint);
    if (src->clientCertificate.value != NULL)
        duplicateBufferOrCleanup(&src->clientCertificate, &dst->clientCertificate);
    if (src->privateKey.value != NULL)
        duplicateBufferOrCleanup(&src->privateKey, &dst->privateKey);

#ifdef GSSEAP_ENABLE_REAUTH
    /* XXX krbCredCache, reauthCred */
#endif

    *pDst = dst;
    dst = GSS_C_NO_CREDENTIAL;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gssEapReleaseCred(&tmpMinor, &dst);

    return major;
}

static int cert_to_byte_array(X509 *cert, unsigned char **bytes)
{
    unsigned char *buf;
    unsigned char *p;

    int len = i2d_X509(cert, NULL);
    if (len <= 0) {
        return -1;
    }

    p = buf = GSSEAP_MALLOC(len);
    if (buf == NULL) {
        return -1;
    }

    i2d_X509(cert, &buf);

    *bytes = p;
    return len;
}

static int sha256(unsigned char *bytes, int len, unsigned char *hash)
{
    unsigned int hash_len = 0;
    int result = -1;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX ctx_internal;
    EVP_MD_CTX_init(&ctx_internal);
    EVP_MD_CTX *ctx = &ctx_internal;
#endif
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "sha256(init_sec_context.c): EVP_DigestInit_ex failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (!EVP_DigestUpdate(ctx, bytes, len)) {
        fprintf(stderr, "sha256(init_sec_context.c): EVP_DigestUpdate failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    if (!EVP_DigestFinal(ctx, hash, &hash_len)) {
        fprintf(stderr, "sha256(init_sec_context.c): EVP_DigestFinal failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    result = hash_len;

cleanup:
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif
    return result;
}

int staticConfirmServerCert (const unsigned char  *hash,
                             int                   hash_len)
{
    OM_uint32 major, minor;
    gss_buffer_desc certFingerprint = GSS_C_EMPTY_BUFFER;

    major = readStaticIdentityFile(&minor, GSS_C_NO_BUFFER, GSS_C_NO_BUFFER, &certFingerprint);
    if (major == GSS_S_COMPLETE) {
        /* Convert hash byte array to string */
        char hash_str[hash_len * 2 + 1];
        int i = 0;
        for (i = 0; i < hash_len; i++)
            sprintf(&(hash_str[i * 2]), "%02X", hash[i]);

        if (strlen(hash_str) == certFingerprint.length && strncasecmp(hash_str, certFingerprint.value, certFingerprint.length) == 0)
            return 1;

        wpa_printf(MSG_WARNING, "Certificate fingerprint mismatch! Server cert: %s\n", hash_str);
    }
    return 0;
}

int authorizedAnchorsConfirmServerCert (const char* realm, const unsigned char *hash, int hash_len)
{
    FILE *fp = NULL;
    char buf[BUFSIZ];
    char *file_path;
    int result = 0;
    char hash_str[hash_len * 2 + 1];
    int i = 0;

#ifndef WIN32
    struct passwd *pw = NULL, pwd;
    char pwbuf[BUFSIZ];
#endif
    file_path = getenv("GSSEAP_AUTHORIZED_ANCHORS");
    if (file_path == NULL) {
#ifdef WIN32
        TCHAR szPath[MAX_PATH];

        if (!SUCCEEDED(SHGetFolderPath(NULL,
                                       CSIDL_APPDATA, /* |CSIDL_FLAG_CREATE */
                                       NULL, /* User access token */
                                       0,    /* SHGFP_TYPE_CURRENT */
                                       szPath))) {
            goto cleanup;
        }

        snprintf(buf, sizeof(buf), "%s/.gss_eap_authorized_anchors", szPath);
#else
        if (getpwuid_r(getuid(), &pwd, pwbuf, sizeof(pwbuf), &pw) != 0 ||
                pw == NULL || pw->pw_dir == NULL) {
            goto cleanup;
        }
        snprintf(buf, sizeof(buf), "%s/.gss_eap_authorized_anchors", pw->pw_dir);
#endif /* WIN32 */
        file_path = buf;
    }

    fp = fopen(file_path, "r");
    if (fp == NULL) {
        goto cleanup;
    }

    /* Convert hash byte array to string */
    for (i = 0; i < 32; i++)
        sprintf(&(hash_str[i*2]), "%02X", hash[i]);

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t length = strlen(buf);

        if (length == 0)
            break;

        if (buf[length - 1] == '\n') {
            buf[length - 1] = '\0';
            if (--length == 0)
                break;
        }

        /* Lines consists of REALM:FINGERPRINT */
        char* sep = strchr(buf, ':');
        char* fingerprint = NULL;
        if (sep != NULL) {
            fingerprint = sep + 1;
            *sep = '\0';
        }

        /* need to find a matching realm */
        if (strcasecmp(buf, realm))
            continue;

        if (strcmp(fingerprint, "*") == 0 || strcasecmp(fingerprint, hash_str) == 0) {
            result = 1;
            wpa_printf(MSG_INFO, "Found matching trusted anchor [%s] for realm: [%s].", fingerprint, realm);
            goto cleanup;
        }
    }

cleanup:
    if (fp != NULL)
        fclose(fp);
    memset(buf, 0, sizeof(buf));

    return result;
}

int peerValidateServerCert(int ok_so_far, X509* cert, void *ca_ctx)
{
    char                 *realm = NULL;
    unsigned char        *cert_bytes = NULL;
    int                   cert_len;
    unsigned char         hash[32];
    int                   hash_len;
#ifdef HAVE_MOONSHOT_GET_IDENTITY
    MoonshotError        *error = NULL;
#endif
    struct eap_peer_config *eap_config = (struct eap_peer_config *) ca_ctx;
    char *identity = strdup((const char *) eap_config->identity);

    // Truncate the identity to just the username; make a separate string for the realm.
    char* at = strchr(identity, '@');
    if (at != NULL) {
        realm = strdup(at + 1);
        *at = '\0';
    }

    cert_len = cert_to_byte_array(cert, &cert_bytes);
    hash_len = sha256(cert_bytes, cert_len, hash);

    if (hash_len != 32) {
        wpa_printf(MSG_ERROR, "peerValidateServerCert: Error: hash_len=%d, not 32!\n", hash_len);
        ok_so_far = FALSE;
        goto cleanup;
    }

#ifdef HAVE_MOONSHOT_GET_IDENTITY
    ok_so_far = moonshot_confirm_ca_certificate(identity, realm, cert_bytes, cert_len, &error);
    if (!ok_so_far)
#endif
    {
        ok_so_far = staticConfirmServerCert(hash, 32);
        if (!ok_so_far)
            ok_so_far = authorizedAnchorsConfirmServerCert(realm, hash, 32);
    }

    wpa_printf(MSG_INFO, "peerValidateServerCert for %s@%s: Returning %d\n", identity, realm, ok_so_far);

cleanup:
    GSSEAP_FREE(cert_bytes);
    free(identity);
    if (realm != NULL) {
        free(realm);
    }
    return ok_so_far;
}

static OM_uint32
staticIdentityFileResolveInitiatorCred(OM_uint32 *minor, gss_cred_id_t cred)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc defaultIdentity = GSS_C_EMPTY_BUFFER;
    gss_name_t defaultIdentityName = GSS_C_NO_NAME;
    gss_buffer_desc defaultPassword = GSS_C_EMPTY_BUFFER;
    int isDefaultIdentity = FALSE;

    major = readStaticIdentityFile(minor, &defaultIdentity, &defaultPassword, GSS_C_NO_BUFFER);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssEapImportName(minor, &defaultIdentity, GSS_C_NT_USER_NAME,
                             gssEapPrimaryMechForCred(cred), &defaultIdentityName);
    if (GSS_ERROR(major))
        goto cleanup;

    if (defaultIdentityName == GSS_C_NO_NAME) {
        if (cred->name == GSS_C_NO_NAME) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSEAP_NO_DEFAULT_IDENTITY;
            goto cleanup;
        }
    } else {
        if (cred->name == GSS_C_NO_NAME) {
            cred->name = defaultIdentityName;
            defaultIdentityName = GSS_C_NO_NAME;
            isDefaultIdentity = TRUE;
        } else {
            major = gssEapCompareName(minor, cred->name,
                                      defaultIdentityName, 0,
                                      &isDefaultIdentity);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

    if (isDefaultIdentity &&
        (cred->flags & CRED_FLAG_PASSWORD) == 0) {
        major = gssEapSetCredPassword(minor, cred, &defaultPassword);
        if (GSS_ERROR(major))
            goto cleanup;
    }

cleanup:
    gssEapReleaseName(&tmpMinor, &defaultIdentityName);
    zeroAndReleasePassword(&defaultPassword);
    gss_release_buffer(&tmpMinor, &defaultIdentity);

    return major;
}

OM_uint32
gssEapResolveInitiatorCred(OM_uint32 *minor,
                           const gss_cred_id_t cred,
                           gss_const_name_t targetName
#ifndef HAVE_MOONSHOT_GET_IDENTITY
                                                       GSSEAP_UNUSED
#endif
                           ,
                           gss_cred_id_t *pResolvedCred)
{
    OM_uint32 major, tmpMinor;
    gss_cred_id_t resolvedCred = GSS_C_NO_CREDENTIAL;

    if (cred == GSS_C_NO_CREDENTIAL) {
        major = gssEapAcquireCred(minor,
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
            *minor = GSSEAP_CRED_USAGE_MISMATCH;
            goto cleanup;
        }

        major = gssEapDuplicateCred(minor, cred, &resolvedCred);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if ((resolvedCred->flags & CRED_FLAG_RESOLVED) == 0) {
#ifdef HAVE_MOONSHOT_GET_IDENTITY
        major = libMoonshotResolveInitiatorCred(minor, resolvedCred, targetName);
        if (major == GSS_S_CRED_UNAVAIL)
#endif
            major = staticIdentityFileResolveInitiatorCred(minor, resolvedCred);
        if (GSS_ERROR(major) && major != GSS_S_CRED_UNAVAIL)
            goto cleanup;

        /* If we have a caller-supplied password, the credential is resolved. */
        if ((resolvedCred->flags &
             (CRED_FLAG_PASSWORD | CRED_FLAG_CERTIFICATE)) == 0) {
            major = GSS_S_CRED_UNAVAIL;
            *minor = GSSEAP_NO_DEFAULT_CRED;
            goto cleanup;
        }

        resolvedCred->flags |= CRED_FLAG_RESOLVED;
    }

    *pResolvedCred = resolvedCred;
    resolvedCred = GSS_C_NO_CREDENTIAL;

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    gssEapReleaseCred(&tmpMinor, &resolvedCred);

    return major;
}
