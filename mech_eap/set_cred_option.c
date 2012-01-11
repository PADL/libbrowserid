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
 * Set an extended property on a credential handle.
 */

#include "gssapiP_eap.h"

static OM_uint32
setCredRadiusConfigFile(OM_uint32 *minor,
                        gss_cred_id_t cred,
                        const gss_OID oid GSSEAP_UNUSED,
                        const gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc configFileBuffer = GSS_C_EMPTY_BUFFER;

    if (buffer != GSS_C_NO_BUFFER && buffer->length != 0) {
        major = duplicateBuffer(minor, buffer, &configFileBuffer);
        if (GSS_ERROR(major))
            return major;
    }

    gss_release_buffer(&tmpMinor, &cred->radiusConfigFile);
    cred->radiusConfigFile = configFileBuffer;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
setCredRadiusConfigStanza(OM_uint32 *minor,
                          gss_cred_id_t cred,
                          const gss_OID oid GSSEAP_UNUSED,
                          const gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc configStanzaBuffer = GSS_C_EMPTY_BUFFER;

    if (buffer != GSS_C_NO_BUFFER && buffer->length != 0) {
        major = duplicateBuffer(minor, buffer, &configStanzaBuffer);
        if (GSS_ERROR(major))
            return major;
    }

    gss_release_buffer(&tmpMinor, &cred->radiusConfigStanza);
    cred->radiusConfigStanza = configStanzaBuffer;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
setCredFlag(OM_uint32 *minor,
            gss_cred_id_t cred,
            const gss_OID oid GSSEAP_UNUSED,
            const gss_buffer_t buffer)
{
    OM_uint32 flags;
    unsigned char *p;

    if (buffer == GSS_C_NO_BUFFER) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_FAILURE;
    }

    if (buffer->length < 4) {
        *minor = GSSEAP_WRONG_SIZE;
        return GSS_S_FAILURE;
    }

    p = (unsigned char *)buffer->value;

    flags = load_uint32_be(buffer->value) & CRED_FLAG_PUBLIC_MASK;

    if (buffer->length > 4 && p[4])
        cred->flags &= ~(flags);
    else
        cred->flags |= flags;

    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
setCredPassword(OM_uint32 *minor,
                gss_cred_id_t cred,
                const gss_OID oid GSSEAP_UNUSED,
                const gss_buffer_t buffer)
{
    return gssEapSetCredPassword(minor, cred, buffer);
}

static OM_uint32
setCredPrivateKey(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  const gss_OID oid GSSEAP_UNUSED,
                  const gss_buffer_t buffer)
{
    return gssEapSetCredClientCertificate(minor, cred, GSS_C_NO_BUFFER, buffer);
}

static struct {
    gss_OID_desc oid;
    OM_uint32 (*setOption)(OM_uint32 *, gss_cred_id_t cred,
                           const gss_OID, const gss_buffer_t);
} setCredOps[] = {
    /* 1.3.6.1.4.1.5322.22.3.3.1 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x03\x03\x01" },
        setCredRadiusConfigFile,
    },
    /* 1.3.6.1.4.1.5322.22.3.3.2 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x03\x03\x02" },
        setCredRadiusConfigStanza,
    },
    /* 1.3.6.1.4.1.5322.22.3.3.3 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x03\x03\x03" },
        setCredFlag,
    },
    /* 1.3.6.1.4.1.5322.22.3.3.4 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x03\x03\x04" },
        setCredPassword,
    },
    /* 1.3.6.1.4.1.5322.22.3.3.5 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x16\x03\x03\x05" },
        setCredPrivateKey,
    },
};

gss_OID GSS_EAP_CRED_SET_RADIUS_CONFIG_FILE     = &setCredOps[0].oid;
gss_OID GSS_EAP_CRED_SET_RADIUS_CONFIG_STANZA   = &setCredOps[1].oid;
gss_OID GSS_EAP_CRED_SET_CRED_FLAG              = &setCredOps[2].oid;
gss_OID GSS_EAP_CRED_SET_CRED_PASSWORD          = &setCredOps[3].oid;
gss_OID GSS_EAP_CRED_SET_CRED_PRIVATE_KEY       = &setCredOps[4].oid;

OM_uint32 GSSAPI_CALLCONV
gssspi_set_cred_option(OM_uint32 *minor,
                       gss_cred_id_t *pCred,
                       const gss_OID desired_object,
                       const gss_buffer_t value)
{
    OM_uint32 major;
    gss_cred_id_t cred = *pCred;
    int i;

    if (cred == GSS_C_NO_CREDENTIAL) {
        *minor = EINVAL;
        return GSS_S_UNAVAILABLE;
    }

    GSSEAP_MUTEX_LOCK(&cred->mutex);

    major = GSS_S_UNAVAILABLE;
    *minor = GSSEAP_BAD_CRED_OPTION;

    for (i = 0; i < sizeof(setCredOps) / sizeof(setCredOps[0]); i++) {
        if (oidEqual(&setCredOps[i].oid, desired_object)) {
            major = (*setCredOps[i].setOption)(minor, cred,
                                               desired_object, value);
            break;
        }
    }

    GSSEAP_MUTEX_UNLOCK(&cred->mutex);

    return major;
}

#if 0
OM_uint32
gsseap_set_cred_flag(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     OM_uint32 flag,
                     int clear)
{
    unsigned char buf[5];
    gss_buffer_desc value;

    value.length = sizeof(buf);
    value.value = buf;

    store_uint32_be(flag, buf);
    buf[4] = (clear != 0);

    return gssspi_set_cred_option(minor, &cred,
                                  GSS_EAP_CRED_SET_CRED_FLAG, &value);
}
#endif
