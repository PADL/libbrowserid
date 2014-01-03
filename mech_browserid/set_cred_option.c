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

#include "gssapiP_bid.h"

static OM_uint32
setCredFlag(OM_uint32 *minor,
            gss_cred_id_t cred,
            const gss_OID oid GSSBID_UNUSED,
            const gss_buffer_t buffer)
{
    OM_uint32 flags;
    unsigned char *p;

    if (buffer == GSS_C_NO_BUFFER) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_FAILURE;
    }

    if (buffer->length < 4) {
        *minor = GSSBID_WRONG_SIZE;
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
setCredAssertion(OM_uint32 *minor,
                 gss_cred_id_t cred,
                 const gss_OID oid GSSBID_UNUSED,
                 const gss_buffer_t buffer)
{
    return gssBidSetCredAssertion(minor, cred, buffer);
}

static OM_uint32
setCredTicketCache(OM_uint32 *minor,
                   gss_cred_id_t cred,
                   const gss_OID oid GSSBID_UNUSED,
                   const gss_buffer_t buffer)
{
    return gssBidSetCredTicketCacheName(minor, cred, buffer);
}

static OM_uint32
setCredReplayCache(OM_uint32 *minor,
                   gss_cred_id_t cred,
                   const gss_OID oid GSSBID_UNUSED,
                   const gss_buffer_t buffer)
{
    return gssBidSetCredReplayCacheName(minor, cred, buffer);
}

#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H
static OM_uint32
setCredCFDictionary(OM_uint32 *minor,
                    gss_cred_id_t cred,
                   const gss_OID oid GSSBID_UNUSED,
                   const gss_buffer_t buffer)
{
    return gssBidSetCredWithCFDictionary(minor, cred, (CFDictionaryRef)buffer->value);
}
#endif /* HAVE_COREFOUNDATION_CFRUNTIME_H */

static struct {
    gss_OID_desc oid;
    OM_uint32 (*setOption)(OM_uint32 *, gss_cred_id_t cred,
                           const gss_OID, const gss_buffer_t);
} setCredOps[] = {
    /* 1.3.6.1.4.1.5322.24.3.3.1 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x03\x03\x01" },
        setCredFlag,
    },
    /* 1.3.6.1.4.1.5322.24.3.3.2 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x03\x03\x02" },
        setCredAssertion,
    },
    /* 1.3.6.1.4.1.5322.24.3.3.3 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x03\x03\x03" },
        setCredTicketCache,
    },
    /* 1.3.6.1.4.1.5322.24.3.3.4 */
    {
        { 11, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x03\x03\x03" },
        setCredReplayCache,
    },
#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H
    /* GSSSetCredCFDictionary - 1.3.6.1.4.1.5322.25.4.1 */
    {
        { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x19\x04\x01" },
        setCredCFDictionary,
    },
#endif /* HAVE_COREFOUNDATION_CFRUNTIME_H */
};

gss_OID GSS_BROWSERID_CRED_SET_CRED_FLAG            = &setCredOps[0].oid;
gss_OID GSS_BROWSERID_CRED_SET_CRED_ASSERTION       = &setCredOps[1].oid;
gss_OID GSS_BROWSERID_CRED_SET_CRED_TICKET_CACHE    = &setCredOps[2].oid;
gss_OID GSS_BROWSERID_CRED_SET_CRED_REPLAY_CACHE    = &setCredOps[3].oid;

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
        major = gssBidAcquireCred(minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                  GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                  &cred, NULL, NULL);
    }

    GSSBID_MUTEX_LOCK(&cred->mutex);

    major = GSS_S_UNAVAILABLE;
    *minor = GSSBID_BAD_CRED_OPTION;

    for (i = 0; i < sizeof(setCredOps) / sizeof(setCredOps[0]); i++) {
        if (oidEqual(&setCredOps[i].oid, desired_object)) {
            major = (*setCredOps[i].setOption)(minor, cred,
                                               desired_object, value);
            break;
        }
    }

    GSSBID_MUTEX_UNLOCK(&cred->mutex);

    if (*pCred == GSS_C_NO_CREDENTIAL)
        *pCred = cred;

    return major;
}
