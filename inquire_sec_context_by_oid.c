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

static OM_uint32
inquireSessionKey(OM_uint32 *minor,
                  const gss_ctx_id_t ctx,
                  const gss_OID desired_object,
                  gss_buffer_set_t *dataSet)
{
    OM_uint32 major, tmpMinor;
    unsigned char oidBuf[16];
    gss_buffer_desc buf;
    gss_OID_desc oid;

    buf.length = ctx->rfc3961Key.length;
    buf.value = ctx->rfc3961Key.contents;

    major = gss_add_buffer_set_member(minor, &buf, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    oid.length = sizeof(oidBuf);
    oid.elements = oidBuf;

    major = composeOid(minor,
                       "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04",
                       10,
                       ctx->encryptionType,
                       &oid);
    if (GSS_ERROR(major))
        goto cleanup;

    buf.length = oid.length;
    buf.value = oid.elements;

    major = gss_add_buffer_set_member(minor, &buf, dataSet);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;

cleanup:
    if (GSS_ERROR(major) && *dataSet != GSS_C_NO_BUFFER_SET) {
        gss_buffer_set_t set = *dataSet;

        if (set->count != 0)
            memset(set->elements[0].value, 0, set->elements[0].length);
        gss_release_buffer_set(&tmpMinor, dataSet);
    }

    return major;
}

static struct {
    gss_OID_desc oid;
    OM_uint32 (*inquire)(OM_uint32 *, const gss_ctx_id_t,
                         const gss_OID, gss_buffer_set_t *);
} inquireCtxOps[] = {
    {
        /* GSS_C_INQ_SSPI_SESSION_KEY */
        { 11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05" },
        inquireSessionKey
    },
};

OM_uint32
gss_inquire_sec_context_by_oid(OM_uint32 *minor,
                               const gss_ctx_id_t context_handle,
                               const gss_OID desired_object,
                               gss_buffer_set_t *data_set)
{
    OM_uint32 major = GSS_S_UNAVAILABLE;
    int i;

    *data_set = GSS_C_NO_BUFFER_SET;

    for (i = 0; i < sizeof(inquireCtxOps) / sizeof(inquireCtxOps[0]); i++) {
        if (oidEqual(&inquireCtxOps[i].oid, desired_object)) {
            major = (*inquireCtxOps[i].inquire)(minor, context_handle,
                                                 desired_object, data_set);
            break;
        }
    }

    return major;
}
