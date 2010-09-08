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
/*
 * Copyright 1995-2010 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#include "gssapiP_eap.h"

#if 0
OM_uint32
copyOid(OM_uint32 *minor_status,
        const gss_OID_desc * const oid,
        gss_OID *new_oid)
{
    gss_OID         p;

    *minor_status = 0;

    p = (gss_OID) malloc(sizeof(gss_OID_desc));
    if (!p) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    p->length = oid->length;
    p->elements = malloc(p->length);
    if (!p->elements) {
        free(p);
        return GSS_S_FAILURE;
    }
    memcpy(p->elements, oid->elements, p->length);
    *new_oid = p;
    return(GSS_S_COMPLETE);
}
#endif

/* Compose an OID of a prefix and an integer suffix */
OM_uint32
composeOid(OM_uint32 *minor_status,
           const char *prefix,
           size_t prefix_len,
           int suffix,
           gss_OID_desc *oid)
{
    int osuffix, i;
    size_t nbytes;
    unsigned char *op;

    if (oid == GSS_C_NO_OID) {
        *minor_status = EINVAL;
        return GSS_S_FAILURE;
    }
    if (oid->length < prefix_len) {
        *minor_status = ERANGE;
        return GSS_S_FAILURE;
    }

    memcpy(oid->elements, prefix, prefix_len);

    nbytes = 0;
    osuffix = suffix;
    while (suffix) {
        nbytes++;
        suffix >>= 7;
    }
    suffix = osuffix;

    if (oid->length < prefix_len + nbytes) {
        *minor_status = ERANGE;
        return GSS_S_FAILURE;
    }

    op = (unsigned char *) oid->elements + prefix_len + nbytes;
    i = -1;
    while (suffix) {
        op[i] = (unsigned char)suffix & 0x7f;
        if (i != -1)
            op[i] |= 0x80;
        i--;
        suffix >>= 7;
    }

    oid->length = prefix_len + nbytes;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
decomposeOid(OM_uint32 *minor_status,
             const char *prefix,
             size_t prefix_len,
             gss_OID_desc *oid,
             int *suffix)
{
    size_t i, slen;
    unsigned char *op;

    if (oid->length < prefix_len ||
        memcmp(oid->elements, prefix, prefix_len) != 0) {
        return GSS_S_BAD_MECH;
    }

    op = (unsigned char *) oid->elements + prefix_len;

    *suffix = 0;

    slen = oid->length - prefix_len;

    for (i = 0; i < slen; i++) {
        *suffix = (*suffix << 7) | (op[i] & 0x7f);
        if (i + 1 != slen && (op[i] & 0x80) == 0) {
            *minor_status = EINVAL;
            return GSS_S_FAILURE;
        }
    }

    return GSS_S_COMPLETE;
}

#if 0
OM_uint32
gssEapReleaseOid(OM_uint32 *minor, gss_OID *oid)
{
    OM_uint32 major;

    major = gss_internal_release_oid(minor, oid);
    if (major == GSS_S_CONTINUE_NEEDED) {
        GSSEAP_FREE(oid->elements);
        GSSEAP_FREE(oid);
        *oid = GSS_C_NO_OID;
        major = GSS_S_COMPLETE;
    }

    return major;
}
#endif
