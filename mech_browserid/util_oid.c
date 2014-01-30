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

/*
 * OID utility routines.
 */

#include "gssapiP_bid.h"

#ifdef HAVE_HEIMDAL_VERSION
extern int
der_parse_heim_oid (const char *str, const char *sep, heim_oid *data);

extern int
der_put_oid (unsigned char *p, size_t len,
             const heim_oid *data, size_t *size);

extern void
der_free_oid (heim_oid *k);
#endif /* HAVE_HEIMDAL_VERSION */

OM_uint32
duplicateOid(OM_uint32 *minor,
             const gss_OID_desc * const oid,
             gss_OID *newOid)
{
    gss_OID p;

    *newOid = GSS_C_NO_OID;

    p = (gss_OID)GSSBID_MALLOC(sizeof(*p));
    if (p == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    p->length = oid->length;
    p->elements = GSSBID_MALLOC(p->length);
    if (p->elements == NULL) {
        GSSBID_FREE(p);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    memcpy(p->elements, oid->elements, p->length);
    *newOid = p;

    *minor = 0;
    return GSS_S_COMPLETE;
}

/* Compose an OID of a prefix and an integer suffix */
OM_uint32
composeOid(OM_uint32 *minor,
           const char *prefix,
           size_t prefix_len,
           int suffix,
           gss_OID_desc *oid)
{
    int osuffix, i;
    size_t nbytes;
    unsigned char *op;

    if (oid == GSS_C_NO_OID) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_FAILURE;
    }

    if (oid->length < prefix_len) {
        *minor = GSSBID_WRONG_SIZE;
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
        *minor = GSSBID_WRONG_SIZE;
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

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
decomposeOid(OM_uint32 *minor,
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
            *minor = GSSBID_WRONG_SIZE;
            return GSS_S_FAILURE;
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
duplicateOidSet(OM_uint32 *minor,
                const gss_OID_set src,
                gss_OID_set *dst)
{
    OM_uint32 major, tmpMinor;
    int i;

    if (src == GSS_C_NO_OID_SET) {
        *dst = GSS_C_NO_OID_SET;
        return GSS_S_COMPLETE;
    }

    major = gss_create_empty_oid_set(minor, dst);
    if (GSS_ERROR(major))
        return major;

    for (i = 0; i < src->count; i++) {
        gss_OID oid = &src->elements[i];

        major = gss_add_oid_set_member(minor, oid, dst);
        if (GSS_ERROR(major))
            break;
    }

    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, dst);

    return major;
}

OM_uint32
oidToJson(OM_uint32 *minor,
          gss_OID oid,
          json_t **pJson)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;

    *pJson = NULL;

    major = gss_oid_to_str(minor, oid, &buffer);
    if (GSS_ERROR(major))
        return major;

    *pJson = json_string((char *)buffer.value); /* XXX NUL termination */

    gss_release_buffer(&tmpMinor, &buffer);

    return GSS_S_COMPLETE;
}

OM_uint32
oidSetToJson(OM_uint32 *minor,
             gss_OID_set oidSet,
             json_t **pJson)
{
    OM_uint32 major;
    json_t *json;
    size_t i;

    *pJson = NULL;

    json = json_array();
    if (json == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    major = GSS_S_COMPLETE;

    for (i = 0; i < oidSet->count; i++) {
        json_t *oid;

        major = oidToJson(minor, &oidSet->elements[i], &oid);
        if (GSS_ERROR(major))
            break;

        json_array_append_new(json, oid);
    }

    if (GSS_ERROR(major))
        json_decref(json);
    else
        *pJson = json;

    return major;
}

OM_uint32
jsonToOid(OM_uint32 *minor,
          json_t *json,
          gss_OID *pOid)
{
    gss_buffer_desc stringBuf = GSS_C_EMPTY_BUFFER;

    if (!json_is_string(json)) {
        *pOid = GSS_C_NO_OID;
        return GSS_S_BAD_MECH;
    }

    stringBuf.length = strlen(json_string_value(json));
    stringBuf.value = (void *)json_string_value(json);

#ifdef HAVE_GSS_STR_TO_OID
    return gss_str_to_oid(minor, &stringBuf, pOid);
#elif defined(HAVE_HEIMDAL_VERSION)
    char mechbuf[64];
    size_t mech_len;
    heim_oid heimOid;
    int ret;
    gss_OID oid;

    if (der_parse_heim_oid(stringBuf.value, " .", &heimOid))
        return GSS_S_FAILURE;

    ret = der_put_oid((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
                      sizeof(mechbuf),
                      &heimOid,
                      &mech_len);
    if (ret) {
        der_free_oid(&heimOid);
        *minor = ret;
        return GSS_S_FAILURE;
    }

    oid = (gss_OID)GSSBID_MALLOC(sizeof(*oid));
    if (oid == NULL) {
        der_free_oid(&heimOid);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    oid->length = mech_len;
    oid->elements = GSSBID_MALLOC(oid->length);
    if (oid->elements == NULL) {
        der_free_oid(&heimOid);
        GSSBID_FREE(oid);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    memcpy(oid->elements, mechbuf + sizeof(mechbuf) - mech_len, mech_len);

    der_free_oid(&heimOid);

    *pOid = oid;
    return GSS_S_COMPLETE;
#else
#error no gss_str_to_oid
#endif /* HAVE_GSS_STR_TO_OID */
}

OM_uint32
jsonToOidSet(OM_uint32 *minor,
             json_t *json,
             gss_OID_set *pOidSet)
{
    OM_uint32 major, tmpMinor;
    gss_OID_set oidSet;
    size_t i;

    *pOidSet = GSS_C_NO_OID_SET;

    if (!json_is_array(json))
        return GSS_S_BAD_MECH;

    oidSet = (gss_OID_set)GSSBID_MALLOC(sizeof(*oidSet));
    if (oidSet == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    oidSet->count = 0;
    oidSet->elements = (gss_OID)GSSBID_CALLOC(json_array_size(json), sizeof(gss_OID_desc));
    if (oidSet->elements == NULL) {
        GSSBID_FREE(oidSet);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    major = GSS_S_COMPLETE;

    for (i = 0; i < json_array_size(json); i++) {
        json_t *oid = json_array_get(json, i);
        gss_OID tmpOid = GSS_C_NO_OID;

        major = jsonToOid(minor, oid, &tmpOid);
        if (GSS_ERROR(major))
            break;

        oidSet->elements[i] = *tmpOid;
        GSSBID_FREE(tmpOid);
        oidSet->count++;
    }

    if (GSS_ERROR(major))
        gss_release_oid_set(&tmpMinor, &oidSet);
    else
        *pOidSet = oidSet;

    return major;
}

