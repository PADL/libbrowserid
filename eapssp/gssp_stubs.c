/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * Stubs to avoid linking against libgssapi
 */
/*
 * Copyright (c) 1997 - 2001, 2003 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *        $FreeBSD: src/lib/libgssapi/gss_test_oid_set_member.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */
/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "gssp.h"

OM_uint32
GsspReleaseBuffer(OM_uint32 *minor, gss_buffer_t buffer)
{
    if (buffer != GSS_C_NO_BUFFER && buffer->value != NULL) {
        GsspFreePtr(buffer->value);
    }
    buffer->value = NULL;
    buffer->length = 0;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
GsspAddOidSetMember(OM_uint32 *minor_status,
    const gss_OID member_oid,
    gss_OID_set *oid_set)
{
    gss_OID tmp;
    size_t n;
    OM_uint32 res;
    int present;

    res = GsspTestOidSetMember(minor_status, member_oid, *oid_set, &present);
    if (res != GSS_S_COMPLETE)
        return res;

    if (present) {
        *minor_status = 0;
        return GSS_S_COMPLETE;
    }

    n = (*oid_set)->count + 1;
    tmp = GsspCallocPtr(n, sizeof(gss_OID_desc));
    if (tmp == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    RtlCopyMemory(tmp, (*oid_set)->elements, (n - 1) * sizeof(gss_OID_desc));

    (*oid_set)->elements = tmp;
    (*oid_set)->count = n;
    (*oid_set)->elements[n - 1] = *member_oid;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
GsspTestOidSetMember(OM_uint32 *minor_status,
    const gss_OID member,
    const gss_OID_set set,
    int *present)
{
    size_t i;

    *present = 0;
    for (i = 0; i < set->count; i++)
        if (oidEqual(member, &set->elements[i]))
            *present = 1;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
GsspReleaseOidSet(OM_uint32 *minor_status,
    gss_OID_set *set)
{
    *minor_status = 0;

    if (set != NULL && *set != GSS_C_NO_OID_SET) {
        if ((*set)->elements != NULL)
            GsspFreePtr((*set)->elements);
        GsspFreePtr(*set);
        *set = GSS_C_NO_OID_SET;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
GsspCreateEmptyOidSet(OM_uint32 *minor_status,
    gss_OID_set *oid_set)
{
    gss_OID_set set;

    *minor_status = 0;
    *oid_set = GSS_C_NO_OID_SET;

    set = GsspAllocPtr(sizeof(gss_OID_set_desc));
    if (set == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    set->count = 0;
    set->elements = NULL;

    *oid_set = set;

    return GSS_S_COMPLETE;
}

/* well known OIDs */
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_anonymous_oid_desc =
    {6, "\x2b\x06\01\x05\x06\x03"};
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_hostbased_service_oid_desc =
    {10, "\x2a\x86\x48\x86\xf7\x12" "\x01\x02\x01\x04"};
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_hostbased_service_x_oid_desc =
    {6, "\x2b\x06\x01\x05\x06\x02"};
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_export_name_oid_desc =
    {6, "\x2b\x06\x01\x05\x06\x04" };
gss_OID_desc GSSAPI_LIB_VARIABLE __gss_c_nt_user_name_oid_desc =
    {10, "\x2a\x86\x48\x86\xf7\x12" "\x01\x02\x01\x01"};

OM_uint32
GsspCreateEmptyBufferSet(
    OM_uint32 *minor_status,
    gss_buffer_set_t *buffer_set)
{
    gss_buffer_set_t set;

    set = (gss_buffer_set_desc *) GsspAllocPtr(sizeof(*set));
    if (set == GSS_C_NO_BUFFER_SET) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    set->count = 0;
    set->elements = NULL;

    *buffer_set = set;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
GsspAddBufferSetMember(
    OM_uint32 *minor_status,
    const gss_buffer_t member_buffer,
    gss_buffer_set_t *buffer_set)
{
    gss_buffer_set_t set;
    gss_buffer_t p;
    OM_uint32 ret;
    gss_buffer_desc *newElements;

    if (*buffer_set == GSS_C_NO_BUFFER_SET) {
        ret = GsspCreateEmptyBufferSet(minor_status, buffer_set);
        if (ret) {
            return ret;
        }
    }

    set = *buffer_set;

    newElements = GsspAllocPtr((set->count + 1) * sizeof(set->elements[0]));
    if (newElements == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    RtlCopyMemory(newElements, set->elements,
                  set->count * sizeof(set->elements[0]));
    GsspFree(set->elements);
    set->elements = newElements;

    p = &set->elements[set->count];

    p->value = GsspAllocPtr(member_buffer->length);
    if (p->value == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    RtlCopyMemory(p->value, member_buffer->value, member_buffer->length);
    p->length = member_buffer->length;

    set->count++;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
GsspReleaseBufferSet(
    OM_uint32 * minor_status,
    gss_buffer_set_t *buffer_set)
{
    size_t i;
    OM_uint32 minor;

    *minor_status = 0;

    if (*buffer_set == GSS_C_NO_BUFFER_SET)
        return GSS_S_COMPLETE;

    for (i = 0; i < (*buffer_set)->count; i++)
        GsspReleaseBuffer(&minor, &((*buffer_set)->elements[i]));

    GsspFreePtr((*buffer_set)->elements);

    (*buffer_set)->elements = NULL;
    (*buffer_set)->count = 0;

    GsspFreePtr(*buffer_set);
    *buffer_set = GSS_C_NO_BUFFER_SET;

    return GSS_S_COMPLETE;
}

