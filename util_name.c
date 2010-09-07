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
gssEapAllocName(OM_uint32 *minor, gss_name_t *pName)
{
    gss_name_t name;

    assert(*pName == GSS_C_NO_NAME);

    name = (gss_name_t)GSSEAP_CALLOC(1, sizeof(*name));
    if (name == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    *pName = name;

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseName(OM_uint32 *minor, gss_name_t *pName)
{
    gss_name_t name;
    krb5_context kerbCtx = NULL;

    if (pName == NULL) {
        return GSS_S_COMPLETE;
    }

    name = *pName;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_COMPLETE;
    }

    krb5_init_context(&kerbCtx);
    krb5_free_principal(kerbCtx, name->kerberosName);
    if (kerbCtx != NULL) {
        krb5_free_context(kerbCtx);
    }

    GSSEAP_FREE(name);
    *pName = NULL;

    *minor = 0;
    return GSS_S_COMPLETE;
}
