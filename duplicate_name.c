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
gss_duplicate_name(OM_uint32 *minor,
                   const gss_name_t input_name,
                   gss_name_t *dest_name)
{
    OM_uint32 major, tmpMinor;
    krb5_context krbContext;
    gss_name_t name;

    if (name == GSS_C_NO_NAME) {
        *minor = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;
    }

    GSSEAP_KRB_INIT(&krbContext);

    major = gssEapAllocName(minor, &name);
    if (GSS_ERROR(major)) {
        return major;
    }

    /* Lock mutex for copying mutable attributes */
    GSSEAP_MUTEX_LOCK(&input_name->mutex);

    *minor = krb5_copy_principal(krbContext, input_name->krbPrincipal,
                                 &name->krbPrincipal);
    if (*minor != 0) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    major = radiusDuplicateAVPs(minor, input_name->avps, &name->avps);
    if (GSS_ERROR(major))
        goto cleanup;

    major = samlDuplicateAssertion(minor, input_name->assertion, &name->assertion);
    if (GSS_ERROR(major))
        goto cleanup;

    *dest_name = name;

cleanup:
    GSSEAP_MUTEX_UNLOCK(&input_name->mutex);

    if (GSS_ERROR(major)) {
        gssEapReleaseName(&tmpMinor, &name);
    }

    return major;
}
