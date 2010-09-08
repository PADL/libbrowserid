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

static GSSEAP_THREAD_ONCE krbContextKeyOnce = GSSEAP_ONCE_INITIALIZER;
static GSSEAP_THREAD_KEY krbContextKey;

static void
destroyKrbContext(void *arg)
{
    krb5_context context = (krb5_context)arg;

    if (context != NULL)
        krb5_free_context(context);
}

static void
createKrbContextKey(void)
{
    GSSEAP_KEY_CREATE(&krbContextKey, destroyKrbContext);
}

OM_uint32
gssEapKerberosInit(OM_uint32 *minor, krb5_context *context)
{
    *minor = 0;

    GSSEAP_ONCE(&krbContextKeyOnce, createKrbContextKey);

    *context = GSSEAP_GETSPECIFIC(krbContextKey);
    if (*context == NULL) {
        *minor = krb5_init_context(context);
        if (*minor == 0) {
            if (GSSEAP_SETSPECIFIC(krbContextKey, *context) != 0) {
                *minor = errno;
                krb5_free_context(*context);
                *context = NULL;
            }
        }
    }

    return *minor == 0 ? GSS_S_COMPLETE : GSS_S_FAILURE;
}
