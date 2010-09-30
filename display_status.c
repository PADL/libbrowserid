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

static GSSEAP_THREAD_ONCE gssEapStatusInfoKeyOnce = GSSEAP_ONCE_INITIALIZER;
static GSSEAP_THREAD_KEY gssEapStatusInfoKey;

struct gss_eap_status_info {
    OM_uint32 code;
    char *message;
    struct gss_eap_status_info *next;
};

static void
destroyStatusInfo(void *arg)
{
    struct gss_eap_status_info *p = arg, *next;

    for (p = arg; p != NULL; p = next) {
        next = p->next;
        GSSEAP_FREE(p->message);
        GSSEAP_FREE(p);
    }
}

static void
createStatusInfoKey(void)
{
    GSSEAP_KEY_CREATE(&gssEapStatusInfoKey, destroyStatusInfo);
}

static void
saveStatusInfoNoCopy(OM_uint32 minor, char *message)
{
    struct gss_eap_status_info *info, *p;

    GSSEAP_ONCE(&gssEapStatusInfoKeyOnce, createStatusInfoKey);

    info = GSSEAP_CALLOC(1, sizeof(*info));
    if (info == NULL)
        return;

    info->code = minor;
    info->message = message;

    p = GSSEAP_GETSPECIFIC(gssEapStatusInfoKey);
    if (p == NULL) {
        GSSEAP_SETSPECIFIC(gssEapStatusInfoKey, info);
    } else {
        struct gss_eap_status_info **next = &p;

        for (; p != NULL; p = p->next)
            next = &p->next;

        *next = info;
    }
}

static const char *
getStatusInfo(OM_uint32 minor)
{
    struct gss_eap_status_info *p;

    GSSEAP_ONCE(&gssEapStatusInfoKeyOnce, createStatusInfoKey);

    for (p = GSSEAP_GETSPECIFIC(gssEapStatusInfoKey);
         p != NULL;
         p = p->next) {
        if (p->code == minor)
            return p->message;
    }

    return NULL;
}

void
gssEapSaveStatusInfo(OM_uint32 minor, const char *format, ...)
{
    char *s;
    int n;
    va_list ap;

    va_start(ap, format);
    n = vasprintf(&s, format, ap);
    va_end(ap);

    if (n >= 0)
        saveStatusInfoNoCopy(minor, s);
}

#if 0
void
gssEapSaveKrbStatusInfo(OM_uint32 minor)
{
    krb5_context krbContext = NULL;
    OM_uint32 tmpMinor;
    const char *s;

    gssEapKerberosInit(&tmpMinor, &krbContext);

    if (krbContext != NULL) {
        s = krb5_get_error_message(krbContext, minor);
        gssEapSaveStatusInfo(minor, "%s", s);
        krb5_set_error_message(krbContext, minor, "%s", s);
        krb5_free_error_message(krbContext, s);
    }
}
#endif

OM_uint32
gss_display_status(OM_uint32 *minor,
                   OM_uint32 status_value,
                   int status_type,
                   gss_OID mech_type,
                   OM_uint32 *message_context,
                   gss_buffer_t status_string)
{
    OM_uint32 major = GSS_S_COMPLETE;
    krb5_context krbContext;
    const char *errMsg;

    status_string->length = 0;
    status_string->value = NULL;

    if (!gssEapIsMechanismOid(mech_type)) {
        return GSS_S_BAD_MECH;
    }

    if (status_type != GSS_C_MECH_CODE) {
        /* we rely on the mechglue for GSS_C_GSS_CODE */
        return GSS_S_BAD_STATUS;
    }

    GSSEAP_KRB_INIT(&krbContext);

    errMsg = krb5_get_error_message(krbContext, status_value);

    if (errMsg != NULL) {
        major = makeStringBuffer(minor, errMsg, status_string);
    }

    krb5_free_error_message(krbContext, errMsg);

    return major;
}
