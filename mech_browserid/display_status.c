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
 * Function for converting mechanism error codes to strings.
 */

#include "gssapiP_bid.h"

struct gss_bid_status_info {
    OM_uint32 code;
    char *message;
    struct gss_bid_status_info *next;
};

void
gssBidDestroyStatusInfo(struct gss_bid_status_info *p)
{
    struct gss_bid_status_info *next;

    for (; p != NULL; p = next) {
        next = p->next;
        GSSBID_FREE(p->message);
        GSSBID_FREE(p);
    }
}

/*
 * Associate a message with a mechanism (minor) status code. This function
 * takes ownership of the message regardless of success. The message must
 * be explicitly cleared, if required, so it is suggested that a specific
 * minor code is either always or never associated with a message, to avoid
 * dangling (and potentially confusing) error messages.
 */
static void
saveStatusInfoNoCopy(OM_uint32 minor, char *message)
{
    struct gss_bid_status_info **next = NULL, *p = NULL;
    struct gss_bid_thread_local_data *tld = gssBidGetThreadLocalData();

    if (tld != NULL) {
        for (p = tld->statusInfo; p != NULL; p = p->next) {
            if (p->code == minor) {
                /* Set message in-place */
                if (p->message != NULL)
                    GSSBID_FREE(p->message);
                p->message = message;
                return;
            }
            next = &p->next;
        }
        p = GSSBID_CALLOC(1, sizeof(*p));
    }

    if (p == NULL) {
        if (message != NULL)
            GSSBID_FREE(message);
        return;
    }

    p->code = minor;
    p->message = message;

    if (next != NULL)
        *next = p;
    else
        tld->statusInfo = p;
}

static const char *
getStatusInfo(OM_uint32 minor)
{
    struct gss_bid_status_info *p;
    struct gss_bid_thread_local_data *tld = gssBidGetThreadLocalData();

    if (tld != NULL) {
        for (p = tld->statusInfo; p != NULL; p = p->next) {
            if (p->code == minor)
                return p->message;
        }
    }
    return NULL;
}

void
gssBidSaveStatusInfo(OM_uint32 minor, const char *format, ...)
{
#ifdef WIN32
    OM_uint32 tmpMajor, tmpMinor;
    char buf[BUFSIZ];
    gss_buffer_desc s = GSS_C_EMPTY_BUFFER;
    va_list ap;

    if (format != NULL) {
        va_start(ap, format);
        snprintf(buf, sizeof(buf), format, ap);
        va_end(ap);
    }

    tmpMajor = makeStringBuffer(&tmpMinor, buf, &s);
    if (!GSS_ERROR(tmpMajor))
        saveStatusInfoNoCopy(minor, (char *)s.value);
#else
    char *s = NULL;
    int n;
    va_list ap;

    if (format != NULL) {
        va_start(ap, format);
        n = vasprintf(&s, format, ap);
        if (n == -1)
            s = NULL;
        va_end(ap);
    }

    saveStatusInfoNoCopy(minor, s);
#endif /* WIN32 */
}

OM_uint32
gssBidDisplayStatus(OM_uint32 *minor,
                    OM_uint32 status_value,
                    gss_buffer_t status_string)
{
    OM_uint32 major;
    krb5_context krbContext = NULL;
    const char *errMsg;

    status_string->length = 0;
    status_string->value = NULL;

    errMsg = getStatusInfo(status_value);
    if (errMsg == NULL) {
        GSSBID_KRB_INIT(&krbContext);

        /* Try the com_err message */
        errMsg = krb5_get_error_message(krbContext, status_value);
    }

    if (errMsg != NULL) {
        major = makeStringBuffer(minor, errMsg, status_string);
    } else {
        major = GSS_S_COMPLETE;
        *minor = 0;
    }

    if (krbContext != NULL)
        krb5_free_error_message(krbContext, errMsg);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
gss_display_status(OM_uint32 *minor,
                   OM_uint32 status_value,
                   int status_type,
                   gss_OID mech_type,
                   OM_uint32 *message_context,
                   gss_buffer_t status_string)
{
    if (!gssBidIsMechanismOid(mech_type)) {
        *minor = GSSBID_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (status_type != GSS_C_MECH_CODE ||
        *message_context != 0) {
        /* we rely on the mechglue for GSS_C_GSS_CODE */
        *minor = 0;
        return GSS_S_BAD_STATUS;
    }

    return gssBidDisplayStatus(minor, status_value, status_string);
}
