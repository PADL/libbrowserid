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

#include "gssapiP_eap.h"
#include "authdata_plugin.h"

/*
 * This rubbish is necessary because MIT doesn't provide another way
 * to access verified AD-KDCIssued elements. We can't verify them
 * ourselves because they're signed in the ticket session key, which
 * is destroyed immediately after the AP-REQ is processed.
 */

struct radius_ad_context {
    krb5_data avpdata;
    krb5_boolean verified;
};

static krb5_data radius_ad_attr = {
    KV5M_DATA, sizeof("urn:authdata-aaa-radius") - 1, "urn:authdata-aaa-radius" };

static krb5_error_code
radius_ad_init(krb5_context kcontext GSSEAP_UNUSED,
               void **plugin_context)
{
    *plugin_context = 0;
    return 0;
}

static void
radius_ad_flags(krb5_context kcontext GSSEAP_UNUSED,
                void *plugin_context GSSEAP_UNUSED,
                krb5_authdatatype ad_type GSSEAP_UNUSED,
                krb5_flags *flags)
{
    *flags = AD_USAGE_KDC_ISSUED | AD_INFORMATIONAL;
}

static void
radius_ad_fini(krb5_context kcontext GSSEAP_UNUSED,
               void *plugin_context GSSEAP_UNUSED)
{
    return;
}

static krb5_error_code
radius_ad_request_init(krb5_context kcontext GSSEAP_UNUSED,
                       struct _krb5_authdata_context *context GSSEAP_UNUSED,
                       void *plugin_context GSSEAP_UNUSED,
                       void **request_context)
{
    struct radius_ad_context *ctx;

    ctx = GSSEAP_CALLOC(1, sizeof(*ctx));
    if (ctx == NULL)
        return ENOMEM;

    *request_context = ctx;

    return 0;
}

static krb5_error_code
radius_ad_export_authdata(krb5_context kcontext,
                          struct _krb5_authdata_context *context GSSEAP_UNUSED,
                          void *plugin_context GSSEAP_UNUSED,
                          void *request_context,
                          krb5_flags usage GSSEAP_UNUSED,
                          krb5_authdata ***out_authdata)
{
    struct radius_ad_context *radius_ad = (struct radius_ad_context *)request_context;
    krb5_authdata *data[2];
    krb5_authdata datum;

    datum.ad_type = KRB5_AUTHDATA_RADIUS_AVP;
    datum.length = radius_ad->avpdata.length;
    datum.contents = (krb5_octet *)radius_ad->avpdata.data;

    data[0] = &datum;
    data[1] = NULL;

    return krb5_copy_authdata(kcontext, data, out_authdata);
}

static krb5_error_code
radius_ad_import_authdata(krb5_context kcontext,
                          struct _krb5_authdata_context *context GSSEAP_UNUSED,
                          void *plugin_context GSSEAP_UNUSED,
                          void *request_context,
                          krb5_authdata **authdata,
                          krb5_boolean kdc_issued_flag,
                          krb5_const_principal issuer GSSEAP_UNUSED)
{
    struct radius_ad_context *radius_ad = (struct radius_ad_context *)request_context;

    krb5_free_data_contents(kcontext, &radius_ad->avpdata);
    radius_ad->verified = FALSE;

    GSSEAP_ASSERT(authdata[0] != NULL);

    radius_ad->avpdata.data = GSSEAP_MALLOC(authdata[0]->length);
    if (radius_ad->avpdata.data == NULL)
        return ENOMEM;

    memcpy(radius_ad->avpdata.data, authdata[0]->contents,
           authdata[0]->length);
    radius_ad->avpdata.length = authdata[0]->length;

    radius_ad->verified = kdc_issued_flag;

    return 0;
}

static void
radius_ad_request_fini(krb5_context kcontext,
                       struct _krb5_authdata_context *context GSSEAP_UNUSED,
                       void *plugin_context GSSEAP_UNUSED,
                       void *request_context)
{
    struct radius_ad_context *radius_ad = (struct radius_ad_context *)request_context;

    if (radius_ad != NULL) {
        krb5_free_data_contents(kcontext, &radius_ad->avpdata);
        GSSEAP_FREE(radius_ad);
    }
}

static krb5_error_code
radius_ad_get_attribute(krb5_context kcontext GSSEAP_UNUSED,
                        struct _krb5_authdata_context *context GSSEAP_UNUSED,
                        void *plugin_context GSSEAP_UNUSED,
                        void *request_context,
                        const krb5_data *attribute,
                        krb5_boolean *authenticated,
                        krb5_boolean *complete,
                        krb5_data *value,
                        krb5_data *display_value GSSEAP_UNUSED,
                        int *more)
{
    struct radius_ad_context *radius_ad = (struct radius_ad_context *)request_context;

    if (attribute->length != radius_ad_attr.length ||
        memcmp(attribute->data, radius_ad_attr.data,
               radius_ad_attr.length) != 0)
        return ENOENT;

    if (radius_ad->avpdata.length == 0)
        return ENOENT;

    *authenticated = radius_ad->verified;
    *complete = TRUE;
    *more = 0;

    value->data = GSSEAP_MALLOC(radius_ad->avpdata.length);
    if (value->data == NULL)
        return ENOMEM;

    memcpy(value->data, radius_ad->avpdata.data, radius_ad->avpdata.length);
    value->length = radius_ad->avpdata.length;

    return 0;
}

static krb5_error_code
radius_ad_copy(krb5_context kcontext GSSEAP_UNUSED,
               struct _krb5_authdata_context *context GSSEAP_UNUSED,
               void *plugin_context GSSEAP_UNUSED,
               void *request_context,
               void *dst_plugin_context GSSEAP_UNUSED,
               void *dst_request_context)
{
    struct radius_ad_context *radius_ad_src =
        (struct radius_ad_context *)request_context;
    struct radius_ad_context *radius_ad_dst =
        (struct radius_ad_context *)dst_request_context;

    radius_ad_dst->avpdata.data = GSSEAP_MALLOC(radius_ad_src->avpdata.length);
    if (radius_ad_dst->avpdata.data == NULL)
        return ENOMEM;

    memcpy(radius_ad_dst->avpdata.data, radius_ad_src->avpdata.data,
           radius_ad_src->avpdata.length);
    radius_ad_dst->avpdata.length = radius_ad_src->avpdata.length;
    radius_ad_dst->verified = radius_ad_src->verified;

    return 0;
}

static krb5_authdatatype radius_ad_ad_types[] =
    { KRB5_AUTHDATA_RADIUS_AVP, 0 };

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "radius_ad",
    radius_ad_ad_types,
    radius_ad_init,
    radius_ad_fini,
    radius_ad_flags,
    radius_ad_request_init,
    radius_ad_request_fini,
    NULL,
    radius_ad_get_attribute,
    NULL,
    NULL,
    radius_ad_export_authdata,
    radius_ad_import_authdata,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    radius_ad_copy
};
