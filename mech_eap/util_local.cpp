/*
 * Copyright (c) 2018, JANET(UK)
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
 * Local attribute provider implementation.
 */


#include "gssapiP_eap.h"
#include "util_local.h"
#include <iostream>
using namespace std;


gss_eap_local_attr_provider::gss_eap_local_attr_provider(void)
{
    m_initialized = false;
    m_authenticated = true;
    m_attributes = NULL;
}

gss_eap_local_attr_provider::~gss_eap_local_attr_provider(void)
{
    json_decref(m_attributes);
}

bool
gss_eap_local_attr_provider::initWithExistingContext(const gss_eap_attr_ctx *manager,
                                                    const gss_eap_attr_provider *ctx)
{
    const gss_eap_local_attr_provider *provider;

    if (!gss_eap_attr_provider::initWithExistingContext(manager, ctx)) {
        return false;
    }

    m_authenticated = false;

    provider = static_cast<const gss_eap_local_attr_provider *>(ctx);
    if (provider != NULL) {
        m_attributes = json_deep_copy(provider->m_attributes);
        m_authenticated = provider->m_authenticated;
    }

    m_initialized = true;

    return true;
}

bool
gss_eap_local_attr_provider::initWithGssContext(const gss_eap_attr_ctx *manager,
                                               const gss_cred_id_t gssCred,
                                               const gss_ctx_id_t gssCtx)
{
    if (!gss_eap_attr_provider::initWithGssContext(manager, gssCred, gssCtx))
        return false;

    m_initialized = true;
    json_error_t error;

    m_attributes = json_load_file(MOONSHOT_LOCAL_ATTRIBUTES, 0, &error);
    if (!m_attributes) {
        if (error.line != -1)
            cout << MOONSHOT_LOCAL_ATTRIBUTES << " could not be open: " << error.text << error.line << endl;
    }
    m_authenticated = true;

    return true;
}

bool
gss_eap_local_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
    GSSEAP_ASSERT(m_initialized);

    if (value->length != 0) {
        json_t *values = json_array();
        string attr_value((char *)value->value, value->length);
        json_array_append_new(values, json_string(attr_value.c_str()));
        json_t *attribute = json_object();
        json_object_set_new(attribute, "values", values);
        string attr_name((char *)attr->value, attr->length);
        json_object_set_new(m_attributes, attr_name.c_str(), attribute);
        return true;
    }

    return false;
}

bool
gss_eap_local_attr_provider::deleteAttribute(const gss_buffer_t attr)
{
    GSSEAP_ASSERT(m_initialized);

    string attr_name((char *)attr->value, attr->length);

    return (json_object_del(m_attributes, attr_name.c_str()) >= 0);
}

bool
gss_eap_local_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    GSSEAP_ASSERT(m_initialized);
    const char *key;
    json_t *value;

    json_object_foreach(m_attributes, key, value) {
        gss_buffer_desc attribute;
        attribute.value = (void*) key;
        attribute.length = strlen(key);
        if (!addAttribute(m_manager, this, &attribute, data))
            return false;
    }

    return true;
}

bool
gss_eap_local_attr_provider::copyAttributeFrom(const char* attrname,
                                               int *authenticated,
                                               int *complete,
                                               gss_buffer_t value,
                                               gss_buffer_t display_value,
                                               int *more) const
{
    gss_buffer_desc attribute;
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;

    attribute.value = (void*) attrname;
    attribute.length = strlen(attrname);
    m_manager->decomposeAttributeName(&attribute, &prefix, &suffix);
    // we only copy from prefixed attributes, to avoid cycle loops
    if (prefix.length != 0) {
        return m_manager->getAttribute(&attribute, authenticated, complete,
                                       value, display_value, more);
    }
    return false;
}


bool
gss_eap_local_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    string attr_name((char *)attr->value, attr->length);

    json_t *jsonattr = json_object_get(m_attributes, attr_name.c_str());

    if (jsonattr && json_is_object(jsonattr)) {
        json_t* values = json_object_get(jsonattr, "values");
        json_t* copyfrom = json_object_get(jsonattr, "copy_from");

        if (values && json_is_array(values)) {
            int i = *more, nvalues;
            *complete = true;
            *authenticated = m_authenticated;
            *more = 0;

            if (i == -1)
                i = 0;
            nvalues = json_array_size(values);
            if (i >= nvalues)
                return false;
            json_t* jsonvalue = json_array_get(values, i);
            if (jsonvalue && json_is_string(jsonvalue)) {
                const char *strvalue = json_string_value(jsonvalue);
                value->value = strdup(strvalue);
                value->length = strlen(strvalue);
                display_value->value = strdup(strvalue);
                display_value->length = strlen(strvalue);
                if (nvalues > ++i)
                    *more = i;
                return true;
            }
        }
        else if (copyfrom && json_is_string(copyfrom) ) {
            return this->copyAttributeFrom(json_string_value(copyfrom),
                                           authenticated, complete, value,
                                           display_value, more);
        }
        else if (copyfrom && json_is_array(copyfrom) ) {
            size_t index;
            json_t *attrname;
            json_array_foreach(copyfrom, index, attrname) {
                if (json_is_string(attrname)) {
                    int new_more = *more;
                    bool result = this->copyAttributeFrom(json_string_value(attrname),
                                                          authenticated, complete, value,
                                                          display_value, &new_more);
                    if (result) {
                        *more = new_more;
                        return true;
                    }
                }
            }
            return false;
        }

    }
    return false;
}

gss_any_t
gss_eap_local_attr_provider::mapToAny(int authenticated,
                                     gss_buffer_t type_id GSSEAP_UNUSED) const
{
    gss_any_t output;

    GSSEAP_ASSERT(m_initialized);

    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    output = (gss_any_t) json_deep_copy(m_attributes);

    return output;
}

void
gss_eap_local_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                  gss_any_t input) const
{
    GSSEAP_ASSERT(m_initialized);

    json_t* attributes = ((json_t *) input);
    json_decref(attributes);
}

const char *
gss_eap_local_attr_provider::prefix(void) const
{
    return NULL;
}

const char *
gss_eap_local_attr_provider::name(void) const
{
    return "local";
}

JSONObject
gss_eap_local_attr_provider::jsonRepresentation(void) const
{
    JSONObject obj;

    if (m_initialized == false)
        return obj; /* don't export incomplete context */

    JSONObject jattrs = JSONObject(m_attributes);

    obj.set("attributes", jattrs);

    obj.set("authenticated", m_authenticated);

    return obj;
}

// TODO: FINISH THIS
bool
gss_eap_local_attr_provider::initWithJsonObject(const gss_eap_attr_ctx *ctx,
                                               JSONObject &obj)
{
    if (!gss_eap_attr_provider::initWithJsonObject(ctx, obj))
        return false;

    GSSEAP_ASSERT(m_attributes == NULL);

    JSONObject jattrs = obj["attributes"];

    m_attributes = jattrs.get();
    m_authenticated = obj["authenticated"].integer();
    m_initialized = true;

    return true;
}

bool
gss_eap_local_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_LOCAL, createAttrContext);
    return true;
}

void
gss_eap_local_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_LOCAL);
}

gss_eap_attr_provider *
gss_eap_local_attr_provider::createAttrContext(void)
{
    return new gss_eap_local_attr_provider;
}

OM_uint32
gssEapLocalAttrProviderInit(OM_uint32 *minor)
{
    if (!gss_eap_local_attr_provider::init()) {
        *minor = GSSEAP_SHIB_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}
