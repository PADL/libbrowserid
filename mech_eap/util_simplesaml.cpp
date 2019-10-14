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
 * Better-than-nothing SAML attribute provider implementation.
 */

#include "gssapiP_eap.h"
#include "util_simplesaml.h"
#include <string.h>

/*
 * gss_eap_saml_assertion_provider is for retrieving the underlying
 * assertion.
 */
gss_eap_simplesaml_assertion_provider::gss_eap_simplesaml_assertion_provider(void)
{
    m_assertion = NULL;
    m_authenticated = false;
}

gss_eap_simplesaml_assertion_provider::~gss_eap_simplesaml_assertion_provider(void)
{
    xmlFreeDoc(m_assertion);
}

bool
gss_eap_simplesaml_assertion_provider::initWithExistingContext(const gss_eap_attr_ctx *manager,
                                                               const gss_eap_attr_provider *ctx)
{
    /* Then we may be creating from an existing attribute context */
    const gss_eap_simplesaml_assertion_provider *saml;

    GSSEAP_ASSERT(m_assertion == NULL);

    if (!gss_eap_attr_provider::initWithExistingContext(manager, ctx))
        return false;

    saml = static_cast<const gss_eap_simplesaml_assertion_provider *>(ctx);
    if (saml->m_assertion) {
        this->m_assertion = xmlCopyDoc(saml->m_assertion, 1);
        this->m_authenticated = saml->m_authenticated;
    }
    return true;
}

bool
gss_eap_simplesaml_assertion_provider::initWithGssContext(const gss_eap_attr_ctx *manager,
                                                          const gss_cred_id_t gssCred,
                                                          const gss_ctx_id_t gssCtx)
{
    const gss_eap_radius_attr_provider *radius;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    int authenticated, complete;
    OM_uint32 minor;
    gss_eap_attrid attrid(VENDORPEC_UKERNA, PW_SAML_AAA_ASSERTION);

    GSSEAP_ASSERT(m_assertion == NULL);

    if (!gss_eap_attr_provider::initWithGssContext(manager, gssCred, gssCtx))
        return false;

    /*
     * XXX TODO we need to support draft-howlett-radius-saml-attr-00
     */
    radius = static_cast<const gss_eap_radius_attr_provider *>
        (m_manager->getProvider(ATTR_TYPE_RADIUS));
    if (radius != NULL && radius->getFragmentedAttribute(attrid, &authenticated, &complete, &value)) {
        this->m_assertion = xmlReadMemory((const char*) value.value, value.length, "noname.xml", NULL, 0);
        this->m_authenticated = authenticated;
        gss_release_buffer(&minor, &value);
    } else {
        m_assertion = NULL;
    }

    return true;
}

bool
gss_eap_simplesaml_assertion_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                                         void *data) const
{
    bool ret;

    /* just add the prefix */
    if (m_assertion != NULL)
        ret = addAttribute(m_manager, this, GSS_C_NO_BUFFER, data);
    else
        ret = true;

    return ret;
}

bool
gss_eap_simplesaml_assertion_provider::setAttribute(int complete GSSEAP_UNUSED,
                                                    const gss_buffer_t attr,
                                                    const gss_buffer_t value)
{
    if (attr == GSS_C_NO_BUFFER || attr->length == 0) {
        xmlFreeDoc(m_assertion);
        m_assertion = xmlReadMemory((const char*) value->value, value->length, "noname.xml", NULL, 0);
        return true;
    }

    return false;
}

bool
gss_eap_simplesaml_assertion_provider::deleteAttribute(const gss_buffer_t value GSSEAP_UNUSED)
{
    xmlFreeDoc(m_assertion);
    m_assertion = NULL;
    m_authenticated = false;

    return true;
}

bool
gss_eap_simplesaml_assertion_provider::getAttribute(const gss_buffer_t attr,
                                              int *authenticated,
                                              int *complete,
                                              gss_buffer_t value,
                                              gss_buffer_t display_value,
                                              int *more) const
{
    gss_buffer_desc str;
    OM_uint32 minor;
    int xmllen = 0;

    if (attr != GSS_C_NO_BUFFER && attr->length != 0)
        return false;

    if (m_assertion == NULL)
        return false;

    if (*more != -1)
        return false;

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    xmlDocDumpMemory(m_assertion, (xmlChar**) &str.value, &xmllen);
    str.length = xmllen;

    if (value != NULL)
        duplicateBuffer(str, value);
    if (display_value != NULL)
        duplicateBuffer(str, display_value);

    *more = 0;

    gss_release_buffer(&minor, &str);
    return true;
}

void gss_eap_simplesaml_assertion_provider::processAttribute(xmlNodePtr attribute, json_t *jattributes) const
{
    char *name = (char*) xmlGetProp(attribute, (const xmlChar*) "Name");
    char *nameFormat = (char*) xmlGetProp(attribute, (const xmlChar*) "NameFormat");
    xmlNodePtr value = NULL;
    if (name && nameFormat) {
        char* full_name = (char*) malloc(strlen(name) + strlen(nameFormat) + 2);
        strcpy(full_name, nameFormat);
        strcat(full_name, (char*) " ");
        strcat(full_name, name);
        json_t *values = json_array();
        for (value = attribute->children; value; value = value->next)
            if (value->type == XML_ELEMENT_NODE && strcmp((const char*) value->name, "AttributeValue") == 0) {
                xmlChar* node_value = xmlNodeListGetString(value->doc, value->children, 1);
                json_array_append_new(values, json_string((char*) node_value));
                xmlFree(node_value);
            }
        json_object_set_new(jattributes, full_name, values);
        free(full_name);
    }
    free(name);
    free(nameFormat);
}

void gss_eap_simplesaml_assertion_provider::processAttributeStatement(xmlNodePtr attributeStatement, json_t *jattributes) const
{
    xmlNodePtr node = NULL;
    for (node = attributeStatement->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && strcmp((const char*) node->name, "Attribute") == 0)
            processAttribute(node, jattributes);
    }
}

json_t *gss_eap_simplesaml_assertion_provider::processNameID(xmlNodePtr name_id_node) const
{
    char* name_id_format = (char*) xmlGetProp(name_id_node, (const xmlChar*) "Format");
    char* name_id = (char*) xmlNodeListGetString(name_id_node->doc, name_id_node->children, 1);
    json_t *jnameid = json_object();

    if (!name_id_format)
        name_id_format = strdup("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");

    json_object_set_new(jnameid, "format", json_string(name_id_format));
    json_object_set_new(jnameid, "value", json_string(name_id));
    free(name_id);
    free(name_id_format);
    return jnameid;
}

json_t *gss_eap_simplesaml_assertion_provider::processSubject(xmlNodePtr subject) const
{
    xmlNodePtr node = NULL;
    for (node = subject->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && strcmp((const char*) node->name, "NameID") == 0)
            return processNameID(node);
    }
    return NULL;
}

json_t* gss_eap_simplesaml_assertion_provider::getJsonAssertion() const
{
    if (!this->m_assertion)
        return NULL;
    xmlNodePtr assertion = xmlDocGetRootElement(this->m_assertion);
    xmlNodePtr node = NULL;
    json_t *jassertion = json_object();
    json_t *jattributes = json_object();
    json_t *name_id = NULL;

    for (node = assertion->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && strcmp((const char*) node->name, "AttributeStatement") == 0) {
            processAttributeStatement(node, jattributes);
        }
        if (node->type == XML_ELEMENT_NODE && strcmp((const char*) node->name, "Subject") == 0) {
            name_id = processSubject(node);
        }
    }

    json_object_set_new(jassertion, "attributes", jattributes);
    if (name_id)
        json_object_set_new(jassertion, "nameid", name_id);

    return jassertion;
}


gss_any_t
gss_eap_simplesaml_assertion_provider::mapToAny(int authenticated,
                                          gss_buffer_t type_id GSSEAP_UNUSED) const
{
    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    return (gss_any_t)m_assertion;
}

void
gss_eap_simplesaml_assertion_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                       gss_any_t input) const
{
    delete ((xmlDocPtr)input);
}

const char *
gss_eap_simplesaml_assertion_provider::prefix(void) const
{
    return "urn:ietf:params:gss:federated-saml-assertion";
}

bool
gss_eap_simplesaml_assertion_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_SAML_ASSERTION, createAttrContext);
    return true;
}

void
gss_eap_simplesaml_assertion_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_SAML_ASSERTION);
}

gss_eap_attr_provider *
gss_eap_simplesaml_assertion_provider::createAttrContext(void)
{
    return new gss_eap_simplesaml_assertion_provider;
}

/*
 * gss_eap_nameid_attr_provider is for retrieving the underlying NameID attributes.
 */
bool
gss_eap_nameid_attr_provider::getAssertion(int *authenticated, json_t **jassertion) const
{
    gss_eap_simplesaml_assertion_provider *saml;

    if (authenticated != NULL)
        *authenticated = false;
    if (jassertion != NULL)
        *jassertion = NULL;

    saml = static_cast<gss_eap_simplesaml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));
    if (saml == NULL)
        return false;

    if (authenticated != NULL)
        *authenticated = saml->authenticated();
    if (jassertion != NULL)
        *jassertion = saml->getJsonAssertion();

    return true;
}

bool
gss_eap_nameid_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    json_t *assertion = NULL;
    json_t *name_id = NULL;
    int authenticated;
    const char* name_id_format = NULL;
    if (!getAssertion(&authenticated, &assertion))
        return true;

    name_id = json_object_get(assertion, "nameid");
    if (!name_id)
        return true;

    name_id_format = json_string_value(json_object_get(name_id, "format"));
    gss_buffer_desc utf8;
    utf8.value = (void*) name_id_format;
    utf8.length = strlen(name_id_format);

    if (!addAttribute(m_manager, this, &utf8, data))
        return false;

    json_decref(assertion);
    return true;
}

bool
gss_eap_nameid_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                         const gss_buffer_t attr GSSEAP_UNUSED,
                                         const gss_buffer_t value GSSEAP_UNUSED)
{
    return false;
}

bool
gss_eap_nameid_attr_provider::deleteAttribute(const gss_buffer_t attr GSSEAP_UNUSED)
{
    return false;
}

bool
gss_eap_nameid_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    json_t *assertion = NULL, *name_id = NULL;
    const char *name_id_format = NULL;
    const char *name_id_value = NULL;

    if (*more != -1)
        return false;

    if (!getAssertion(authenticated, &assertion))
        return false;

    name_id = json_object_get(assertion, "nameid");
    if (!name_id)
        return false;

    *more = 0;
    *complete = 1;

    name_id_format = json_string_value(json_object_get(name_id, "format"));
    name_id_value = json_string_value(json_object_get(name_id, "value"));

    string str((const char *)attr->value, attr->length);
    if (strcmp(name_id_format, str.c_str()))
        return false;

    if (value != NULL) {
        value->value = strdup(name_id_value);
        value->length = strlen(name_id_value);
    }
    if (display_value != NULL) {
        display_value->value = strdup(name_id_value);
        display_value->length = strlen(name_id_value);
    }
    json_decref(assertion);
    return true;
}

gss_any_t
gss_eap_nameid_attr_provider::mapToAny(int authenticated GSSEAP_UNUSED,
                                     gss_buffer_t type_id GSSEAP_UNUSED) const
{
    return (gss_any_t)NULL;
}

void
gss_eap_nameid_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                  gss_any_t input GSSEAP_UNUSED) const
{
}

const char *
gss_eap_nameid_attr_provider::prefix(void) const
{
    return "urn:ietf:params:gss:federated-saml-nameid";
}

bool
gss_eap_nameid_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_NAMEID, createAttrContext);
    return true;
}

void
gss_eap_nameid_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_NAMEID);
}

gss_eap_attr_provider *
gss_eap_nameid_attr_provider::createAttrContext(void)
{
    return new gss_eap_nameid_attr_provider;
}

/*
 * gss_eap_saml_attr_provider is for retrieving the underlying NameID attributes.
 */
bool
gss_eap_saml_attr_provider::getAssertion(int *authenticated, json_t **jassertion) const
{
    gss_eap_simplesaml_assertion_provider *saml;

    if (authenticated != NULL)
        *authenticated = false;
    if (jassertion != NULL)
        *jassertion = NULL;

    saml = static_cast<gss_eap_simplesaml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));
    if (saml == NULL)
        return false;

    if (authenticated != NULL)
        *authenticated = saml->authenticated();
    if (jassertion != NULL)
        *jassertion = saml->getJsonAssertion();

    return true;
}

bool
gss_eap_saml_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    int authenticated;
    json_t *jassertion = NULL, *jattributes = NULL;
    const char *key = NULL;
    json_t *value = NULL;

    if (!getAssertion(&authenticated, &jassertion))
        return true;

    jattributes = json_object_get(jassertion, "attributes");
    json_object_foreach(jattributes, key, value) {
        gss_buffer_desc utf8;
        utf8.value = (void*) key;
        utf8.length = strlen(key);
        if (!addAttribute(m_manager, this, &utf8, data))
            return false;
    }

    json_decref(jassertion);
    return true;
}

bool
gss_eap_saml_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                         const gss_buffer_t attr GSSEAP_UNUSED,
                                         const gss_buffer_t value GSSEAP_UNUSED)
{
    return false;
}

bool
gss_eap_saml_attr_provider::deleteAttribute(const gss_buffer_t attr GSSEAP_UNUSED)
{
    return false;
}

bool
gss_eap_saml_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    json_t* assertion = NULL;
    json_t* jattributes = NULL;
    json_t *values = NULL;
    int i = *more, nvalues;
    string attr_name((char *)attr->value, attr->length);
    bool rv = false;

    *complete = true;
    *more = 0;
    if (i == -1)
        i = 0;

    if (getAssertion(authenticated, &assertion)) {
        jattributes = json_object_get(assertion, "attributes");
        values = json_object_get(jattributes, attr_name.c_str());

        nvalues = json_array_size(values);
        if (i < nvalues) {
            const char *strvalue = json_string_value(json_array_get(values, i));
            value->value = strdup(strvalue);
            value->length = strlen(strvalue);
            display_value->value = strdup(strvalue);
            display_value->length = strlen(strvalue);
            if (nvalues > ++i)
                *more = i;
            rv = true;
        }
    }

    json_decref(assertion);
    return rv;
}

gss_any_t
gss_eap_saml_attr_provider::mapToAny(int authenticated GSSEAP_UNUSED,
                                     gss_buffer_t type_id GSSEAP_UNUSED) const
{
    return (gss_any_t)NULL;
}

void
gss_eap_saml_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                  gss_any_t input GSSEAP_UNUSED) const
{
}

const char *
gss_eap_saml_attr_provider::prefix(void) const
{
    return "urn:ietf:params:gss:federated-saml-attribute";
}

bool
gss_eap_saml_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_SAML, createAttrContext);
    return true;
}

void
gss_eap_saml_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_SAML);
}

gss_eap_attr_provider *
gss_eap_saml_attr_provider::createAttrContext(void)
{
    return new gss_eap_saml_attr_provider;
}


OM_uint32
gssEapSimpleSamlAttrProvidersInit(OM_uint32 *minor)
{
    if (!gss_eap_simplesaml_assertion_provider::init() ||
        !gss_eap_nameid_attr_provider::init() ||
        !gss_eap_saml_attr_provider::init()) {
        *minor = GSSEAP_SAML_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapSimpleSamlAttrProvidersFinalize(OM_uint32 *minor)
{
    gss_eap_saml_attr_provider::finalize();
    gss_eap_nameid_attr_provider::finalize();
    gss_eap_simplesaml_assertion_provider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}

