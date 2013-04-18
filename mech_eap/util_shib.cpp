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
 * Copyright 2001-2009 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Local attribute provider implementation.
 */

#include "gssapiP_eap.h"

#include <xmltooling/XMLObject.h>
#ifndef HAVE_OPENSAML
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#endif

#include <saml/saml2/core/Assertions.h>

#include <shibsp/exceptions.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/BinaryAttribute.h>
#include <shibsp/attribute/ScopedAttribute.h>
#include <shibresolver/resolver.h>

#include <sstream>

using namespace shibsp;
using namespace shibresolver;
using namespace xmltooling;
using namespace std;
#ifdef HAVE_OPENSAML
using namespace opensaml::saml2md;
using namespace opensaml;
#else
using namespace xercesc;
#endif

gss_eap_shib_attr_provider::gss_eap_shib_attr_provider(void)
{
    m_initialized = false;
    m_authenticated = false;
}

gss_eap_shib_attr_provider::~gss_eap_shib_attr_provider(void)
{
    for_each(m_attributes.begin(),
             m_attributes.end(),
             xmltooling::cleanup<Attribute>())
        ;
}

bool
gss_eap_shib_attr_provider::initWithExistingContext(const gss_eap_attr_ctx *manager,
                                                    const gss_eap_attr_provider *ctx)
{
    const gss_eap_shib_attr_provider *shib;

    if (!gss_eap_attr_provider::initWithExistingContext(manager, ctx)) {
        return false;
    }

    m_authenticated = false;

    shib = static_cast<const gss_eap_shib_attr_provider *>(ctx);
    if (shib != NULL) {
        m_attributes = duplicateAttributes(shib->getAttributes());
        m_authenticated = shib->authenticated();
    }

    m_initialized = true;

    return true;
}

bool
gss_eap_shib_attr_provider::initWithGssContext(const gss_eap_attr_ctx *manager,
                                               const gss_cred_id_t gssCred,
                                               const gss_ctx_id_t gssCtx)
{
    if (!gss_eap_attr_provider::initWithGssContext(manager, gssCred, gssCtx))
        return false;

    auto_ptr<ShibbolethResolver> resolver(ShibbolethResolver::create());

    /*
     * For now, leave ApplicationID defaulted.
     * Later on, we could allow this via config option to the mechanism
     * or rely on an SPRequest interface to pass in a URI identifying the
     * acceptor.
     */
#if 0
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;
    if (gssCred != GSS_C_NO_CREDENTIAL &&
        gssEapDisplayName(&minor, gssCred->name, &nameBuf, NULL) == GSS_S_COMPLETE) {
        resolver->setApplicationID((const char *)nameBuf.value);
        gss_release_buffer(&minor, &nameBuf);
    }
#endif

    gss_buffer_desc mechName = GSS_C_EMPTY_BUFFER;
    OM_uint32 major, minor;

    major = gssEapExportNameInternal(&minor, gssCtx->initiatorName, &mechName,
                                     EXPORT_NAME_FLAG_OID |
                                     EXPORT_NAME_FLAG_COMPOSITE);
    if (major == GSS_S_COMPLETE) {
        resolver->addToken(&mechName);
        gss_release_buffer(&minor, &mechName);
    }

#ifdef HAVE_OPENSAML
    const gss_eap_saml_assertion_provider *saml;
    saml = static_cast<const gss_eap_saml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));
    if (saml != NULL && saml->getAssertion() != NULL) {
        resolver->addToken(saml->getAssertion());
    }
#else
    /* If no OpenSAML, parse the XML assertion explicitly */
    const gss_eap_radius_attr_provider *radius;
    int authenticated, complete;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    gss_eap_attrid attrid(VENDORPEC_UKERNA, PW_SAML_AAA_ASSERTION);

    radius = static_cast<const gss_eap_radius_attr_provider *>
        (m_manager->getProvider(ATTR_TYPE_RADIUS));
    if (radius != NULL &&
        radius->getFragmentedAttribute(attrid, &authenticated, &complete, &value)) {
        string str((char *)value.value, value.length);
        istringstream istream(str);
        DOMDocument *doc = XMLToolingConfig::getConfig().getParser().parse(istream);
        const XMLObjectBuilder *b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        resolver->addToken(b->buildFromDocument(doc));
        gss_release_buffer(&minor, &value);
    }
#endif /* HAVE_OPENSAML */

    try {
        resolver->resolve();
        m_attributes = resolver->getResolvedAttributes();
        resolver->getResolvedAttributes().clear();
    } catch (exception &e) {
        return false;
    }

    m_authenticated = true;
    m_initialized = true;

    return true;
}

ssize_t
gss_eap_shib_attr_provider::getAttributeIndex(const gss_buffer_t attr) const
{
    int i = 0;

    GSSEAP_ASSERT(m_initialized);

    for (vector<Attribute *>::const_iterator a = m_attributes.begin();
         a != m_attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == (*s).length() &&
                memcmp((*s).c_str(), attr->value, attr->length) == 0) {
                return i;
            }
        }
    }

    return -1;
}

bool
gss_eap_shib_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
    string attrStr((char *)attr->value, attr->length);
    vector <string> ids(1, attrStr);
    BinaryAttribute *a = new BinaryAttribute(ids);

    GSSEAP_ASSERT(m_initialized);

    if (value->length != 0) {
        string valueStr((char *)value->value, value->length);

        a->getValues().push_back(valueStr);
    }

    m_attributes.push_back(a);
    m_authenticated = false;

    return true;
}

bool
gss_eap_shib_attr_provider::deleteAttribute(const gss_buffer_t attr)
{
    int i;

    GSSEAP_ASSERT(m_initialized);

    i = getAttributeIndex(attr);
    if (i >= 0)
        m_attributes.erase(m_attributes.begin() + i);

    m_authenticated = false;

    return true;
}

bool
gss_eap_shib_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    GSSEAP_ASSERT(m_initialized);

    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
        a != m_attributes.end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)((*a)->getId());
        attribute.length = strlen((char *)attribute.value);

        if (!addAttribute(m_manager, this, &attribute, data))
            return false;
    }

    return true;
}

const Attribute *
gss_eap_shib_attr_provider::getAttribute(const gss_buffer_t attr) const
{
    const Attribute *ret = NULL;

    GSSEAP_ASSERT(m_initialized);

    for (vector<Attribute *>::const_iterator a = m_attributes.begin();
         a != m_attributes.end();
         ++a)
    {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == (*s).length() &&
                memcmp((*s).c_str(), attr->value, attr->length) == 0) {
                ret = *a;
                break;
            }
        }
        if (ret != NULL)
            break;
    }

    return ret;
}

bool
gss_eap_shib_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    const Attribute *shibAttr = NULL;
    const BinaryAttribute *binaryAttr;
    gss_buffer_desc valueBuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc displayValueBuf = GSS_C_EMPTY_BUFFER;
    int nvalues, i = *more;

    GSSEAP_ASSERT(m_initialized);

    *more = 0;

    shibAttr = getAttribute(attr);
    if (shibAttr == NULL)
        return false;

    nvalues = shibAttr->valueCount();

    if (i == -1)
        i = 0;
    if (i >= nvalues)
        return false;

    binaryAttr = dynamic_cast<const BinaryAttribute *>(shibAttr);
    if (binaryAttr != NULL) {
        std::string str = binaryAttr->getValues()[*more];

        valueBuf.value = (void *)str.data();
        valueBuf.length = str.size();
    } else {
        std::string str = shibAttr->getSerializedValues()[*more];

        valueBuf.value = (void *)str.c_str();
        valueBuf.length = str.length();

        const SimpleAttribute *simpleAttr =
            dynamic_cast<const SimpleAttribute *>(shibAttr);
        const ScopedAttribute *scopedAttr =
            dynamic_cast<const ScopedAttribute *>(shibAttr);
        if (simpleAttr != NULL || scopedAttr != NULL)
            displayValueBuf = valueBuf;
    }

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;
    if (value != NULL)
        duplicateBuffer(valueBuf, value);
    if (display_value != NULL)
        duplicateBuffer(displayValueBuf, display_value);
    if (nvalues > ++i)
        *more = i;

    return true;
}

gss_any_t
gss_eap_shib_attr_provider::mapToAny(int authenticated,
                                     gss_buffer_t type_id GSSEAP_UNUSED) const
{
    gss_any_t output;

    GSSEAP_ASSERT(m_initialized);

    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    vector <Attribute *>v = duplicateAttributes(m_attributes);

    output = (gss_any_t)new vector <Attribute *>(v);

    return output;
}

void
gss_eap_shib_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                  gss_any_t input) const
{
    GSSEAP_ASSERT(m_initialized);

    vector <Attribute *> *v = ((vector <Attribute *> *)input);
    delete v;
}

const char *
gss_eap_shib_attr_provider::prefix(void) const
{
    return NULL;
}

const char *
gss_eap_shib_attr_provider::name(void) const
{
    return "local";
}

JSONObject
gss_eap_shib_attr_provider::jsonRepresentation(void) const
{
    JSONObject obj;

    if (m_initialized == false)
        return obj; /* don't export incomplete context */

    JSONObject jattrs = JSONObject::array();

    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
         a != m_attributes.end(); ++a) {
        DDF attr = (*a)->marshall();
        JSONObject jattr = JSONObject::ddf(attr);
        jattrs.append(jattr);
    }

    obj.set("attributes", jattrs);

    obj.set("authenticated", m_authenticated);

    return obj;
}

bool
gss_eap_shib_attr_provider::initWithJsonObject(const gss_eap_attr_ctx *ctx,
                                               JSONObject &obj)
{
    if (!gss_eap_attr_provider::initWithJsonObject(ctx, obj))
        return false;

    GSSEAP_ASSERT(m_authenticated == false);
    GSSEAP_ASSERT(m_attributes.size() == 0);

    JSONObject jattrs = obj["attributes"];
    size_t nelems = jattrs.size();

    for (size_t i = 0; i < nelems; i++) {
        JSONObject jattr = jattrs.get(i);

        DDF attr = jattr.ddf();
        Attribute *attribute = Attribute::unmarshall(attr);
        m_attributes.push_back(attribute);
    }

    m_authenticated = obj["authenticated"].integer();
    m_initialized = true;

    return true;
}

bool
gss_eap_shib_attr_provider::init(void)
{
    bool ret = false;

    try {
        ret = ShibbolethResolver::init();
    } catch (exception &e) {
    }

    if (ret)
        gss_eap_attr_ctx::registerProvider(ATTR_TYPE_LOCAL, createAttrContext);

    return ret;
}

void
gss_eap_shib_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_LOCAL);
    ShibbolethResolver::term();
}

OM_uint32
gss_eap_shib_attr_provider::mapException(OM_uint32 *minor,
                                         std::exception &e) const
{
    if (typeid(e) == typeid(AttributeException))
        *minor = GSSEAP_SHIB_ATTR_FAILURE;
    else if (typeid(e) == typeid(AttributeExtractionException))
        *minor = GSSEAP_SHIB_ATTR_EXTRACT_FAILURE;
    else if (typeid(e) == typeid(AttributeFilteringException))
        *minor = GSSEAP_SHIB_ATTR_FILTER_FAILURE;
    else if (typeid(e) == typeid(AttributeResolutionException))
        *minor = GSSEAP_SHIB_ATTR_RESOLVE_FAILURE;
    else if (typeid(e) == typeid(ConfigurationException))
        *minor = GSSEAP_SHIB_CONFIG_FAILURE;
    else if (typeid(e) == typeid(ListenerException))
        *minor = GSSEAP_SHIB_LISTENER_FAILURE;
    else
        return GSS_S_CONTINUE_NEEDED;

    gssEapSaveStatusInfo(*minor, "%s", e.what());

    return GSS_S_FAILURE;
}

gss_eap_attr_provider *
gss_eap_shib_attr_provider::createAttrContext(void)
{
    return new gss_eap_shib_attr_provider;
}

Attribute *
gss_eap_shib_attr_provider::duplicateAttribute(const Attribute *src)
{
    DDF obj = src->marshall();
    Attribute *attribute = Attribute::unmarshall(obj);
    obj.destroy();

    return attribute;
}

vector <Attribute *>
gss_eap_shib_attr_provider::duplicateAttributes(const vector <Attribute *>src)
{
    vector <Attribute *> dst;

    for (vector<Attribute *>::const_iterator a = src.begin();
         a != src.end();
         ++a)
        dst.push_back(duplicateAttribute(*a));

    return dst;
}

OM_uint32
gssEapLocalAttrProviderInit(OM_uint32 *minor)
{
    if (!gss_eap_shib_attr_provider::init()) {
        *minor = GSSEAP_SHIB_INIT_FAILURE;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapLocalAttrProviderFinalize(OM_uint32 *minor)
{
    gss_eap_shib_attr_provider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}
