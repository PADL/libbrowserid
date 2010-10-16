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

#include <shibsp/exceptions.h>
#include <shibsp/attribute/SimpleAttribute.h>

#include <shibresolver/resolver.h>

#include <sstream>

#include "gssapiP_eap.h"

using namespace shibsp;
using namespace shibresolver;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

gss_eap_shib_attr_provider::gss_eap_shib_attr_provider(void)
{
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
gss_eap_shib_attr_provider::initFromExistingContext(const gss_eap_attr_ctx *manager,
                                                    const gss_eap_attr_provider *ctx)
{
    const gss_eap_shib_attr_provider *shib;

    if (!gss_eap_attr_provider::initFromExistingContext(manager, ctx)) {
        return false;
    }

    m_authenticated = false;

    shib = static_cast<const gss_eap_shib_attr_provider *>(ctx);
    if (shib != NULL) {
        m_attributes = duplicateAttributes(shib->getAttributes());
        m_authenticated = shib->authenticated();
    }

    return true;
}

bool
addRadiusAttribute(const gss_eap_attr_provider *provider,
                   const gss_buffer_t attribute,
                   void *data)
{
    const gss_eap_shib_attr_provider *shib;
    const gss_eap_radius_attr_provider *radius;
    int authenticated, complete, more = -1;
    vector <string> attributeIds(1);
    SimpleAttribute *a;

    radius = static_cast<const gss_eap_radius_attr_provider *>(provider);
    shib = static_cast<const gss_eap_shib_attr_provider *>(data);

    assert(radius != NULL && shib != NULL);

    string attributeName =
        gss_eap_attr_ctx::composeAttributeName(ATTR_TYPE_RADIUS, attribute);

    attributeIds.push_back(attributeName);
    a = new SimpleAttribute(attributeIds);
    if (a == NULL)
        return false;

    while (more != 0) {
        gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
        OM_uint32 minor;

        if (!radius->getAttribute(attribute,
                                  &authenticated,
                                  &complete,
                                  &value,
                                  NULL,
                                  &more))
            return false;

        string attributeValue((char *)value.value, value.length);
        a->getValues().push_back(attributeValue);

        gss_release_buffer(&minor, &value);
    }

    shib->getAttributes().push_back(a);

    return true;
}

bool
gss_eap_shib_attr_provider::initFromGssContext(const gss_eap_attr_ctx *manager,
                                               const gss_cred_id_t gssCred,
                                               const gss_ctx_id_t gssCtx)
{
    const gss_eap_saml_assertion_provider *saml;
    const gss_eap_radius_attr_provider *radius;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;
    ShibbolethResolver *resolver;
    OM_uint32 minor;

    if (!gss_eap_attr_provider::initFromGssContext(manager, gssCred, gssCtx))
        return false;

    saml = static_cast<const gss_eap_saml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));
    radius = static_cast<const gss_eap_radius_attr_provider *>
        (m_manager->getProvider(ATTR_TYPE_RADIUS));

    resolver = ShibbolethResolver::create();

    if (gssCred != GSS_C_NO_CREDENTIAL &&
        gssEapDisplayName(&minor, gssCred->name, &nameBuf, NULL) == GSS_S_COMPLETE)
        resolver->setApplicationID((const char *)nameBuf.value);

    m_authenticated = false;

    if (radius != NULL) {
        radius->getAttributeTypes(addRadiusAttribute, (void *)this);
        m_authenticated = radius->authenticated();
    }

    if (saml != NULL && saml->getAssertion() != NULL) {
        resolver->addToken(saml->getAssertion());
        if (m_authenticated)
            m_authenticated = saml->authenticated();
    }

    resolver->resolve();

    m_attributes = resolver->getResolvedAttributes();
    resolver->getResolvedAttributes().clear();

    gss_release_buffer(&minor, &nameBuf);

    delete resolver;

    return true;
}

ssize_t
gss_eap_shib_attr_provider::getAttributeIndex(const gss_buffer_t attr) const
{
    int i = 0;

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
gss_eap_shib_attr_provider::setAttribute(int complete,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
    string attrStr((char *)attr->value, attr->length);
    vector <string> ids(1, attrStr);
    SimpleAttribute *a = new SimpleAttribute(ids);

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
    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
        a != m_attributes.end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)((*a)->getId());
        attribute.length = strlen((char *)attribute.value);

        if (!addAttribute(this, &attribute, data))
            return false;
    }

    return true;
}

const Attribute *
gss_eap_shib_attr_provider::getAttribute(const gss_buffer_t attr) const
{
    const Attribute *ret = NULL;

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
    gss_buffer_desc buf;
    int nvalues, i = *more;

    *more = 0;

    shibAttr = getAttribute(attr);
    if (shibAttr == NULL)
        return false;

    nvalues = shibAttr->valueCount();

    if (i == -1)
        i = 0;
    else if (i >= nvalues)
        return false;

    buf.value = (void *)shibAttr->getString(*more);
    buf.length = strlen((char *)buf.value);

    if (buf.length != 0) {
        if (value != NULL)
            duplicateBuffer(buf, value);

        if (display_value != NULL)
            duplicateBuffer(buf, display_value);
    }

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = false;

    if (nvalues > ++i)
        *more = i;

    return true;
}

gss_any_t
gss_eap_shib_attr_provider::mapToAny(int authenticated,
                                     gss_buffer_t type_id) const
{
    gss_any_t output;

    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    vector <Attribute *>v = duplicateAttributes(m_attributes);

    output = (gss_any_t)new vector <Attribute *>(v);

    return output;
}

void
gss_eap_shib_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                  gss_any_t input) const
{
    vector <Attribute *> *v = ((vector <Attribute *> *)input);
    delete v;
}

void
gss_eap_shib_attr_provider::exportToBuffer(gss_buffer_t buffer) const
{
    DDF obj(NULL);
    DDF attrs(NULL);

    buffer->length = 0;
    buffer->value = NULL;

    obj.addmember("version").integer(1);
    obj.addmember("authenticated").integer(m_authenticated);

    attrs = obj.addmember("attributes").list();
    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
         a != m_attributes.end(); ++a) {
        DDF attr = (*a)->marshall();
        attrs.add(attr);
    }

    ostringstream sink;
    sink << attrs;
    string str = sink.str();

    duplicateBuffer(str, buffer);

    attrs.destroy();
}

bool
gss_eap_shib_attr_provider::initFromBuffer(const gss_eap_attr_ctx *ctx,
                                           const gss_buffer_t buffer)
{
    if (!gss_eap_attr_provider::initFromBuffer(ctx, buffer))
        return false;

    if (buffer->length == 0)
        return true;

    assert(m_authenticated == false);
    assert(m_attributes.size() == 0);

    DDF obj(NULL);
    string str((const char *)buffer->value, buffer->length);
    istringstream source(str);

    source >> obj;

    if (obj["version"].integer() != 1)
        return false;

    m_authenticated = (obj["authenticated"].integer() != 0);

    DDF attrs = obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        Attribute *attribute = Attribute::unmarshall(attr);
        m_attributes.push_back(attribute);
        attr = attrs.next();
    }

    attrs.destroy();

    return true;
}

bool
gss_eap_shib_attr_provider::init(void)
{
    if (!ShibbolethResolver::init())
        return false;

    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_LOCAL,
                                       NULL,
                                       gss_eap_shib_attr_provider::createAttrContext);

    return true;
}

void
gss_eap_shib_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_LOCAL);
    ShibbolethResolver::term();
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
    return GSS_S_COMPLETE;
}
