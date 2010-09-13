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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "util.h"

#include <shibsp/Application.h>
#include <shibsp/exceptions.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>
#include <shibsp/util/SPConstants.h>

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

class GSSEAPResolver : public shibsp::AssertionConsumerService
{
public:
    GSSEAPResolver(const DOMElement *e, const char *appId)
        : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".GSSEAPResolver")) {
    }
    virtual ~GSSEAPResolver() {}

    ResolutionContext* resolveAttributes (
        const Application& application,
        const RoleDescriptor* issuer,
        const XMLCh* protocol,
        const saml1::NameIdentifier* v1nameid,
        const saml2::NameID* nameid,
        const XMLCh* authncontext_class,
        const XMLCh* authncontext_decl,
        const vector<const Assertion*>* tokens
        ) const {
            return shibsp::AssertionConsumerService::resolveAttributes(
                    application, issuer, protocol, v1nameid,
                    nameid, authncontext_class, authncontext_decl, tokens
            );
    }

private:
    void implementProtocol(
        const Application& application,
        const HTTPRequest& httpRequest,
        HTTPResponse& httpResponse,
        SecurityPolicy& policy,
        const PropertySet* settings,
        const XMLObject& xmlObject
        ) const {
            throw FatalProfileException("Should never be called.");
    }
};

struct eap_gss_saml_attr_ctx {
public:
    eap_gss_saml_attr_ctx();
    eap_gss_saml_attr_ctx(const gss_buffer_t buffer);
    eap_gss_saml_attr_ctx(const Assertion *assertion);

    eap_gss_saml_attr_ctx(const vector<Attribute*>& attributes,
                          const Assertion *assertion);

    eap_gss_saml_attr_ctx(const eap_gss_saml_attr_ctx &ctx) {
        eap_gss_saml_attr_ctx(ctx.m_attributes, ctx.m_assertion);
    }

    ~eap_gss_saml_attr_ctx();

    const vector <Attribute *> getAttributes(void) const {
        return m_attributes;
    }

    void addAttribute(Attribute *attr, bool copy = true);
    void setAttributes(const vector<Attribute*> attributes);

    void setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    void deleteAttribute(const gss_buffer_t attr);

    int getAttributeIndex(const gss_buffer_t attr) const;
    const Attribute *getAttribute(const gss_buffer_t attr) const;

    bool getAttribute(const gss_buffer_t attr,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more);

    const Assertion *getAssertion(void) const {
        return m_assertion;
    }

    bool getAssertion(gss_buffer_t buffer);

    DDF marshall() const;
    static eap_gss_saml_attr_ctx *unmarshall(DDF &in);

    void marshall(gss_buffer_t buffer);
    static eap_gss_saml_attr_ctx *unmarshall(const gss_buffer_t buffer);

private:
    mutable vector<Attribute*> m_attributes;
    mutable Assertion *m_assertion;

    bool parseAssertion(const gss_buffer_t buffer);
};

eap_gss_saml_attr_ctx::eap_gss_saml_attr_ctx(const vector<Attribute*>& attributes,
                                             const Assertion *assertion)
{
    m_assertion = dynamic_cast<Assertion *>(assertion->clone());
    setAttributes(attributes);
}

eap_gss_saml_attr_ctx::~eap_gss_saml_attr_ctx()
{
    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    delete m_assertion;
}

eap_gss_saml_attr_ctx::eap_gss_saml_attr_ctx(const gss_buffer_t buffer)
{
    parseAssertion(buffer);
}

static OM_uint32
mapException(OM_uint32 *minor, exception &e)
{
    return GSS_S_FAILURE;
}

bool
eap_gss_saml_attr_ctx::parseAssertion(const gss_buffer_t buffer)
{
    DOMDocument *doc;
    const XMLObjectBuilder *b;
    DOMElement *elem;
    XMLObject *xobj;
    string str((char *)buffer->value, buffer->length);
    istringstream istream(str);

    doc = XMLToolingConfig::getConfig().getParser().parse(istream);
    b = XMLObjectBuilder::getDefaultBuilder();
    elem = doc->getDocumentElement();
    xobj = b->buildOneFromElement(elem, true);

    m_assertion = dynamic_cast<Assertion *>(xobj);

    return (m_assertion != NULL);
}

static inline void
duplicateBuffer(gss_buffer_desc &src, gss_buffer_t dst)
{
    OM_uint32 minor;

    if (GSS_ERROR(duplicateBuffer(&minor, &src, dst)))
        throw new bad_alloc();
}

static inline void
duplicateBuffer(string &str, gss_buffer_t buffer)
{
    gss_buffer_desc tmp;

    tmp.length = str.length();
    tmp.value = (char *)str.c_str();

    duplicateBuffer(tmp, buffer);
}

DDF
eap_gss_saml_attr_ctx::marshall() const
{
    DDF obj(NULL);
    DDF attrs;
    DDF assertion;

    obj.addmember("version").integer(1);

    attrs = obj.addmember("attributes").list();
    for (vector<Attribute*>::const_iterator a = m_attributes.begin();
         a != m_attributes.end(); ++a) {
        DDF attr = (*a)->marshall();
        attrs.add(attr);
    }

    ostringstream sink;
    sink << *m_assertion;
    assertion = obj.addmember("assertion").string(sink.str().c_str());

    return obj;
}

eap_gss_saml_attr_ctx *
eap_gss_saml_attr_ctx::unmarshall(DDF &obj)
{
    eap_gss_saml_attr_ctx *ctx = new eap_gss_saml_attr_ctx();

    DDF version = obj["version"];
    if (version.integer() != 1)
        return NULL;

    DDF assertion = obj["assertion"];
    gss_buffer_desc buffer;

    if (!assertion.isnull()) {
        buffer.length = assertion.strlen();
        buffer.value = (void *)assertion.string();
    } else {
        buffer.length = 0;
    }

    if (buffer.length != 0)
        ctx->parseAssertion(&buffer);

    DDF attrs = obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        Attribute *attribute = Attribute::unmarshall(attr);
        ctx->addAttribute(attribute, false);
        attr = attrs.next();
    }

    return ctx;
}

void
eap_gss_saml_attr_ctx::marshall(gss_buffer_t buffer)
{
    DDF obj = marshall();
    ostringstream sink;
    sink << obj;
    string str = sink.str();

    duplicateBuffer(str, buffer);

    obj.destroy();
}

eap_gss_saml_attr_ctx *
eap_gss_saml_attr_ctx::unmarshall(const gss_buffer_t buffer)
{
    eap_gss_saml_attr_ctx *ctx;

    string str((const char *)buffer->value, buffer->length);
    istringstream source(str);
    DDF obj(NULL);
    source >> obj;

    ctx = unmarshall(obj);

    obj.destroy();

    return ctx;
}

bool
eap_gss_saml_attr_ctx::getAssertion(gss_buffer_t buffer)
{
    string str;

    if (m_assertion == NULL)
        return false;

    buffer->value = NULL;
    buffer->length = 0;

    XMLHelper::serialize(m_assertion->marshall((DOMDocument *)NULL), str);

    duplicateBuffer(str, buffer);

    return true;
}

static Attribute *
duplicateAttribute(const Attribute *src)
{
    Attribute *attribute;

    DDF obj = src->marshall();
    attribute = Attribute::unmarshall(obj);
    obj.destroy();

    return attribute;
}

static vector <Attribute *>
duplicateAttributes(const vector <Attribute *>src)
{
    vector <Attribute *> dst;

    for (vector<Attribute *>::const_iterator a = src.begin();
         a != src.end();
         ++a)
        dst.push_back(duplicateAttribute(*a));

    return dst;
}

void
eap_gss_saml_attr_ctx::addAttribute(Attribute *attribute, bool copy)
{
    Attribute *a;

    a = copy ? duplicateAttribute(attribute) : attribute;

    m_attributes.push_back(a);
}

void
eap_gss_saml_attr_ctx::setAttributes(const vector<Attribute*> attributes)
{
    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    m_attributes = duplicateAttributes(attributes);
}

int
eap_gss_saml_attr_ctx::getAttributeIndex(const gss_buffer_t attr) const
{
    int i = 0;

    for (vector<Attribute *>::const_iterator a = getAttributes().begin();
         a != getAttributes().end();
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

const Attribute *
eap_gss_saml_attr_ctx::getAttribute(const gss_buffer_t attr) const
{
    const Attribute *ret = NULL;

    for (vector<Attribute *>::const_iterator a = getAttributes().begin();
         a != getAttributes().end();
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
eap_gss_saml_attr_ctx::getAttribute(const gss_buffer_t attr,
                                    int *authenticated,
                                    int *complete,
                                    gss_buffer_t value,
                                    gss_buffer_t display_value,
                                    int *more)
{
    const Attribute *shibAttr = NULL;
    gss_buffer_desc buf;

    shibAttr = getAttribute(attr);
    if (shibAttr == NULL)
        return false;

    if (*more == -1) {
        *more = 0;
    } else if (*more >= (int)shibAttr->valueCount()) {
        *more = 0;
        return true;
    }

    buf.value = (void *)shibAttr->getString(*more);
    buf.length = strlen((char *)buf.value);

    duplicateBuffer(buf, value);
 
    *authenticated = TRUE;
    *complete = FALSE;

    return true;
}

void
eap_gss_saml_attr_ctx::setAttribute(int complete,
                                    const gss_buffer_t attr,
                                    const gss_buffer_t value)
{
    string attrStr((char *)attr->value, attr->length);
    vector <string> ids(1);
    SimpleAttribute *a;

    ids.push_back(attrStr);

    a = new SimpleAttribute(ids);

    if (value->length != 0) {
        string valStr((char *)value->value, value->length);

        a->getValues().push_back(valStr);        
    }

    m_attributes.push_back(a);
}

void
eap_gss_saml_attr_ctx::deleteAttribute(const gss_buffer_t attr)
{
    int i;

    i = getAttributeIndex(attr);
    if (i >= 0)
        m_attributes.erase(m_attributes.begin() + i);
}

OM_uint32
samlReleaseAttrContext(OM_uint32 *minor,
                       struct eap_gss_saml_attr_ctx **pCtx)
{
    eap_gss_saml_attr_ctx *ctx = *pCtx;

    if (ctx != NULL) {
        delete ctx;
        *pCtx = NULL;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
samlCreateAttrContext(OM_uint32 *minor,
                      gss_buffer_t buffer,
                      gss_name_t acceptorName,
                      struct eap_gss_saml_attr_ctx **pCtx)
{
    OM_uint32 major, tmpMinor;
    eap_gss_saml_attr_ctx *ctx = NULL;
    SPConfig &conf = SPConfig::getConfig();
    ServiceProvider *sp;
    const Application *app;
    MetadataProvider *m;
    gss_buffer_desc nameBuf;
    const XMLCh *issuer = NULL;
    saml2::NameID *subjectName = NULL;
    saml2::Assertion *assertion;
    ResolutionContext *resolverContext;

    nameBuf.length = 0;
    nameBuf.value = NULL;

    conf.setFeatures(SPConfig::Metadata             |
                     SPConfig::Trust                |
                     SPConfig::AttributeResolution  |
                     SPConfig::Credentials          |
                     SPConfig::OutOfProcess);
    if (!conf.init())
        return GSS_S_FAILURE;
    if (!conf.instantiate())
        return GSS_S_FAILURE;

    sp = conf.getServiceProvider();
    sp->lock();

    major = gss_display_name(minor, acceptorName, &nameBuf, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    app = sp->getApplication((const char *)nameBuf.value);
    if (app == NULL) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    try {
        ctx = new eap_gss_saml_attr_ctx(buffer);

        if (assertion->getIssuer() != NULL)
            issuer = assertion->getIssuer()->getName();
        if (assertion->getSubject() != NULL)
            subjectName = assertion->getSubject()->getNameID();

        m = app->getMetadataProvider();
        xmltooling::Locker mlocker(m);
        MetadataProviderCriteria mc(*app, issuer,
                                    &IDPSSODescriptor::ELEMENT_QNAME,
                                    samlconstants::SAML20P_NS);
        pair<const EntityDescriptor *, const RoleDescriptor *> site =
            m->getEntityDescriptor(mc);
        if (!site.first) {
            auto_ptr_char temp(issuer);
            throw MetadataException("Unable to locate metadata for IdP ($1).",
                                    params(1,temp.get()));
        }
        vector<const Assertion*> tokens(1, assertion);
        GSSEAPResolver gssResolver(NULL, (const char *)nameBuf.value);
        resolverContext = gssResolver.resolveAttributes(*app, site.second,
                                                        samlconstants::SAML20P_NS,
                                                        NULL, subjectName, NULL,
                                                        NULL, &tokens);
        ctx->setAttributes(resolverContext->getResolvedAttributes());
    } catch (exception &ex) {
        major = mapException(minor, ex);
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *pCtx = ctx;

cleanup:
    sp->unlock();
    conf.term();

    if (GSS_ERROR(major))
        delete ctx;
    gss_release_buffer(&tmpMinor, &nameBuf);

    return major;
}

OM_uint32
samlGetAttributeTypes(OM_uint32 *minor,
                      const struct eap_gss_saml_attr_ctx *ctx,
                      void *data,
                      OM_uint32 (*addAttribute)(OM_uint32 *, void *, gss_buffer_t))
{
    OM_uint32 major = GSS_S_COMPLETE;

    if (ctx == NULL)
        return GSS_S_COMPLETE;

    for (vector<Attribute*>::const_iterator a = ctx->getAttributes().begin();
        a != ctx->getAttributes().end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)((*a)->getId());
        attribute.length = strlen((char *)attribute.value);

        major = addAttribute(minor, data, &attribute);
        if (GSS_ERROR(major))
            break;
    }

    return major;
}

/*
 * SAML implementation of gss_get_name_attribute
 */
OM_uint32
samlGetAttribute(OM_uint32 *minor,
                 struct eap_gss_saml_attr_ctx *ctx,
                 gss_buffer_t attr,
                 int *authenticated,
                 int *complete,
                 gss_buffer_t value,
                 gss_buffer_t display_value,
                 int *more)
{
    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    if (!ctx->getAttribute(attr, authenticated, complete,
                           value, display_value, more))
        return GSS_S_UNAVAILABLE;

    return GSS_S_COMPLETE;
}

OM_uint32
samlSetAttribute(OM_uint32 *minor,
                 struct eap_gss_saml_attr_ctx *ctx,
                 int complete,
                 gss_buffer_t attr,
                 gss_buffer_t value)
{
    try {
        ctx->setAttribute(complete, attr, value);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlDeleteAttribute(OM_uint32 *minor,
                    struct eap_gss_saml_attr_ctx *ctx,
                    gss_buffer_t attr)
{
    try {
        ctx->deleteAttribute(attr);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

/*
 * In order to implement gss_export_name and gss_export_sec_context,
 * we need to serialise a resolved attribute context to a buffer.
 */
OM_uint32
samlExportAttrContext(OM_uint32 *minor,
                      struct eap_gss_saml_attr_ctx *ctx,
                      gss_buffer_t buffer)
{
    try {
        ctx->marshall(buffer);
    } catch (exception &e) {
        return mapException(minor, e);
    }        

    return GSS_S_COMPLETE;
}

/*
 * In order to implement gss_import_name and gss_import_sec_context,
 * we need to deserialise a resolved attribute context from a buffer.
 */
OM_uint32
samlImportAttrContext(OM_uint32 *minor,
                      gss_buffer_t buffer,
                      struct eap_gss_saml_attr_ctx **pCtx)
{
    try {
        *pCtx = eap_gss_saml_attr_ctx::unmarshall(buffer);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlGetAssertion(OM_uint32 *minor,
                 struct eap_gss_saml_attr_ctx *ctx,
                 gss_buffer_t assertion)
{
    try {
        ctx->getAssertion(assertion);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlDuplicateAttrContext(OM_uint32 *minor,
                         const struct eap_gss_saml_attr_ctx *in,
                         struct eap_gss_saml_attr_ctx **out)
{
    try {
        *out = new eap_gss_saml_attr_ctx(*in);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlMapNametoAny(OM_uint32 *minor,
                 const struct eap_gss_saml_attr_ctx *ctx,
                 int authenticated,
                 gss_buffer_t type_id,
                 gss_any_t *output)
{
    if (bufferEqualString(type_id, "shibsp::Attribute")) {
        vector <Attribute *>v = duplicateAttributes(ctx->getAttributes());

        *output = (gss_any_t)new vector <Attribute *>(v);
    } else if (bufferEqualString(type_id, "opensaml::Assertion")) {
        *output = (gss_any_t)ctx->getAssertion()->clone();
    } else {
        *output = (gss_any_t)NULL;
        return GSS_S_UNAVAILABLE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlReleaseAnyNameMapping(OM_uint32 *minor,
                          const struct eap_gss_saml_attr_ctx *ctx,
                          gss_buffer_t type_id,
                          gss_any_t *input)
{
    if (bufferEqualString(type_id, "vector<shibsp::Attribute>")) {
        vector <Attribute *> *v = ((vector <Attribute *> *)*input);
        delete v;
    } else if (bufferEqualString(type_id, "opensaml::Assertion")) {
        delete (Assertion *)*input;
    } else {
        return GSS_S_UNAVAILABLE;
    }

    *input = (gss_any_t)NULL;
    return GSS_S_COMPLETE;
}
