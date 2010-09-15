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

#include "gssapiP_eap.h"

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

#include "resolver.h"

using namespace shibsp;
using namespace shibresolver;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

static vector <Attribute *>
duplicateAttributes(const vector <Attribute *>src);

/*
 * Class representing the SAML compoments of a EAP GSS name.
 */
struct gss_eap_saml_attr_ctx
{
public:
    gss_eap_saml_attr_ctx(void) {}

    gss_eap_saml_attr_ctx(const vector<Attribute*>& attributes,
                          const saml2::Assertion *assertion = NULL) {
        if (assertion != NULL)
            setAssertion(assertion);
        if (attributes.size())
            setAttributes(duplicateAttributes(attributes));
    }

    gss_eap_saml_attr_ctx(const gss_eap_saml_attr_ctx &ctx) {
        gss_eap_saml_attr_ctx(ctx.m_attributes, ctx.m_assertion);
    }

    ~gss_eap_saml_attr_ctx() {
        for_each(m_attributes.begin(),
                 m_attributes.end(),
                 xmltooling::cleanup<Attribute>())
            ;
        delete m_assertion;
    }

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

    const saml2::Assertion *getAssertion(void) const {
        return m_assertion;
    }

    void setAssertion(const saml2::Assertion *assertion) {
        delete m_assertion;
        if (assertion != NULL)
            m_assertion = dynamic_cast<saml2::Assertion *>(assertion->clone());
        else
            m_assertion = NULL;
    }

    void setAssertion(const gss_buffer_t buffer) {
        delete m_assertion;
        m_assertion = parseAssertion(buffer);
    }

    bool getAssertion(gss_buffer_t buffer);

    DDF marshall() const;
    static gss_eap_saml_attr_ctx *unmarshall(DDF &in);

    void marshall(gss_buffer_t buffer);
    static gss_eap_saml_attr_ctx *unmarshall(const gss_buffer_t buffer);

private:
    mutable vector<Attribute*> m_attributes;
    mutable saml2::Assertion *m_assertion;

    static saml2::Assertion *parseAssertion(const gss_buffer_t buffer);
};

/*
 * Map an exception to a GSS major/mechanism status code.
 * TODO
 */
static OM_uint32
mapException(OM_uint32 *minor, exception &e)
{
    *minor = 0;
    return GSS_S_FAILURE;
}

/*
 * Parse a GSS buffer into a SAML v2 assertion.
 */
saml2::Assertion *
gss_eap_saml_attr_ctx::parseAssertion(const gss_buffer_t buffer)
{
    string str((char *)buffer->value, buffer->length);
    istringstream istream(str);
    DOMDocument *doc;
    const XMLObjectBuilder *b;

    doc = XMLToolingConfig::getConfig().getParser().parse(istream);
    b =XMLObjectBuilder::getBuilder(doc->getDocumentElement());

    return dynamic_cast<saml2::Assertion *>(b->buildFromDocument(doc));
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

/*
 * Marshall SAML attribute context into a form suitable for
 * exported names.
 */
DDF
gss_eap_saml_attr_ctx::marshall() const
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

/*
 * Unmarshall SAML attribute context from a form suitable for
 * exported names.
 */
gss_eap_saml_attr_ctx *
gss_eap_saml_attr_ctx::unmarshall(DDF &obj)
{
    gss_eap_saml_attr_ctx *ctx = new gss_eap_saml_attr_ctx();

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
gss_eap_saml_attr_ctx::marshall(gss_buffer_t buffer)
{
    DDF obj = marshall();
    ostringstream sink;
    sink << obj;
    string str = sink.str();

    duplicateBuffer(str, buffer);

    obj.destroy();
}

gss_eap_saml_attr_ctx *
gss_eap_saml_attr_ctx::unmarshall(const gss_buffer_t buffer)
{
    gss_eap_saml_attr_ctx *ctx;

    string str((const char *)buffer->value, buffer->length);
    istringstream source(str);
    DDF obj(NULL);
    source >> obj;

    ctx = unmarshall(obj);

    obj.destroy();

    return ctx;
}

/*
 * Return the serialised assertion.
 */
bool
gss_eap_saml_attr_ctx::getAssertion(gss_buffer_t buffer)
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
gss_eap_saml_attr_ctx::addAttribute(Attribute *attribute, bool copy)
{
    Attribute *a;

    a = copy ? duplicateAttribute(attribute) : attribute;

    m_attributes.push_back(a);
}

void
gss_eap_saml_attr_ctx::setAttributes(const vector<Attribute*> attributes)
{
    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    m_attributes = attributes;
}

int
gss_eap_saml_attr_ctx::getAttributeIndex(const gss_buffer_t attr) const
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
gss_eap_saml_attr_ctx::getAttribute(const gss_buffer_t attr) const
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
gss_eap_saml_attr_ctx::getAttribute(const gss_buffer_t attr,
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

static Attribute *
samlAttributeFromGssBuffers(const gss_buffer_t attr,
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

    return a;
}

void
gss_eap_saml_attr_ctx::setAttribute(int complete,
                                    const gss_buffer_t attr,
                                    const gss_buffer_t value)
{
    Attribute *a = samlAttributeFromGssBuffers(attr, value);

    addAttribute(a, false);
}

void
gss_eap_saml_attr_ctx::deleteAttribute(const gss_buffer_t attr)
{
    int i;

    i = getAttributeIndex(attr);
    if (i >= 0)
        m_attributes.erase(m_attributes.begin() + i);
}

OM_uint32
samlReleaseAttrContext(OM_uint32 *minor, gss_name_t name)
{
    try {
        delete name->samlCtx;
        name->samlCtx = NULL;
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

static gss_buffer_desc
gssEapRadiusAssertionAttr = { 3, (void *)"128" };   /* TODO */

class gss_eap_saml_attr_args {
public:
    vector <Attribute *> attrs;
    ShibbolethResolver *resolver;
};

/*
 * Callback to add a RADIUS attribute as input to the resolver.
 */
static OM_uint32
samlAddRadiusAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       void *data)
{
    OM_uint32 major;
    gss_eap_saml_attr_args *args = (gss_eap_saml_attr_args *)data;
    Attribute *a;
    int authenticated, complete, more = -1;
    gss_buffer_desc value;

    /* Put attributes to skip here (or in a table somewhere) */
    if (bufferEqual(attr, &gssEapRadiusAssertionAttr)) {
        return GSS_S_COMPLETE;
    }

    major = radiusGetAttribute(minor, name, attr,
                               &authenticated, &complete,
                               &value, GSS_C_NO_BUFFER, &more);
    if (major == GSS_S_COMPLETE) {
        /* XXX TODO prefix */
        a = samlAttributeFromGssBuffers(attr, &value);
        args->attrs.push_back(a);
        args->resolver->addAttribute(a);
    }

    return GSS_S_COMPLETE;
}

/*
 * Add attributes retrieved via RADIUS.
 */
static OM_uint32
samlAddRadiusAttributes(OM_uint32 *minor,
                        gss_name_t name,
                        gss_eap_saml_attr_args *args)
{
    return radiusGetAttributeTypes(minor,
                                   name,
                                   samlAddRadiusAttribute,
                                   (void *)args);
}

/*
 * Add assertion retrieved via RADIUS.
 */
static OM_uint32
samlAddRadiusAssertion(OM_uint32 *minor,
                       gss_name_t name,
                       gss_eap_saml_attr_ctx *ctx)
{
    OM_uint32 major;
    int authenticated, complete, more = -1;
    gss_buffer_desc value;

    value.value = NULL;
    value.length = 0;

    major = radiusGetAttribute(minor, name, &gssEapRadiusAssertionAttr,
                               &authenticated, &complete,
                               &value, GSS_C_NO_BUFFER, &more);
    if (GSS_ERROR(major) && major != GSS_S_UNAVAILABLE)
        return major;

    ctx->setAssertion(&value);

    gss_release_buffer(minor, &value);

    return GSS_S_COMPLETE;
}

/*
 * Initialise SAML attribute context in initiator name. RADIUS context
 * must have been previously initialised.
 */
OM_uint32
samlCreateAttrContext(OM_uint32 *minor,
                      gss_cred_id_t acceptorCred,
                      gss_name_t initiatorName,
                      time_t *pExpiryTime)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc nameBuf;
    gss_eap_saml_attr_ctx *ctx = NULL;
    ShibbolethResolver *resolver = NULL;
    gss_eap_saml_attr_args args;

    assert(initiatorName != GSS_C_NO_NAME);

    if (initiatorName->radiusCtx == NULL)
        return GSS_S_UNAVAILABLE;

    nameBuf.length = 0;
    nameBuf.value = NULL;

    resolver = ShibbolethResolver::create();
    if (resolver == NULL)
        return GSS_S_FAILURE;

    args.resolver = resolver;

    if (acceptorCred != GSS_C_NO_CREDENTIAL) {
        major = gss_display_name(minor, acceptorCred->name, &nameBuf, NULL);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    try {
        const saml2::Assertion *assertion;
        vector <Attribute *> attrs;

        ctx = new gss_eap_saml_attr_ctx();

        major = samlAddRadiusAssertion(minor, initiatorName, ctx);
        if (GSS_ERROR(major))
            goto cleanup;

        assertion = ctx->getAssertion();

        if (assertion != NULL) {
            if (assertion->getConditions()) {
                *pExpiryTime =
                    assertion->getConditions()->getNotOnOrAfter()->getEpoch();
            }

            resolver->addToken(assertion);
        }

        resolver->setApplicationID((const char *)nameBuf.value);
        if (initiatorName->radiusCtx != NULL)
            samlAddRadiusAttributes(minor, initiatorName, &args);
        resolver->resolveAttributes(attrs);
        ctx->setAttributes(attrs);
    } catch (exception &ex) {
        major = mapException(minor, ex);
        goto cleanup;
    }

    *minor = 0;
    major = GSS_S_COMPLETE;

    initiatorName->samlCtx = ctx;

cleanup:
    for_each(args.attrs.begin(), args.attrs.end(), xmltooling::cleanup<Attribute>());
    gss_release_buffer(&tmpMinor, &nameBuf);
    if (GSS_ERROR(major))
        delete ctx;
    delete resolver;

    return major;
}

OM_uint32
samlGetAttributeTypes(OM_uint32 *minor,
                      gss_name_t name,
                      enum gss_eap_attribute_type type,
                      gss_eap_add_attr_cb addAttribute,
                      void *data)
{
    OM_uint32 major = GSS_S_COMPLETE;
    gss_eap_saml_attr_ctx *ctx = name->samlCtx;

    if (ctx == NULL)
        return GSS_S_COMPLETE;

    if (type != ATTR_TYPE_NONE)
        return GSS_S_UNAVAILABLE;

    for (vector<Attribute*>::const_iterator a = ctx->getAttributes().begin();
        a != ctx->getAttributes().end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)((*a)->getId());
        attribute.length = strlen((char *)attribute.value);

        major = addAttribute(minor, name, &attribute, data);
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
                 enum gss_eap_attribute_type type,
                 gss_name_t name,
                 gss_buffer_t attr,
                 int *authenticated,
                 int *complete,
                 gss_buffer_t value,
                 gss_buffer_t display_value,
                 int *more)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;
    bool ret;

    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    switch (type) {
    case ATTR_TYPE_NONE:
        ret = ctx->getAttribute(attr, authenticated, complete,
                                value, display_value, more);
        break;
    default:
        ret = false;
        break;
    }

    return ret ? GSS_S_COMPLETE : GSS_S_UNAVAILABLE;
}

OM_uint32
samlSetAttribute(OM_uint32 *minor,
                 gss_name_t name,
                 int complete,
                 gss_buffer_t attr,
                 gss_buffer_t value)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;

    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        ctx->setAttribute(complete, attr, value);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlDeleteAttribute(OM_uint32 *minor,
                    gss_name_t name,
                    gss_buffer_t attr)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;

    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

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
                      gss_name_t name,
                      gss_buffer_t buffer)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;

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
                      gss_name_t name)
{
    try {
        assert(name->samlCtx == NULL);
        name->samlCtx = gss_eap_saml_attr_ctx::unmarshall(buffer);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlGetAssertion(OM_uint32 *minor,
                 gss_name_t name,
                 gss_buffer_t assertion)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;

    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        ctx->getAssertion(assertion);
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlDuplicateAttrContext(OM_uint32 *minor,
                         gss_name_t in,
                         gss_name_t out)
{
    try {
        if (in->samlCtx != NULL)
            out->samlCtx = new gss_eap_saml_attr_ctx(*(in->samlCtx));
        else
            out->samlCtx = NULL;
    } catch (exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
samlMapNameToAny(OM_uint32 *minor,
                 gss_name_t name,
                 int authenticated,
                 gss_buffer_t type_id,
                 gss_any_t *output)
{
    struct gss_eap_saml_attr_ctx *ctx = name->samlCtx;

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
                          gss_name_t name,
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

OM_uint32
samlInit(OM_uint32 *minor)
{
    *minor = 0;

    return ShibbolethResolver::init() ? GSS_S_COMPLETE : GSS_S_FAILURE;
}

OM_uint32
samlFinalize(OM_uint32 *minor)
{
    *minor = 0;

    ShibbolethResolver::term();
    return GSS_S_COMPLETE;
}
