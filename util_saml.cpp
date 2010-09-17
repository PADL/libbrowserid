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

#include <sstream>

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h> 
#include <xmltooling/util/XMLHelper.h>

#include <saml/saml1/core/Assertions.h> 
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>

using namespace xmltooling;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xercesc;
using namespace std;

class auto_ptr_gss_buffer {
    MAKE_NONCOPYABLE(auto_ptr_gss_buffer);
    public:
        auto_ptr_gss_buffer() : m_buf(NULL) {
        }
        auto_ptr_gss_buffer(const gss_buffer_t src) {
            m_buf = new XMLCh[src->length + 1];
            XMLString::transcode((const char *)src->value, m_buf, src->length);
        }
        ~auto_ptr_gss_buffer() {
            xercesc::XMLString::release(&m_buf);
        }
        const XMLCh* get() const {
            return m_buf;
        }
        XMLCh* release() {
            XMLCh *temp = m_buf; m_buf = NULL; return temp;
        }
    private:
        XMLCh *m_buf;
};

/*
 * gss_eap_saml_assertion_provider is for retrieving the underlying
 * assertion.
 */
gss_eap_saml_assertion_provider::gss_eap_saml_assertion_provider(const gss_eap_attr_ctx *
ctx)
    : gss_eap_attr_provider(ctx)
{
    /* Then we may be creating from an existing attribute context */
    gss_eap_saml_assertion_provider *saml;

    saml = dynamic_cast<gss_eap_saml_assertion_provider *>
        (ctx->getProvider(ATTR_TYPE_SAML_ASSERTION));
    if (saml != NULL)
        setAssertion(saml->getAssertion());
}

gss_eap_saml_assertion_provider::gss_eap_saml_assertion_provider(const gss_eap_attr_ctx *ctx,
                                                                 gss_cred_id_t gssCred,
                                                                 gss_ctx_id_t gssCtx)
    : gss_eap_attr_provider(ctx)
{
    gss_eap_radius_attr_provider *radius;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    int authenticated, complete, more = -1;
    OM_uint32 minor;

    radius = dynamic_cast<gss_eap_radius_attr_provider *>
        (ctx->getProvider(ATTR_TYPE_RADIUS));
    if (radius != NULL &&
        radius->getAttribute(512, &authenticated, &complete,
                             &value, NULL, &more)) {
        m_assertion = parseAssertion(&value);
        gss_release_buffer(&minor, &value);
    }
}

gss_eap_saml_assertion_provider::~gss_eap_saml_assertion_provider(void)
{
    delete m_assertion;
}

void
gss_eap_saml_assertion_provider::setAssertion(const saml2::Assertion *assertion)
{

    delete m_assertion;
    m_assertion = dynamic_cast<saml2::Assertion*>(assertion->clone());
}

saml2::Assertion *
gss_eap_saml_assertion_provider::parseAssertion(const gss_buffer_t buffer)
{
    string str((char *)buffer->value, buffer->length);
    istringstream istream(str);
    DOMDocument *doc;
    const XMLObjectBuilder *b;

    doc = XMLToolingConfig::getConfig().getParser().parse(istream);
    b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());

    return dynamic_cast<saml2::Assertion *>(b->buildFromDocument(doc));
}

bool
gss_eap_saml_assertion_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute, void *data) const
{
    return addAttribute(this, GSS_C_NO_BUFFER, data);
}

void
gss_eap_saml_assertion_provider::setAttribute(int complete,
                                              const gss_buffer_t attr,
                                              const gss_buffer_t value)
{
    saml2::Assertion *assertion = parseAssertion(value);

    m_assertion = assertion;
}

void
gss_eap_saml_assertion_provider::deleteAttribute(const gss_buffer_t value)
{
    delete m_assertion;
    m_assertion = NULL;
}

bool
gss_eap_saml_assertion_provider::getAttribute(const gss_buffer_t attr,
                                              int *authenticated,
                                              int *complete,
                                              gss_buffer_t value,
                                              gss_buffer_t display_value,
                                              int *more) const
{
    string str;

    if (attr->length != 0 || m_assertion == NULL)
        return false;

    if (*more == -1)
        *more = 0;

    if (*more == 0) {
        *authenticated = true;
        *complete = false;

        XMLHelper::serialize(m_assertion->marshall((DOMDocument *)NULL), str);

        duplicateBuffer(str, value);
    }

    return true;
}

gss_any_t
gss_eap_saml_assertion_provider::mapToAny(int authenticated,
                                          gss_buffer_t type_id) const
{
    return (gss_any_t)m_assertion;
}

void
gss_eap_saml_assertion_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                       gss_any_t input) const
{
    delete ((saml2::Assertion *)input);
}

void
gss_eap_saml_assertion_provider::marshall(gss_buffer_t buffer) const
{
    ostringstream sink;
    string str;

    buffer->length = 0;
    buffer->value = NULL;

    if (m_assertion == NULL)
        return;

    sink << *m_assertion;
    str = sink.str();

    duplicateBuffer(str, buffer);
}

bool
gss_eap_saml_assertion_provider::unmarshall(const gss_eap_attr_ctx *ctx,
                                            const gss_buffer_t buffer)
{
    assert(m_assertion == NULL);

    m_assertion = parseAssertion(buffer);

    return (m_assertion != NULL);
}

bool
gss_eap_saml_assertion_provider::init(void)
{
    return true;
}

void
gss_eap_saml_assertion_provider::finalize(void)
{
}

gss_eap_attr_provider *
gss_eap_saml_assertion_provider::createAttrContext(const gss_eap_attr_ctx *ctx,
                                                   gss_cred_id_t gssCred,
                                                   gss_ctx_id_t gssCtx)
{
    return new gss_eap_saml_assertion_provider(ctx, gssCred, gssCtx);
}

/*
 * gss_eap_saml_attr_provider is for retrieving the underlying attributes.
 */
const saml2::Assertion *
gss_eap_saml_attr_provider::getAssertion(void) const
{
    gss_eap_saml_assertion_provider *saml;
    
    saml = dynamic_cast<gss_eap_saml_assertion_provider *>(m_source->getProvider(ATTR_TYPE_SAML_ASSERTION));
    assert(saml != NULL);

    return saml->getAssertion();
}

gss_eap_saml_attr_provider::gss_eap_saml_attr_provider(const gss_eap_attr_ctx *ctx,
                                                       gss_cred_id_t gssCred,
                                                       gss_ctx_id_t gssCtx)
    : gss_eap_attr_provider(ctx, gssCred, gssCtx)
{
    /* Nothing to do, we're just a wrapper around the assertion provider. */
}

gss_eap_saml_attr_provider::~gss_eap_saml_attr_provider(void)
{
    /* Nothing to do, we're just a wrapper around the assertion provider. */
}

bool
gss_eap_saml_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    const saml2::Assertion *assertion = getAssertion();

    if (assertion == NULL)
        return true;

    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(assertion->getAttributeStatements().front())->getAttributes();
    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a)
    {
        gss_buffer_desc attribute;

        attribute.value = (void *)toUTF8((*a)->getName(), true);
        attribute.length = strlen((char *)attribute.value);

        if (!addAttribute(this, &attribute, data))
            return false;

        delete (char *)attribute.value;
    }

    return true;
}

void
gss_eap_saml_attr_provider::setAttribute(int complete,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
}

void
gss_eap_saml_attr_provider::deleteAttribute(const gss_buffer_t value)
{
}

const saml2::Attribute *
gss_eap_saml_attr_provider::getAttribute(const gss_buffer_t attr) const
{
    const saml2::Assertion *assertion = getAssertion();
    saml2::AttributeStatement *statement;

    if (assertion == NULL)
        return NULL;

    if (assertion->getAttributeStatements().size() == 0)
        return NULL;

    statement = assertion->getAttributeStatements().front();

    auto_ptr_gss_buffer attrname(attr);

    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(statement)->getAttributes();

    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a) {
        if (XMLString::equals((*a)->getName(), attrname.get()))
            return *a;
    }

    return NULL;
}

bool
gss_eap_saml_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    const saml2::Attribute *a;
    const saml2::AttributeValue *av;
    int nvalues, i = *more;

    *more = 0;

    a = getAttribute(attr);
    if (a == NULL)
        return false;

    nvalues = a->getAttributeValues().size();

    if (i == -1)
        i = 0;
    else if (i >= nvalues)
        return false;
    av = dynamic_cast<const saml2::AttributeValue *>(a->getAttributeValues().at(i)
);
    if (av == NULL)
        return false;

    *authenticated = TRUE;
    *complete = FALSE;

    value->value = toUTF8(av->getTextContent(), true);
    value->length = strlen((char *)value->value);

    if (nvalues > ++i)
        *more = i;

    return true;
}

gss_any_t
gss_eap_saml_attr_provider::mapToAny(int authenticated,
                                          gss_buffer_t type_id) const
{
    return (gss_any_t)0;
}

void
gss_eap_saml_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                  gss_any_t input) const
{
}

void
gss_eap_saml_attr_provider::marshall(gss_buffer_t buffer) const
{
}

bool
gss_eap_saml_attr_provider::unmarshall(const gss_eap_attr_ctx *ctx,
                                       const gss_buffer_t buffer)
{
    return false;
}

bool
gss_eap_saml_attr_provider::init(void)
{
    return true;
}

void
gss_eap_saml_attr_provider::finalize(void)
{
}

gss_eap_attr_provider *
gss_eap_saml_attr_provider::createAttrContext(const gss_eap_attr_ctx *ctx,
                                              gss_cred_id_t gssCred,
                                              gss_ctx_id_t gssCtx)
{
    if (gssCtx != GSS_C_NO_CONTEXT)
        return new gss_eap_saml_attr_provider(ctx, gssCred, gssCtx);
    else
        return new gss_eap_saml_attr_provider(ctx);
}
