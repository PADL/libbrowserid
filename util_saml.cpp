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
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/DateTime.h>

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>

using namespace xmltooling;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xercesc;
using namespace std;

/*
 * gss_eap_saml_assertion_provider is for retrieving the underlying
 * assertion.
 */
gss_eap_saml_assertion_provider::gss_eap_saml_assertion_provider(void)
{
    m_assertion = NULL;
    m_authenticated = false;
}

gss_eap_saml_assertion_provider::~gss_eap_saml_assertion_provider(void)
{
    delete m_assertion;
}

bool
gss_eap_saml_assertion_provider::initFromExistingContext(const gss_eap_attr_ctx *manager,
                                                         const gss_eap_attr_provider *ctx)
{
    /* Then we may be creating from an existing attribute context */
    const gss_eap_saml_assertion_provider *saml;

    assert(m_assertion == NULL);

    if (!gss_eap_attr_provider::initFromExistingContext(manager, ctx))
        return false;

    saml = static_cast<const gss_eap_saml_assertion_provider *>(ctx);
    setAssertion(saml->getAssertion(), saml->authenticated());

    return true;
}

bool
gss_eap_saml_assertion_provider::initFromGssContext(const gss_eap_attr_ctx *manager,
                                                    const gss_cred_id_t gssCred,
                                                    const gss_ctx_id_t gssCtx)
{
    const gss_eap_radius_attr_provider *radius;
    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    int authenticated, complete;
    OM_uint32 minor;

    assert(m_assertion == NULL);

    if (!gss_eap_attr_provider::initFromGssContext(manager, gssCred, gssCtx))
        return false;

    /*
     * XXX TODO we need to support draft-howlett-radius-saml-attr-00
     */
    radius = static_cast<const gss_eap_radius_attr_provider *>
        (m_manager->getProvider(ATTR_TYPE_RADIUS));
    if (radius != NULL &&
        radius->getFragmentedAttribute(PW_SAML_AAA_ASSERTION,
                                       VENDORPEC_UKERNA,
                                       &authenticated, &complete, &value)) {
        setAssertion(&value, authenticated);
        gss_release_buffer(&minor, &value);
    } else {
        m_assertion = NULL;
    }

    return true;
}

void
gss_eap_saml_assertion_provider::setAssertion(const saml2::Assertion *assertion,
                                              bool authenticated)
{

    delete m_assertion;

    if (assertion != NULL) {
#ifdef __APPLE__
        m_assertion = (saml2::Assertion *)((void *)assertion->clone());
#else
        m_assertion = dynamic_cast<saml2::Assertion *>(assertion->clone());
#endif
        m_authenticated = authenticated;
    } else {
        m_assertion = NULL;
        m_authenticated = false;
    }
}

void
gss_eap_saml_assertion_provider::setAssertion(const gss_buffer_t buffer,
                                              bool authenticated)
{
    delete m_assertion;

    m_assertion = parseAssertion(buffer);
    m_authenticated = (m_assertion != NULL && authenticated);
}

saml2::Assertion *
gss_eap_saml_assertion_provider::parseAssertion(const gss_buffer_t buffer)
{
    string str((char *)buffer->value, buffer->length);
    istringstream istream(str);
    DOMDocument *doc;
    const XMLObjectBuilder *b;

    doc = XMLToolingConfig::getConfig().getParser().parse(istream);
    if (doc == NULL)
        return NULL;

    b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());

#ifdef __APPLE__
    return (saml2::Assertion *)((void *)b->buildFromDocument(doc));
#else
    return dynamic_cast<saml2::Assertion *>(b->buildFromDocument(doc));
#endif
}

bool
gss_eap_saml_assertion_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                                   void *data) const
{
    bool ret;

    /* just add the prefix */
    if (m_assertion != NULL)
        ret = addAttribute(this, GSS_C_NO_BUFFER, data);
    else
        ret = true;

    return ret;
}

void
gss_eap_saml_assertion_provider::setAttribute(int complete,
                                              const gss_buffer_t attr,
                                              const gss_buffer_t value)
{
    if (attr == GSS_C_NO_BUFFER || attr->length == 0) {
        setAssertion(value);
    }
}

void
gss_eap_saml_assertion_provider::deleteAttribute(const gss_buffer_t value)
{
    delete m_assertion;
    m_assertion = NULL;
    m_authenticated = false;
}

time_t
gss_eap_saml_assertion_provider::getExpiryTime(void) const
{
    saml2::Conditions *conditions;
    time_t expiryTime = 0;

    if (m_assertion == NULL)
        return 0;

    conditions = m_assertion->getConditions();

    if (conditions != NULL && conditions->getNotOnOrAfter() != NULL)
        expiryTime = conditions->getNotOnOrAfter()->getEpoch();

    return expiryTime;
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

    XMLHelper::serialize(m_assertion->marshall((DOMDocument *)NULL), str);

    duplicateBuffer(str, value);
    *more = 0;

    return true;
}

gss_any_t
gss_eap_saml_assertion_provider::mapToAny(int authenticated,
                                          gss_buffer_t type_id) const
{
    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    return (gss_any_t)m_assertion;
}

void
gss_eap_saml_assertion_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                       gss_any_t input) const
{
    delete ((saml2::Assertion *)input);
}

void
gss_eap_saml_assertion_provider::exportToBuffer(gss_buffer_t buffer) const
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
gss_eap_saml_assertion_provider::initFromBuffer(const gss_eap_attr_ctx *ctx,
                                                const gss_buffer_t buffer)
{
    if (!gss_eap_attr_provider::initFromBuffer(ctx, buffer))
        return false;

    if (buffer->length == 0)
        return true;

    assert(m_assertion == NULL);

    setAssertion(buffer);
    /* TODO XXX how to propagate authenticated flag? */

    return true;
}

bool
gss_eap_saml_assertion_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_SAML_ASSERTION,
                                       "urn:ietf:params:gss-eap:saml-aaa-assertion",
                                       gss_eap_saml_assertion_provider::createAttrContext);
    return true;
}

void
gss_eap_saml_assertion_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_SAML_ASSERTION);
}

gss_eap_attr_provider *
gss_eap_saml_assertion_provider::createAttrContext(void)
{
    return new gss_eap_saml_assertion_provider;
}

/*
 * gss_eap_saml_attr_provider is for retrieving the underlying attributes.
 */
bool
gss_eap_saml_attr_provider::getAssertion(int *authenticated,
                                         const saml2::Assertion **pAssertion) const
{
    const gss_eap_saml_assertion_provider *saml;

    if (authenticated != NULL)
        *authenticated = false;
    if (pAssertion != NULL)
        *pAssertion = NULL;

    saml = static_cast<const gss_eap_saml_assertion_provider *>
        (m_manager->getProvider(ATTR_TYPE_SAML_ASSERTION));
    if (saml == NULL)
        return false;

    if (authenticated != NULL)
        *authenticated = saml->authenticated();
    if (pAssertion != NULL)
        *pAssertion = saml->getAssertion();

    return (saml->getAssertion() != NULL);
}

bool
gss_eap_saml_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                              void *data) const
{
    const saml2::Assertion *assertion;
    bool ret = true;
    int authenticated;

    if (!getAssertion(&authenticated, &assertion))
        return true;

    /*
     * Note: the first prefix is added by the attribute provider manager
     *
     * From draft-hartman-gss-eap-naming-00:
     *
     *   Each attribute carried in the assertion SHOULD also be a GSS name
     *   attribute.  The name of this attribute has three parts, all separated
     *   by an ASCII space character.  The first part is
     *   urn:ietf:params:gss-eap:saml-attr.  The second part is the URI for
     *   the SAML attribute name format.  The final part is the name of the
     *   SAML attribute.  If the mechanism performs an additional attribute
     *   query, the retrieved attributes SHOULD be GSS-API name attributes
     *   using the same name syntax.
     */
    const vector<saml2::Attribute*>& attrs2 =
        const_cast<const saml2::AttributeStatement*>(assertion->getAttributeStatements().front())->getAttributes();
    for (vector<saml2::Attribute*>::const_iterator a = attrs2.begin();
        a != attrs2.end();
        ++a)
    {
        const XMLCh *attributeName = (*a)->getName();
        const XMLCh *attributeNameFormat = (*a)->getNameFormat();
        XMLCh *qualifiedName;
        XMLCh space[2] = { ' ', 0 };
        gss_buffer_desc utf8;

        qualifiedName = new XMLCh[XMLString::stringLen(attributeNameFormat) + 1 +
                                  XMLString::stringLen(attributeName) + 1];
        XMLString::copyString(qualifiedName, attributeNameFormat);
        XMLString::catString(qualifiedName, space);
        XMLString::catString(qualifiedName, attributeName);

        utf8.value = (void *)toUTF8(qualifiedName);
        utf8.length = strlen((char *)utf8.value);

        ret = addAttribute(this, &utf8, data);

        delete qualifiedName;

        if (!ret)
            break;
    }

    return ret;
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

static BaseRefVectorOf<XMLCh> *
decomposeAttributeName(const gss_buffer_t attr)
{
    XMLCh *qualifiedAttr = new XMLCh[attr->length + 1];
    XMLString::transcode((const char *)attr->value, qualifiedAttr, attr->length);

    BaseRefVectorOf<XMLCh> *components = XMLString::tokenizeString(qualifiedAttr);

    delete qualifiedAttr;

    return components;
}

bool
gss_eap_saml_attr_provider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         const saml2::Attribute **pAttribute) const
{
    const saml2::Assertion *assertion;

    if (authenticated != NULL)
        *authenticated = false;
    if (complete != NULL)
        *complete = true;
    *pAttribute = NULL;

    if (!getAssertion(authenticated, &assertion) ||
        assertion->getAttributeStatements().size() == 0)
        return false;

    /* Check the attribute name consists of name format | whsp | name */
    BaseRefVectorOf<XMLCh> *components = decomposeAttributeName(attr);
    if (components == NULL || components->size() != 2) {
        delete components;
        return false;
    }

    /* For each attribute statement, look for an attribute match */
    const vector <saml2::AttributeStatement *>&statements =
        assertion->getAttributeStatements();
    const saml2::Attribute *ret = NULL;

    for (vector<saml2::AttributeStatement *>::const_iterator s = statements.begin();
        s != statements.end();
        ++s) {
        const vector<saml2::Attribute*>& attrs =
            const_cast<const saml2::AttributeStatement*>(*s)->getAttributes();

        for (vector<saml2::Attribute*>::const_iterator a = attrs.begin(); a != attrs.end(); ++a) {
            if (XMLString::equals((*a)->getNameFormat(), components->elementAt(0)) &&
                XMLString::equals((*a)->getName(), components->elementAt(1))) {
                ret = *a;
                break;
            }
        }

        if (ret != NULL)
            break;
    }

    delete components;

    *pAttribute = ret;

    return (ret != NULL);
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

    if (!getAttribute(attr, authenticated, complete, &a))
        return false;

    nvalues = a->getAttributeValues().size();

    if (i == -1)
        i = 0;
    else if (i >= nvalues)
        return false;
#ifdef __APPLE__
    av = (const saml2::AttributeValue *)((void *)(a->getAttributeValues().at(i)));
#else
    av = dynamic_cast<const saml2::AttributeValue *>(a->getAttributeValues().at(i));
#endif
    if (av != NULL) {
        if (value != NULL) {
            value->value = toUTF8(av->getTextContent(), true);
            value->length = strlen((char *)value->value);
        }
        if (display_value != NULL) {
            display_value->value = toUTF8(av->getTextContent(), true);
            display_value->length = strlen((char *)value->value);
        }
    }

    if (nvalues > ++i)
        *more = i;

    return true;
}

gss_any_t
gss_eap_saml_attr_provider::mapToAny(int authenticated,
                                     gss_buffer_t type_id) const
{
    return (gss_any_t)NULL;
}

void
gss_eap_saml_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                  gss_any_t input) const
{
}

void
gss_eap_saml_attr_provider::exportToBuffer(gss_buffer_t buffer) const
{
    buffer->length = 0;
    buffer->value = NULL;
}

bool
gss_eap_saml_attr_provider::initFromBuffer(const gss_eap_attr_ctx *ctx,
                                           const gss_buffer_t buffer)
{
    return gss_eap_attr_provider::initFromBuffer(ctx, buffer);
}

bool
gss_eap_saml_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_SAML,
                                       "urn:ietf:params:gss-eap:saml-attr",
                                       gss_eap_saml_attr_provider::createAttrContext);
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
gssEapSamlAttrProvidersInit(OM_uint32 *minor)
{
    if (gss_eap_saml_assertion_provider::init() &&
        gss_eap_saml_attr_provider::init())
        return GSS_S_COMPLETE;

    return GSS_S_FAILURE;
}

OM_uint32
gssEapSamlAttrProvidersFinalize(OM_uint32 *minor)
{
    gss_eap_saml_attr_provider::finalize();
    gss_eap_saml_assertion_provider::finalize();
    return GSS_S_COMPLETE;
}
