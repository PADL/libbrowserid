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

class SHIBSP_DLLLOCAL DummyContext : public ResolutionContext
{
public:
    DummyContext(const vector<Attribute*>& attributes) : m_attributes(attributes) {
    }

    virtual ~DummyContext() {
        for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    }

    vector<Attribute*>& getResolvedAttributes() {
        return m_attributes;
    }
    vector<Assertion*>& getResolvedAssertions() {
        return m_tokens;
    }

private:
    vector<Attribute*> m_attributes;
    static vector<Assertion*> m_tokens; // never any tokens, so just share an empty vector
};

struct eap_gss_saml_attr_ctx {
    ResolutionContext *resCtx;
    gss_buffer_desc assertion;
};

static OM_uint32
samlAllocAttrContext(OM_uint32 *minor,
                     struct eap_gss_saml_attr_ctx **pCtx)
{
    struct eap_gss_saml_attr_ctx *ctx;

    ctx = (struct eap_gss_saml_attr_ctx *)GSSEAP_CALLOC(1, sizeof(*ctx));
    if (ctx == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    *pCtx = ctx;
    *minor = 0;
    return GSS_S_COMPLETE;
}

static OM_uint32
samlImportAssertion(OM_uint32 *minor,
                    gss_buffer_t buffer,
                    saml2::Assertion **pAssertion)
{
    *pAssertion = NULL;

    try {
        DOMDocument *doc;
        const XMLObjectBuilder *b;
        DOMElement *elem;
        XMLObject *xobj;
        string samlBuf((char *)buffer->value, buffer->length);
        istringstream samlIn(samlBuf);

        doc = XMLToolingConfig::getConfig().getParser().parse(samlIn);
        b = XMLObjectBuilder::getDefaultBuilder();
        elem = doc->getDocumentElement();
        xobj = b->buildOneFromElement(elem, true);

        *pAssertion = dynamic_cast<saml2::Assertion *>(xobj);
        if (*pAssertion == NULL) {
            /* TODO minor_status */
            return GSS_S_BAD_NAME;
        }
    } catch (exception &e){
        /* TODO minor_status */
        return GSS_S_BAD_NAME;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
samlDuplicateAttrContext(OM_uint32 *minor,
                         const struct eap_gss_saml_attr_ctx *in,
                         struct eap_gss_saml_attr_ctx **out)
{
    OM_uint32 major, tmpMinor;
    struct eap_gss_saml_attr_ctx *ctx;

    major = samlAllocAttrContext(minor, &ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    major = duplicateBuffer(minor, (gss_buffer_t)&in->assertion, &ctx->assertion);
    if (GSS_ERROR(major))
        goto cleanup;

    ctx->resCtx = new DummyContext(in->resCtx->getResolvedAttributes());

cleanup:
    if (GSS_ERROR(major))
        samlReleaseAttrContext(&tmpMinor, &ctx);

    return major;
}

OM_uint32
samlReleaseAttrContext(OM_uint32 *minor,
                       struct eap_gss_saml_attr_ctx **pCtx)
{
    struct eap_gss_saml_attr_ctx *ctx = *pCtx;

    if (ctx != NULL) {
        delete ctx->resCtx;
        gss_release_buffer(minor, &ctx->assertion);
        GSSEAP_FREE(ctx);
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
    struct eap_gss_saml_attr_ctx *ctx;
    SPConfig &conf = SPConfig::getConfig();
    ServiceProvider *sp;
    const Application *app;
    MetadataProvider *m;
    gss_buffer_desc nameBuf;
    const XMLCh *issuer = NULL;
    saml2::NameID *subjectName = NULL;
    saml2::Assertion *assertion;

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

    major = samlAllocAttrContext(minor, &ctx);
    if (GSS_ERROR(major))
        goto cleanup;

    major = duplicateBuffer(minor, buffer, &ctx->assertion);
    if (GSS_ERROR(major))
        goto cleanup;

    major = samlImportAssertion(minor, &ctx->assertion, &assertion);
    if (GSS_ERROR(major))
        goto cleanup;

    if (assertion->getIssuer() != NULL)
        issuer = assertion->getIssuer()->getName();
    if (assertion->getSubject() != NULL)
        subjectName = assertion->getSubject()->getNameID();

    try {
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
        ctx->resCtx = gssResolver.resolveAttributes(*app, site.second,
                                                    samlconstants::SAML20P_NS,
                                                    NULL, subjectName, NULL,
                                                    NULL, &tokens);
    } catch (exception &ex) {
        major = GSS_S_BAD_NAME;
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *pCtx = ctx;

cleanup:
    sp->unlock();
    conf.term();

    if (GSS_ERROR(major))
        samlReleaseAttrContext(&tmpMinor, &ctx);
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

    for (vector<Attribute*>::const_iterator a = ctx->resCtx->getResolvedAttributes().begin();
        a != ctx->resCtx->getResolvedAttributes().end();
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

OM_uint32
samlGetAttribute(OM_uint32 *minor,
                 const struct eap_gss_saml_attr_ctx *ctx,
                 gss_buffer_t attr,
                 int *authenticated,
                 int *complete,
                 gss_buffer_t value,
                 gss_buffer_t display_value,
                 int *more)
{
    OM_uint32 major;
    Attribute *shibAttr = NULL;
    gss_buffer_desc buf;

    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    for (vector<Attribute *>::const_iterator a = ctx->resCtx->getResolvedAttributes().begin();
         a != ctx->resCtx->getResolvedAttributes().end();
         ++a) {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin();
             s != (*a)->getAliases().end();
             ++s) {
            if (attr->length == strlen((*s).c_str()) &&
                memcmp((*s).c_str(), attr->value, attr->length) == 0) {
                shibAttr = *a;
                break;
            }
        }
        if (shibAttr != NULL)
            break;
    }

    if (shibAttr == NULL)
        return GSS_S_UNAVAILABLE;

    if (*more == -1) {
        *more = 0;
    } else if (*more >= (int)shibAttr->valueCount()) {
        *more = 0;
        return GSS_S_COMPLETE;
    }

    buf.value = (void *)shibAttr->getString(*more);
    buf.length = strlen((char *)buf.value);

    major = duplicateBuffer(minor, &buf, value);
    if (GSS_ERROR(major))
        return major;
 
    *authenticated = TRUE;
    *complete = FALSE;

    return GSS_S_COMPLETE;
}

OM_uint32
samlSetAttribute(OM_uint32 *minor,
                 struct eap_gss_saml_attr_ctx *ctx,
                 int complete,
                 gss_buffer_t attr,
                 gss_buffer_t value)
{
    return GSS_S_UNAVAILABLE;
}

OM_uint32
samlGetAssertion(OM_uint32 *minor,
                 struct eap_gss_saml_attr_ctx *ctx,
                 gss_buffer_t buffer)
{
    if (ctx == NULL)
        return GSS_S_UNAVAILABLE;

    return duplicateBuffer(minor, &ctx->assertion, buffer);
}

OM_uint32
samlExportAttrContext(OM_uint32 *minor,
                      struct eap_gss_saml_attr_ctx *ctx,
                      gss_buffer_t buffer)
{
    GSSEAP_NOT_IMPLEMENTED;
}

OM_uint32
samlImportAttrContext(OM_uint32 *minor,
                      gss_buffer_t buffer,
                      struct eap_gss_saml_attr_ctx **ppCtx)
{
    GSSEAP_NOT_IMPLEMENTED;
}
