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
    delete m_assertion;
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
    this->m_assertion = strdup(saml->m_assertion);
    this->m_authenticated = saml->m_authenticated;

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
    if (radius != NULL &&
        radius->getFragmentedAttribute(attrid, &authenticated, &complete, &value)) {
        this->m_assertion = (char*) malloc(value.length + 1);
        snprintf((char*) this->m_assertion, value.length + 1, "%s", (char*) value.value);
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
        delete this->m_assertion;
        this->m_assertion = (char*) malloc(value->length + 1);
        snprintf((char*)this->m_assertion, value->length + 1, "%s", (char*) value->value);
        return true;
    }

    return false;
}

bool
gss_eap_simplesaml_assertion_provider::deleteAttribute(const gss_buffer_t value GSSEAP_UNUSED)
{
    delete m_assertion;
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

    str.length = strlen(this->m_assertion);
    str.value = (void*) this->m_assertion;

    if (value != NULL)
        duplicateBuffer(str, value);
    if (display_value != NULL)
        duplicateBuffer(str, display_value);

    *more = 0;

    return true;
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
    delete ((char *)input);
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

OM_uint32
gssEapSimpleSamlAttrProvidersInit(OM_uint32 *minor)
{
    if (!gss_eap_simplesaml_assertion_provider::init()) {
        *minor = GSSEAP_SAML_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapSimpleSamlAttrProvidersFinalize(OM_uint32 *minor)
{
    gss_eap_simplesaml_assertion_provider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}
