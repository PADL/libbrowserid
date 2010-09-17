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

#include <string>
#include <exception>
#include <new>

static gss_eap_attr_create_cb
gss_eap_attr_factories[ATTR_TYPE_MAX] = {
    gss_eap_radius_attr_provider::createAttrContext,
    gss_eap_saml_assertion_provider::createAttrContext,
    gss_eap_saml_attr_provider::createAttrContext,
    gss_eap_shib_attr_provider::createAttrContext
};

gss_eap_attr_ctx *
gss_eap_attr_ctx::createAttrContext(void)
{
    gss_eap_attr_ctx *ctx;

    ctx = new gss_eap_attr_ctx;

    for (unsigned int i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        provider = (gss_eap_attr_factories[i])();
        if (provider != NULL)
            ctx->m_providers[i] = provider;
    }

    return ctx;
}

bool
gss_eap_attr_ctx::initFromExistingContext(const gss_eap_attr_ctx *source,
                                          const gss_eap_attr_provider *ctx)
{
    if (!gss_eap_attr_provider::initFromExistingContext(this, ctx))
        return false;

    for (unsigned int i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        provider = m_providers[i];
        if (provider != NULL) {
            if (!provider->initFromExistingContext(this, provider))
                return false;
        }
    }

    return true;
}

bool
gss_eap_attr_ctx::initFromGssContext(const gss_eap_attr_ctx *source,
                                     const gss_cred_id_t cred,
                                     const gss_ctx_id_t ctx)
{
    if (!gss_eap_attr_provider::initFromGssContext(this, cred, ctx))
        return false;

    for (unsigned int i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        provider = m_providers[i];
        if (provider != NULL) {
            if (!provider->initFromGssContext(this, cred, ctx))
                return false;
        }
    }

    return true;
}

gss_eap_attr_ctx::~gss_eap_attr_ctx(void)
{
    for (unsigned int i = 0; i < ATTR_TYPE_MAX; i++)
        delete m_providers[i];
}

bool
gss_eap_attr_ctx::init(void)
{
    return gss_eap_radius_attr_provider::init() &&
           gss_eap_saml_assertion_provider::init() &&
           gss_eap_saml_attr_provider::init() &&
           gss_eap_shib_attr_provider::init();
}

void
gss_eap_attr_ctx::finalize(void)
{
    gss_eap_shib_attr_provider::finalize();
    gss_eap_saml_attr_provider::finalize();
    gss_eap_saml_assertion_provider::finalize();
    gss_eap_radius_attr_provider::finalize();
}

gss_eap_attr_provider *
gss_eap_attr_ctx::getProvider(unsigned int type) const
{
    return m_providers[type];
}

gss_eap_attr_provider *
gss_eap_attr_ctx::getProvider(const gss_buffer_t prefix) const
{
    unsigned int type;

    type = attributePrefixToType(prefix);

    return m_providers[type];
}

void
gss_eap_attr_ctx::setAttribute(int complete,
                               const gss_buffer_t attr,
                               const gss_buffer_t value)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        provider->setAttribute(complete,
                               (type == ATTR_TYPE_LOCAL) ? attr : &suffix,
                               value);
                               
    }
}

void
gss_eap_attr_ctx::deleteAttribute(const gss_buffer_t attr)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        provider->deleteAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix);
    }
}

bool
gss_eap_attr_ctx::getAttributeTypes(gss_eap_attr_enumeration_cb cb, void *data) const
{
    bool ret = false;
    size_t i;

    for (i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        provider = m_providers[i];
        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(cb, data);
        if (ret == false)
            break;
    }

    return ret;
}

struct eap_gss_get_attr_types_args {
    unsigned int type;
    gss_buffer_set_t attrs;
};

static bool
addAttribute(const gss_eap_attr_provider *provider,
             const gss_buffer_t attribute,
             void *data)
{
    eap_gss_get_attr_types_args *args = (eap_gss_get_attr_types_args *)data;
    gss_buffer_t prefix = GSS_C_NO_BUFFER;
    gss_buffer_desc qualified;
    OM_uint32 major, minor;

    if (args->type != ATTR_TYPE_LOCAL) {
        gss_eap_attr_ctx::composeAttributeName(args->type, attribute, &qualified);
        major = gss_add_buffer_set_member(&minor, &qualified, &args->attrs);
        gss_release_buffer(&minor, &qualified);
    } else {
        major = gss_add_buffer_set_member(&minor, prefix, &args->attrs);
    }

    return GSS_ERROR(major) ? false : true;
}

bool
gss_eap_attr_ctx::getAttributeTypes(gss_buffer_set_t *attrs)
{
    eap_gss_get_attr_types_args args;
    OM_uint32 major, minor;
    bool ret = false;
    unsigned int i;

    major = gss_create_empty_buffer_set(&minor, attrs);
    if (GSS_ERROR(major)) {
        throw new std::bad_alloc;
        return false;
    }

    args.attrs = *attrs;

    for (i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider;

        args.type = i;

        provider = m_providers[i];
        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(addAttribute, (void *)&args);
        if (ret == false)
            break;
    }

    if (ret == false) {
        gss_release_buffer_set(&minor, attrs);
    }

    return ret;
}

bool
gss_eap_attr_ctx::getAttribute(const gss_buffer_t attr,
                               int *authenticated,
                               int *complete,
                               gss_buffer_t value,
                               gss_buffer_t display_value,
                               int *more) const
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    gss_eap_attr_provider *provider;
    bool ret;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider == NULL) {
        *more = 0;
        return false;
    }

    ret = provider->getAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix,
                                 authenticated, complete,
                                 value, display_value, more);

    return ret;
}

gss_any_t
gss_eap_attr_ctx::mapToAny(int authenticated,
                           gss_buffer_t type_id) const
{
    return NULL;
}

void
gss_eap_attr_ctx::releaseAnyNameMapping(gss_buffer_t type_id,
                                        gss_any_t input) const
{
}

void
gss_eap_attr_ctx::marshall(gss_buffer_t buffer) const
{
    /* For now, just marshall the RADIUS context. */
}

bool
gss_eap_attr_ctx::unmarshall(const gss_eap_attr_ctx *ctx,
                             const gss_buffer_t buffer)
{
    unsigned int i;

    for (i = 0; i < ATTR_TYPE_MAX; i++) {
        gss_eap_attr_provider *provider = m_providers[i];
    }
}


/*
 * C wrappers
 */

static OM_uint32
mapException(OM_uint32 *minor, std::exception &e)
{
    *minor = 0;
    return GSS_S_FAILURE;
}

static gss_buffer_desc attributePrefixes[] = {
    {
        /* ATTR_TYPE_RADIUS_AVP */
        sizeof("urn:ietf:params:gss-eap:radius-avp"),
        (void *)"urn:ietf:params:gss-eap:radius-avp",
    },
    {
        /* ATTR_TYPE_SAML_AAA_ASSERTION */
        sizeof("urn:ietf:params:gss-eap:saml-aaa-assertion"),
        (void *)"urn:ietf:params:gss-eap:saml-aaa-assertion"
    },
    {
        /* ATTR_TYPE_SAML_ATTR */
        sizeof("urn:ietf:params:gss-eap:saml-attr"),
        (void *)"urn:ietf:params:gss-eap:saml-attr"
    },
};

unsigned int
gss_eap_attr_ctx::attributePrefixToType(const gss_buffer_t prefix)
{
    unsigned int i;

    for (i = ATTR_TYPE_MIN;
         i < sizeof(attributePrefixes) / sizeof(attributePrefixes[0]);
         i++)
    {
        if (bufferEqual(&attributePrefixes[i], prefix))
            return i;
    }

    return ATTR_TYPE_LOCAL;
}

gss_buffer_t
gss_eap_attr_ctx::attributeTypeToPrefix(unsigned int type)
{
    if (type < ATTR_TYPE_MIN || type >= ATTR_TYPE_LOCAL)
        return GSS_C_NO_BUFFER;

    return &attributePrefixes[type];
}

void
gss_eap_attr_ctx::decomposeAttributeName(const gss_buffer_t attribute,
                                         gss_buffer_t prefix,
                                         gss_buffer_t suffix)
{
    char *p = NULL;
    size_t i;

    for (i = 0; i < attribute->length; i++) {
        if (((char *)attribute->value)[i] == ' ') {
            p = (char *)attribute->value + i + 1;
            break;
        }
    }

    prefix->value = attribute->value;
    prefix->length = i;

    if (p != NULL && *p != '\0')  {
        suffix->length = attribute->length - 1 - prefix->length;
        suffix->value = p;
    } else {
        suffix->length = 0;
        suffix->value = NULL;
    }
}

void
gss_eap_attr_ctx::composeAttributeName(const gss_buffer_t prefix,
                                       const gss_buffer_t suffix,
                                       gss_buffer_t attribute)
{
    size_t len = 0;
    char *p;

    attribute->length = 0;
    attribute->value = NULL;

    if (prefix == GSS_C_NO_BUFFER || prefix->length == 0)
        return;

    len = prefix->length;
    if (suffix != GSS_C_NO_BUFFER) {
        len += 1 + suffix->length;
    }

    attribute->value = GSSEAP_MALLOC(len + 1);
    if (attribute->value == NULL) {
        throw new std::bad_alloc;
    }
    attribute->length = len;

    p = (char *)attribute->value;
    memcpy(p, prefix->value, prefix->length);
    if (suffix != NULL) {
        p[prefix->length] = ' ';
        memcpy(p + prefix->length + 1, suffix->value, suffix->length);
    }

    p[attribute->length] = '\0';
}

void
gss_eap_attr_ctx::decomposeAttributeName(const gss_buffer_t attribute,
                                         unsigned int*type,
                                         gss_buffer_t suffix)
{
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;

    decomposeAttributeName(attribute, &prefix, suffix);
    *type = attributePrefixToType(&prefix);
}

void
gss_eap_attr_ctx::composeAttributeName(unsigned int type,
                                       const gss_buffer_t suffix,
                                       gss_buffer_t attribute)
{
    gss_buffer_t prefix = attributeTypeToPrefix(type);

    composeAttributeName(prefix, suffix, attribute);
}

OM_uint32
gssEapInquireName(OM_uint32 *minor,
                  gss_name_t name,
                  int *name_is_MN,
                  gss_OID *MN_mech,
                  gss_buffer_set_t *attrs)
{
    if (name->attrCtx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->getAttributeTypes(attrs))
            return GSS_S_UNAVAILABLE;
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapGetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more)
{
    *authenticated = 0;
    *complete = 0;

    value->length = 0;
    value->value = NULL;

    if (display_value != NULL) {
        display_value->length = 0;
        display_value->value = NULL;
    }

    *more = -1;

    if (name->attrCtx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->getAttribute(attr, authenticated, complete,
                                         value, display_value, more))
            return GSS_S_UNAVAILABLE;
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapDeleteNameAttribute(OM_uint32 *minor,
                          gss_name_t name,
                          gss_buffer_t attr)
{
    if (name->attrCtx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        name->attrCtx->deleteAttribute(attr);
    } catch (std::exception &ex) {
        return mapException(minor, ex);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapSetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       int complete,
                       gss_buffer_t attr,
                       gss_buffer_t value)
{
    if (name->attrCtx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        name->attrCtx->setAttribute(complete, attr, value);
    } catch (std::exception &ex) {
        return mapException(minor, ex);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapExportAttrContext(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t buffer)
{
    if (name->attrCtx == NULL) {
        buffer->length = 0;
        buffer->value = NULL;

        return GSS_S_COMPLETE;
    };

    try {
        name->attrCtx->marshall(buffer);
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapImportAttrContext(OM_uint32 *minor,
                        gss_buffer_t buffer,
                        gss_name_t name)
{
    if (buffer->length)
        GSSEAP_NOT_IMPLEMENTED;
}

OM_uint32
gssEapDuplicateAttrContext(OM_uint32 *minor,
                           gss_name_t in,
                           gss_name_t out)
{
    try {
        if (in->attrCtx != NULL) {
            gss_eap_attr_ctx *ctx = new gss_eap_attr_ctx;

            out->attrCtx = new gss_eap_attr_ctx;
            if (!ctx->initFromExistingContext(NULL, in->attrCtx)) {
                delete ctx;
                return GSS_S_FAILURE;
            }
            out->attrCtx = ctx;
        } else
            out->attrCtx = NULL;
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapMapNameToAny(OM_uint32 *minor,
                   gss_name_t name,
                   int authenticated,
                   gss_buffer_t type_id,
                   gss_any_t *output)
{
    try {
        *output = name->attrCtx->mapToAny(authenticated, type_id);
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseAnyNameMapping(OM_uint32 *minor,
                            gss_name_t name,
                            gss_buffer_t type_id,
                            gss_any_t *input)
{
    if (name->attrCtx == NULL)
        return GSS_S_UNAVAILABLE;

    try {
        if (*input != NULL)
            name->attrCtx->releaseAnyNameMapping(type_id, *input);
        *input = NULL;
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapReleaseAttrContext(OM_uint32 *minor,
                         gss_name_t name)
{
    if (name->attrCtx != NULL)
        delete name->attrCtx;

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapAttrProvidersInit(OM_uint32 *minor)
{
    try {
        gss_eap_attr_ctx::init();
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapAttrProvidersFinalize(OM_uint32 *minor)
{
    try {
        gss_eap_attr_ctx::finalize();
    } catch (std::exception &e) {
        return mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

struct gss_eap_attr_ctx *
gssEapCreateAttrContext(gss_cred_id_t gssCred,
                        gss_ctx_id_t gssCtx)
{
    gss_eap_attr_ctx *ctx;

    ctx = gss_eap_attr_ctx::createAttrContext();
    if (!ctx->initFromGssContext(NULL, gssCred, gssCtx)) {
        delete ctx;
        return NULL;
    }

    return ctx;
}
