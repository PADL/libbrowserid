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
 * Attribute provider mechanism.
 */

#include "gssapiP_bid.h"

#include <typeinfo>
#include <string>
#include <sstream>
#include <exception>
#include <new>

/* lazy initialisation */
static GSSBID_THREAD_ONCE gssBidAttrProvidersInitOnce = GSSBID_ONCE_INITIALIZER;
static OM_uint32 gssBidAttrProvidersInitStatus = GSS_S_UNAVAILABLE;

GSSBID_ONCE_CALLBACK(gssBidAttrProvidersInitInternal)
{
    OM_uint32 major, minor;

    GSSBID_ASSERT(gssBidAttrProvidersInitStatus == GSS_S_UNAVAILABLE);

    json_set_alloc_funcs(GSSBID_MALLOC, GSSBID_FREE);

    major = gssBidJwtAttrProviderInit(&minor);
    if (GSS_ERROR(major))
        goto cleanup;


#ifdef HAVE_SHIBRESOLVER
    /* Allow Shibboleth initialization failure to be non-fatal */
    gssBidLocalAttrProviderInit(&minor);
#endif
#ifdef HAVE_OPENSAML
    major = gssBidSamlAttrProvidersInit(&minor);
    if (GSS_ERROR(major))
        goto cleanup;
#endif

cleanup:
#ifdef GSSBID_DEBUG
    GSSBID_ASSERT(major == GSS_S_COMPLETE);
#endif

    gssBidAttrProvidersInitStatus = major;

    GSSBID_ONCE_LEAVE;
}

static OM_uint32
gssBidAttrProvidersInit(OM_uint32 *minor)
{
    GSSBID_ONCE(&gssBidAttrProvidersInitOnce, gssBidAttrProvidersInitInternal);

    if (GSS_ERROR(gssBidAttrProvidersInitStatus))
        *minor = GSSBID_NO_ATTR_PROVIDERS;

    return gssBidAttrProvidersInitStatus;
}

OM_uint32
gssBidAttrProvidersFinalize(OM_uint32 *minor)
{
    if (gssBidAttrProvidersInitStatus == GSS_S_COMPLETE) {
#ifdef HAVE_SHIBRESOLVER
        gssBidLocalAttrProviderFinalize(minor);
#endif
#ifdef HAVE_OPENSAML
        gssBidSamlAttrProvidersFinalize(minor);
#endif
        gssBidJwtAttrProviderFinalize(minor);

        gssBidAttrProvidersInitStatus = GSS_S_UNAVAILABLE;
    }

    return GSS_S_COMPLETE;
}

static BIDGSSAttributeFactory gssBidAttrFactories[ATTR_TYPE_MAX + 1];

/*
 * Register a provider for a particular type and prefix
 */
void
BIDGSSAttributeContext::registerProvider(unsigned int type,
                                         BIDGSSAttributeFactory factory)
{
    GSSBID_ASSERT(type <= ATTR_TYPE_MAX);

    GSSBID_ASSERT(gssBidAttrFactories[type] == NULL);

    gssBidAttrFactories[type] = factory;
}

/*
 * Unregister a provider
 */
void
BIDGSSAttributeContext::unregisterProvider(unsigned int type)
{
    GSSBID_ASSERT(type <= ATTR_TYPE_MAX);

    gssBidAttrFactories[type] = NULL;
}

/*
 * Create an attribute context, that manages instances of providers
 */
BIDGSSAttributeContext::BIDGSSAttributeContext(void)
{
    m_flags = 0;

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider;

        if (gssBidAttrFactories[i] != NULL) {
            provider = (gssBidAttrFactories[i])();
        } else {
            provider = NULL;
        }

        m_providers[i] = provider;
    }
}

/*
 * Convert an attribute prefix to a type
 */
unsigned int
BIDGSSAttributeContext::attributePrefixToType(const gss_buffer_t prefix) const
{
    unsigned int i;

    for (i = ATTR_TYPE_MIN; i < ATTR_TYPE_MAX; i++) {
        const char *pprefix;

        if (!providerEnabled(i))
            continue;

        pprefix = m_providers[i]->prefix();
        if (pprefix == NULL)
            continue;

        if (strlen(pprefix) == prefix->length &&
            memcmp(pprefix, prefix->value, prefix->length) == 0)
            return i;
    }

    return ATTR_TYPE_LOCAL;
}

/*
 * Convert a type to an attribute prefix
 */
gss_buffer_desc
BIDGSSAttributeContext::attributeTypeToPrefix(unsigned int type) const
{
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;

    if (type < ATTR_TYPE_MIN || type >= ATTR_TYPE_MAX)
        return prefix;

    if (!providerEnabled(type))
        return prefix;

    prefix.value = (void *)m_providers[type]->prefix();
    if (prefix.value != NULL)
        prefix.length = strlen((char *)prefix.value);

    return prefix;
}

bool
BIDGSSAttributeContext::providerEnabled(unsigned int type) const
{
    if (type == ATTR_TYPE_LOCAL &&
        (m_flags & ATTR_FLAG_DISABLE_LOCAL))
        return false;

    if (m_providers[type] == NULL)
        return false;

    return true;
}

void
BIDGSSAttributeContext::releaseProvider(unsigned int type)
{
    delete m_providers[type];
    m_providers[type] = NULL;
}

/*
 * Initialize a context from an existing context.
 */
bool
BIDGSSAttributeContext::initWithExistingContext(const BIDGSSAttributeContext *manager)
{
    bool ret = true;

    m_flags = manager->m_flags;

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider;

        if (!providerEnabled(i)) {
            releaseProvider(i);
            continue;
        }

        provider = m_providers[i];

        ret = provider->initWithExistingContext(this,
                                                manager->m_providers[i]);
        if (ret == false) {
            releaseProvider(i);
            break;
        }
    }

    return ret;
}

/*
 * Initialize a context from a GSS credential and context.
 */
bool
BIDGSSAttributeContext::initWithGssContext(const gss_cred_id_t cred,
                                           const gss_ctx_id_t ctx)
{
    bool ret = true;

    if (cred != GSS_C_NO_CREDENTIAL &&
        (cred->flags & GSS_BROWSERID_DISABLE_LOCAL_ATTRS_FLAG)) {
        m_flags |= ATTR_FLAG_DISABLE_LOCAL;
    }

    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider;

        if (!providerEnabled(i)) {
            releaseProvider(i);
            continue;
        }

        provider = m_providers[i];

        ret = provider->initWithGssContext(this, cred, ctx);
        if (ret == false) {
            releaseProvider(i);
            break;
        }
    }

    return ret;
}

bool
BIDGSSAttributeContext::initWithJsonObject(JSONObject &obj)
{
    bool ret = false;
    bool foundSource[ATTR_TYPE_MAX + 1];
    unsigned int type;

    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++)
        foundSource[type] = false;

    if (obj["version"].integer() != 1)
        return false;

    m_flags = obj["flags"].integer();

    JSONObject sources = obj["sources"];

    /* Initialize providers from serialized state */
    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++) {
        BIDGSSAttributeProvider *provider;
        const char *key;

        if (!providerEnabled(type)) {
            releaseProvider(type);
            continue;
        }

        provider = m_providers[type];
        key = provider->name();
        if (key == NULL)
            continue;

        JSONObject source = sources.get(key);
        if (!source.isNull() &&
            !provider->initWithJsonObject(this, source)) {
            releaseProvider(type);
            return false;
        }

        foundSource[type] = true;
    }

    /* Initialize remaining providers from initialized providers */
    for (type = ATTR_TYPE_MIN; type <= ATTR_TYPE_MAX; type++) {
        BIDGSSAttributeProvider *provider;

        if (foundSource[type] || !providerEnabled(type))
            continue;

        provider = m_providers[type];

        ret = provider->initWithGssContext(this,
                                           GSS_C_NO_CREDENTIAL,
                                           GSS_C_NO_CONTEXT);
        if (ret == false) {
            releaseProvider(type);
            return false;
        }
    }

    return true;
}

JSONObject
BIDGSSAttributeContext::jsonRepresentation(void) const
{
    JSONObject obj, sources;
    unsigned int i;

    obj.set("version", 1);
    obj.set("flags", m_flags);

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider;
        const char *key;

        provider = m_providers[i];
        if (provider == NULL)
            continue; /* provider not initialised */

        key = provider->name();
        if (key == NULL)
            continue; /* provider does not have state */

        JSONObject source = provider->jsonRepresentation();
        sources.set(key, source);
    }

    obj.set("sources", sources);

    return obj;
}

/*
 * Initialize a context from an exported context or name token
 */
bool
BIDGSSAttributeContext::initWithBuffer(const gss_buffer_t buffer)
{
    OM_uint32 major, minor;
    bool ret;
    char *s;
    json_error_t error;

    major = bufferToString(&minor, buffer, &s);
    if (GSS_ERROR(major))
        return false;

    JSONObject obj = JSONObject::load(s, 0, &error);
    if (!obj.isNull()) {
        ret = initWithJsonObject(obj);
    } else
        ret = false;

    GSSBID_FREE(s);

    return ret;
}

BIDGSSAttributeContext::~BIDGSSAttributeContext(void)
{
    for (unsigned int i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++)
        delete m_providers[i];
}

/*
 * Locate provider for a given type
 */
BIDGSSAttributeProvider *
BIDGSSAttributeContext::getProvider(unsigned int type) const
{
    GSSBID_ASSERT(type >= ATTR_TYPE_MIN && type <= ATTR_TYPE_MAX);
    return m_providers[type];
}

/*
 * Get primary provider. Only the primary provider is serialised when
 * gss_export_sec_context() or gss_export_name_composite() is called.
 */
BIDGSSAttributeProvider *
BIDGSSAttributeContext::getPrimaryProvider(void) const
{
    return m_providers[ATTR_TYPE_MIN];
}

/*
 * Set an attribute
 */
bool
BIDGSSAttributeContext::setAttribute(int complete,
                                     const gss_buffer_t attr,
                                     const gss_buffer_t value)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    BIDGSSAttributeProvider *provider;
    bool ret = false;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        ret = provider->setAttribute(complete,
                                     (type == ATTR_TYPE_LOCAL) ? attr : &suffix,
                                     value);
    }

    return ret;
}

/*
 * Delete an attrbiute
 */
bool
BIDGSSAttributeContext::deleteAttribute(const gss_buffer_t attr)
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    BIDGSSAttributeProvider *provider;
    bool ret = false;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL) {
        ret = provider->deleteAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix);
    }

    return ret;
}

/*
 * Enumerate attribute types with callback
 */
bool
BIDGSSAttributeContext::getAttributeTypes(BIDGSSAttributeIterator cb, void *data) const
{
    bool ret = false;
    size_t i;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider = m_providers[i];

        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(cb, data);
        if (ret == false)
            break;
    }

    return ret;
}

struct bid_gss_get_attr_types_args {
    unsigned int type;
    gss_buffer_set_t attrs;
};

static bool
addAttribute(const BIDGSSAttributeContext *manager,
             const BIDGSSAttributeProvider *provider GSSBID_UNUSED,
             const gss_buffer_t attribute,
             void *data)
{
    bid_gss_get_attr_types_args *args = (bid_gss_get_attr_types_args *)data;
    gss_buffer_desc qualified;
    OM_uint32 major, minor;

    if (args->type != ATTR_TYPE_LOCAL) {
        manager->composeAttributeName(args->type, attribute, &qualified);
        major = gss_add_buffer_set_member(&minor, &qualified, &args->attrs);
        gss_release_buffer(&minor, &qualified);
    } else {
        major = gss_add_buffer_set_member(&minor, attribute, &args->attrs);
    }

    return GSS_ERROR(major) == false;
}

/*
 * Enumerate attribute types, output is buffer set
 */
bool
BIDGSSAttributeContext::getAttributeTypes(gss_buffer_set_t *attrs)
{
    bid_gss_get_attr_types_args args;
    OM_uint32 major, minor;
    bool ret = false;
    unsigned int i;

    major = gss_create_empty_buffer_set(&minor, attrs);
    if (GSS_ERROR(major))
        throw std::bad_alloc();

    args.attrs = *attrs;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider = m_providers[i];

        args.type = i;

        if (provider == NULL)
            continue;

        ret = provider->getAttributeTypes(addAttribute, (void *)&args);
        if (ret == false)
            break;
    }

    if (ret == false)
        gss_release_buffer_set(&minor, attrs);

    return ret;
}

/*
 * Get attribute with given name
 */
bool
BIDGSSAttributeContext::getAttribute(const gss_buffer_t attr,
                                     int *authenticated,
                                     int *complete,
                                     gss_buffer_t value,
                                     gss_buffer_t display_value,
                                     int *more) const
{
    gss_buffer_desc suffix = GSS_C_EMPTY_BUFFER;
    unsigned int type;
    BIDGSSAttributeProvider *provider;
    bool ret;

    decomposeAttributeName(attr, &type, &suffix);

    provider = m_providers[type];
    if (provider == NULL)
        return false;

    ret = provider->getAttribute(type == ATTR_TYPE_LOCAL ? attr : &suffix,
                                 authenticated, complete,
                                 value, display_value, more);

    return ret;
}

/*
 * Map attribute context to C++ object
 */
gss_any_t
BIDGSSAttributeContext::mapToAny(int authenticated,
                                 gss_buffer_t type_id) const
{
    unsigned int type;
    BIDGSSAttributeProvider *provider;
    gss_buffer_desc suffix;

    decomposeAttributeName(type_id, &type, &suffix);

    provider = m_providers[type];
    if (provider == NULL)
        return (gss_any_t)NULL;

    return provider->mapToAny(authenticated, &suffix);
}

/*
 * Release mapped context
 */
void
BIDGSSAttributeContext::releaseAnyNameMapping(gss_buffer_t type_id,
                                              gss_any_t input) const
{
    unsigned int type;
    BIDGSSAttributeProvider *provider;
    gss_buffer_desc suffix;

    decomposeAttributeName(type_id, &type, &suffix);

    provider = m_providers[type];
    if (provider != NULL)
        provider->releaseAnyNameMapping(&suffix, input);
}

/*
 * Export attribute context to buffer
 */
void
BIDGSSAttributeContext::exportToBuffer(gss_buffer_t buffer) const
{
    OM_uint32 minor;
    char *s;

    JSONObject obj = jsonRepresentation();

#if 0
    obj.dump(stdout);
#endif

    s = obj.dump(JSON_COMPACT);

    if (GSS_ERROR(makeStringBuffer(&minor, s, buffer)))
        throw std::bad_alloc();
}

/*
 * Return soonest expiry time of providers
 */
time_t
BIDGSSAttributeContext::getExpiryTime(void) const
{
    unsigned int i;
    time_t expiryTime = 0;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider = m_providers[i];
        time_t providerExpiryTime;

        if (provider == NULL)
            continue;

        providerExpiryTime = provider->getExpiryTime();
        if (providerExpiryTime == 0)
            continue;

        if (expiryTime == 0 || providerExpiryTime < expiryTime)
            expiryTime = providerExpiryTime;
    }

    return expiryTime;
}

OM_uint32
BIDGSSAttributeContext::mapException(OM_uint32 *minor, std::exception &e) const
{
    unsigned int i;
    OM_uint32 major;

    /* Errors we handle ourselves */
    if (typeid(e) == typeid(std::bad_alloc)) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    } else if (typeid(e) == typeid(JSONException)) {
        major = GSS_S_BAD_NAME;
        *minor = GSSBID_BAD_ATTR_TOKEN;
        gssBidSaveStatusInfo(*minor, "%s", e.what());
        goto cleanup;
    }

    /* Errors we delegate to providers */
    major = GSS_S_CONTINUE_NEEDED;

    for (i = ATTR_TYPE_MIN; i <= ATTR_TYPE_MAX; i++) {
        BIDGSSAttributeProvider *provider = m_providers[i];

        if (provider == NULL)
            continue;

        major = provider->mapException(minor, e);
        if (major != GSS_S_CONTINUE_NEEDED)
            break;
    }

    if (major == GSS_S_CONTINUE_NEEDED) {
        *minor = GSSBID_ATTR_CONTEXT_FAILURE;
        major = GSS_S_FAILURE;
    }

cleanup:
    GSSBID_ASSERT(GSS_ERROR(major));

    return major;
}

/*
 * Decompose attribute name into prefix and suffix
 */
void
BIDGSSAttributeContext::decomposeAttributeName(const gss_buffer_t attribute,
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

/*
 * Decompose attribute name into type and suffix
 */
void
BIDGSSAttributeContext::decomposeAttributeName(const gss_buffer_t attribute,
                                               unsigned int *type,
                                               gss_buffer_t suffix) const
{
    gss_buffer_desc prefix = GSS_C_EMPTY_BUFFER;

    decomposeAttributeName(attribute, &prefix, suffix);
    *type = attributePrefixToType(&prefix);
}

/*
 * Compose attribute name from prefix, suffix; returns C++ string
 */
std::string
BIDGSSAttributeContext::composeAttributeName(const gss_buffer_t prefix,
                                             const gss_buffer_t suffix)
{
    std::string str;

    if (prefix == GSS_C_NO_BUFFER || prefix->length == 0)
        return str;

    str.append((const char *)prefix->value, prefix->length);

    if (suffix != GSS_C_NO_BUFFER) {
        str.append(" ");
        str.append((const char *)suffix->value, suffix->length);
    }

    return str;
}

/*
 * Compose attribute name from type, suffix; returns C++ string
 */
std::string
BIDGSSAttributeContext::composeAttributeName(unsigned int type,
                                             const gss_buffer_t suffix)
{
    gss_buffer_desc prefix = attributeTypeToPrefix(type);

    return composeAttributeName(&prefix, suffix);
}

/*
 * Compose attribute name from prefix, suffix; returns GSS buffer
 */
void
BIDGSSAttributeContext::composeAttributeName(const gss_buffer_t prefix,
                                             const gss_buffer_t suffix,
                                             gss_buffer_t attribute)
{
    std::string str = composeAttributeName(prefix, suffix);

    if (str.length() != 0) {
        return duplicateBuffer(str, attribute);
    } else {
        attribute->length = 0;
        attribute->value = NULL;
    }
}

/*
 * Compose attribute name from type, suffix; returns GSS buffer
 */
void
BIDGSSAttributeContext::composeAttributeName(unsigned int type,
                                             const gss_buffer_t suffix,
                                             gss_buffer_t attribute) const
{
    gss_buffer_desc prefix = attributeTypeToPrefix(type);

    return composeAttributeName(&prefix, suffix, attribute);
}

/*
 * C wrappers
 */
OM_uint32
gssBidInquireName(OM_uint32 *minor,
                  gss_name_t name,
                  int *name_is_MN,
                  gss_OID *MN_mech,
                  gss_buffer_set_t *attrs)
{
    OM_uint32 major;

    if (name_is_MN != NULL)
        *name_is_MN = (name->mechanismUsed != GSS_C_NULL_OID);

    if (MN_mech != NULL) {
        major = gssBidCanonicalizeOid(minor, name->mechanismUsed,
                                      OID_FLAG_NULL_VALID, MN_mech);
        if (GSS_ERROR(major))
            return major;
    }

    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor))) {
        return GSS_S_UNAVAILABLE;
    }

    try {
        if (!name->attrCtx->getAttributeTypes(attrs)) {
            *minor = GSSBID_NO_ATTR_CONTEXT;
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidGetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more)
{
    if (authenticated != NULL)
        *authenticated = 0;
    if (complete != NULL)
        *complete = 0;

    if (value != NULL) {
        value->length = 0;
        value->value = NULL;
    }

    if (display_value != NULL) {
        display_value->length = 0;
        display_value->value = NULL;
    }

    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor))) {
        return GSS_S_UNAVAILABLE;
    }

    try {
        if (!name->attrCtx->getAttribute(attr, authenticated, complete,
                                         value, display_value, more)) {
            *minor = GSSBID_NO_SUCH_ATTR;
            gssBidSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidDeleteNameAttribute(OM_uint32 *minor,
                          gss_name_t name,
                          gss_buffer_t attr)
{
    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->deleteAttribute(attr)) {
            *minor = GSSBID_NO_SUCH_ATTR;
            gssBidSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidSetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       int complete,
                       gss_buffer_t attr,
                       gss_buffer_t value)
{
    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (!name->attrCtx->setAttribute(complete, attr, value)) {
             *minor = GSSBID_NO_SUCH_ATTR;
            gssBidSaveStatusInfo(*minor, "Unknown naming attribute %.*s",
                                 (int)attr->length, (char *)attr->value);
            return GSS_S_UNAVAILABLE;
        }
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidExportAttrContext(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t buffer)
{
    if (name->attrCtx == NULL) {
        buffer->length = 0;
        buffer->value = NULL;

        return GSS_S_COMPLETE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        name->attrCtx->exportToBuffer(buffer);
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidImportAttrContext(OM_uint32 *minor,
                        gss_buffer_t buffer,
                        gss_name_t name)
{
    BIDGSSAttributeContext *ctx = NULL;
    OM_uint32 major = GSS_S_FAILURE;

    GSSBID_ASSERT(name->attrCtx == NULL);

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    if (buffer->length == 0)
        return GSS_S_COMPLETE;

    try {
        ctx = new BIDGSSAttributeContext();

        if (ctx->initWithBuffer(buffer)) {
            name->attrCtx = ctx;
            major = GSS_S_COMPLETE;
            *minor = 0;
        } else {
            major = GSS_S_BAD_NAME;
            *minor = GSSBID_ATTR_CONTEXT_FAILURE;
        }
    } catch (std::exception &e) {
        if (ctx != NULL)
            major = ctx->mapException(minor, e);
    }

    GSSBID_ASSERT(major == GSS_S_COMPLETE || name->attrCtx == NULL);

    if (GSS_ERROR(major))
        delete ctx;

    return major;
}

OM_uint32
gssBidDuplicateAttrContext(OM_uint32 *minor,
                           gss_name_t in,
                           gss_name_t out)
{
    BIDGSSAttributeContext *ctx = NULL;
    OM_uint32 major = GSS_S_FAILURE;

    GSSBID_ASSERT(out->attrCtx == NULL);

    if (in->attrCtx == NULL) {
        *minor = 0;
        return GSS_S_COMPLETE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        ctx = new BIDGSSAttributeContext();

        if (ctx->initWithExistingContext(in->attrCtx)) {
            out->attrCtx = ctx;
            major = GSS_S_COMPLETE;
            *minor = 0;
        } else {
            major = GSS_S_FAILURE;
            *minor = GSSBID_ATTR_CONTEXT_FAILURE;
        }
    } catch (std::exception &e) {
        major = in->attrCtx->mapException(minor, e);
    }

    GSSBID_ASSERT(major == GSS_S_COMPLETE || out->attrCtx == NULL);

    if (GSS_ERROR(major))
        delete ctx;

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidMapNameToAny(OM_uint32 *minor,
                   gss_name_t name,
                   int authenticated,
                   gss_buffer_t type_id,
                   gss_any_t *output)
{
    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        *output = name->attrCtx->mapToAny(authenticated, type_id);
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidReleaseAnyNameMapping(OM_uint32 *minor,
                            gss_name_t name,
                            gss_buffer_t type_id,
                            gss_any_t *input)
{
    if (name->attrCtx == NULL) {
        *minor = GSSBID_NO_ATTR_CONTEXT;
        return GSS_S_UNAVAILABLE;
    }

    if (GSS_ERROR(gssBidAttrProvidersInit(minor)))
        return GSS_S_UNAVAILABLE;

    try {
        if (*input != NULL)
            name->attrCtx->releaseAnyNameMapping(type_id, *input);
        *input = NULL;
    } catch (std::exception &e) {
        return name->attrCtx->mapException(minor, e);
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidReleaseAttrContext(OM_uint32 *minor,
                         gss_name_t name)
{
    if (name->attrCtx != NULL)
        delete name->attrCtx;

    *minor = 0;
    return GSS_S_COMPLETE;
}

/*
 * Public accessor for initialisng a context from a GSS context. Also
 * sets expiry time on GSS context as a side-effect.
 */
OM_uint32
gssBidCreateAttrContext(OM_uint32 *minor,
                        gss_cred_id_t gssCred,
                        gss_ctx_id_t gssCtx,
                        struct BIDGSSAttributeContext **pAttrContext,
                        time_t *pExpiryTime)
{
    BIDGSSAttributeContext *ctx = NULL;
    OM_uint32 major;

    GSSBID_ASSERT(gssCtx != GSS_C_NO_CONTEXT);

    *pAttrContext = NULL;

    major = gssBidAttrProvidersInit(minor);
    if (GSS_ERROR(major))
        return major;

    try {
        /* Set *pAttrContext here to for reentrancy */
        *pAttrContext = ctx = new BIDGSSAttributeContext();

        if (ctx->initWithGssContext(gssCred, gssCtx)) {
            *pExpiryTime = ctx->getExpiryTime();
            major = GSS_S_COMPLETE;
            *minor = 0;
        } else {
            major = GSS_S_FAILURE;
            *minor = GSSBID_ATTR_CONTEXT_FAILURE;
        }
    } catch (std::exception &e) {
        if (ctx != NULL)
            major = ctx->mapException(minor, e);
    }

    if (GSS_ERROR(major)) {
        delete ctx;
        *pAttrContext = NULL;
    }

    return major;
}
