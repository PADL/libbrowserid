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
 * RADIUS attribute provider implementation.
 */

#include "gssapiP_eap.h"
#include "util_radius.h"
#include "utils/radius_utils.h"

#ifdef GSSEAP_ENABLE_ACCEPTOR

/* stuff that should be provided by libradsec/libfreeradius-radius */
#define VENDORATTR(vendor, attr)            (((vendor) << 16) | (attr))

#ifndef ATTRID
#define ATTRID(attr)                        ((attr) & 0xFFFF)
#endif

static gss_buffer_desc radiusUrnPrefix = {
    sizeof("urn:x-radius:") - 1,
    (void *)"urn:x-radius:"
};

static VALUE_PAIR *copyAvps(const VALUE_PAIR *src);

gss_eap_radius_attr_provider::gss_eap_radius_attr_provider(void)
{
    m_vps = NULL;
    m_authenticated = false;
}

gss_eap_radius_attr_provider::~gss_eap_radius_attr_provider(void)
{
    if (m_vps != NULL)
        pairfree(&m_vps);
}

bool
gss_eap_radius_attr_provider::initWithExistingContext(const gss_eap_attr_ctx *manager,
                                                      const gss_eap_attr_provider *ctx)
{
    const gss_eap_radius_attr_provider *radius;

    if (!gss_eap_attr_provider::initWithExistingContext(manager, ctx))
        return false;

    radius = static_cast<const gss_eap_radius_attr_provider *>(ctx);

    if (radius->m_vps != NULL)
        m_vps = copyAvps(const_cast<VALUE_PAIR *>(radius->getAvps()));

    m_authenticated = radius->m_authenticated;

    return true;
}

bool
gss_eap_radius_attr_provider::initWithGssContext(const gss_eap_attr_ctx *manager,
                                                 const gss_cred_id_t gssCred,
                                                 const gss_ctx_id_t gssCtx)
{
    if (!gss_eap_attr_provider::initWithGssContext(manager, gssCred, gssCtx))
        return false;

    if (gssCtx != GSS_C_NO_CONTEXT) {
        if (gssCtx->acceptorCtx.vps != NULL) {
            m_vps = copyAvps(gssCtx->acceptorCtx.vps);
            if (m_vps == NULL)
                return false;

            /* We assume libradsec validated this for us */
            GSSEAP_ASSERT(pairfind(m_vps, PW_MESSAGE_AUTHENTICATOR) != NULL);
            m_authenticated = true;
        }
    }

    return true;
}

static bool
alreadyAddedAttributeP(std::vector <std::string> &attrs, VALUE_PAIR *vp)
{
    for (std::vector<std::string>::const_iterator a = attrs.begin();
         a != attrs.end();
         ++a) {
        if (strcmp(vp->name, (*a).c_str()) == 0)
            return true;
    }

    return false;
}

static bool
isSecretAttributeP(uint16_t attrid, uint16_t vendor)
{
    bool bSecretAttribute = false;

    switch (vendor) {
    case VENDORPEC_MS:
        switch (attrid) {
        case PW_MS_MPPE_SEND_KEY:
        case PW_MS_MPPE_RECV_KEY:
            bSecretAttribute = true;
            break;
        default:
            break;
        }
    default:
        break;
    }

    return bSecretAttribute;
}

static bool
isSecretAttributeP(uint32_t attribute)
{
    return isSecretAttributeP(ATTRID(attribute), VENDOR(attribute));
}

static bool
isInternalAttributeP(uint16_t attrid, uint16_t vendor)
{
    bool bInternalAttribute = false;

    /* should have been filtered */
    GSSEAP_ASSERT(!isSecretAttributeP(attrid, vendor));

    switch (vendor) {
    case VENDORPEC_UKERNA:
        switch (attrid) {
        case PW_GSS_ACCEPTOR_SERVICE_NAME:
        case PW_GSS_ACCEPTOR_HOST_NAME:
        case PW_GSS_ACCEPTOR_SERVICE_SPECIFIC:
        case PW_GSS_ACCEPTOR_REALM_NAME:
        case PW_SAML_AAA_ASSERTION:
            bInternalAttribute = true;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return bInternalAttribute;
}

static bool
isInternalAttributeP(uint32_t attribute)
{
    return isInternalAttributeP(ATTRID(attribute), VENDOR(attribute));
}

static bool
isFragmentedAttributeP(uint16_t attrid, uint16_t vendor)
{
    /* A bit of a hack for the PAC for now. Should be configurable. */
    return (vendor == VENDORPEC_UKERNA) &&
        !isInternalAttributeP(attrid, vendor);
}

static bool
isFragmentedAttributeP(uint32_t attribute)
{
    return isFragmentedAttributeP(ATTRID(attribute), VENDOR(attribute));
}

/*
 * Copy AVP list, same as paircopy except it filters out attributes
 * containing keys.
 */
static VALUE_PAIR *
copyAvps(const VALUE_PAIR *src)
{
    const VALUE_PAIR *vp;
    VALUE_PAIR *dst = NULL, **pDst = &dst;

    for (vp = src; vp != NULL; vp = vp->next) {
        VALUE_PAIR *vpcopy;

        if (isSecretAttributeP(vp->attribute))
            continue;

        vpcopy = paircopyvp(vp);
        if (vpcopy == NULL) {
            pairfree(&dst);
            throw std::bad_alloc();
        }
        *pDst = vpcopy;
        pDst = &vpcopy->next;
     }

    return dst;
}

bool
gss_eap_radius_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                                void *data) const
{
    VALUE_PAIR *vp;
    std::vector <std::string> seen;

    for (vp = m_vps; vp != NULL; vp = vp->next) {
        gss_buffer_desc attribute;
        char attrid[64];

        /* Don't advertise attributes that are internal to the GSS-EAP mechanism */
        if (isInternalAttributeP(vp->attribute))
            continue;

        if (alreadyAddedAttributeP(seen, vp))
            continue;

        snprintf(attrid, sizeof(attrid), "%s%d",
            (char *)radiusUrnPrefix.value, vp->attribute);

        attribute.value = attrid;
        attribute.length = strlen(attrid);

        if (!addAttribute(m_manager, this, &attribute, data))
            return false;

        seen.push_back(std::string(vp->name));
    }

    return true;
}

uint32_t
getAttributeId(const gss_buffer_t attr)
{
    OM_uint32 tmpMinor;
    gss_buffer_desc strAttr = GSS_C_EMPTY_BUFFER;
    DICT_ATTR *da;
    char *s;
    uint32_t attrid = 0;

    if (attr->length < radiusUrnPrefix.length ||
        memcmp(attr->value, radiusUrnPrefix.value, radiusUrnPrefix.length) != 0)
        return 0;

    /* need to duplicate because attr may not be NUL terminated */
    duplicateBuffer(*attr, &strAttr);
    s = (char *)strAttr.value + radiusUrnPrefix.length;

    if (isdigit(*s)) {
        attrid = strtoul(s, NULL, 10);
    } else {
        da = dict_attrbyname(s);
        if (da != NULL)
            attrid = da->attr;
    }

    gss_release_buffer(&tmpMinor, &strAttr);

    return attrid;
}

bool
gss_eap_radius_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                           uint32_t attrid,
                                           const gss_buffer_t value)
{
    OM_uint32 major = GSS_S_UNAVAILABLE, minor;

    if (!isSecretAttributeP(attrid) &&
        !isInternalAttributeP(attrid)) {
        deleteAttribute(attrid);

        major = gssEapRadiusAddAvp(&minor, &m_vps,
                                   ATTRID(attrid), VENDOR(attrid), 
                                   value);
    }

    return !GSS_ERROR(major);
}

bool
gss_eap_radius_attr_provider::setAttribute(int complete,
                                           const gss_buffer_t attr,
                                           const gss_buffer_t value)
{
    uint32_t attrid = getAttributeId(attr);

    if (!attrid)
        return false;

    return setAttribute(complete, attrid, value);
}

bool
gss_eap_radius_attr_provider::deleteAttribute(uint32_t attrid)
{
    if (isSecretAttributeP(attrid) || isInternalAttributeP(attrid) ||
        pairfind(m_vps, attrid) == NULL)
        return false;

    pairdelete(&m_vps, attrid);

    return true;
}

bool
gss_eap_radius_attr_provider::deleteAttribute(const gss_buffer_t attr)
{
    uint32_t attrid = getAttributeId(attr);

    if (!attrid)
        return false;

    return deleteAttribute(attrid);
}

bool
gss_eap_radius_attr_provider::getAttribute(const gss_buffer_t attr,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{
    uint32_t attrid;

    attrid = getAttributeId(attr);
    if (!attrid)
        return false;

    return getAttribute(attrid, authenticated, complete,
                        value, display_value, more);
}

bool
gss_eap_radius_attr_provider::getAttribute(uint32_t attrid,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{
    VALUE_PAIR *vp;
    int i = *more, count = 0;

    *more = 0;

    if (i == -1)
        i = 0;

    if (isSecretAttributeP(attrid) || isInternalAttributeP(attrid)) {
        return false;
    } else if (isFragmentedAttributeP(attrid)) {
        return getFragmentedAttribute(attrid,
                                      authenticated,
                                      complete,
                                      value);
    }

    for (vp = pairfind(m_vps, attrid);
         vp != NULL;
         vp = pairfind(vp->next, attrid)) {
        if (count++ == i) {
            if (pairfind(vp->next, attrid) != NULL)
                *more = count;
            break;
        }
    }

    if (vp == NULL && *more == 0)
        return false;

    if (value != GSS_C_NO_BUFFER) {
        gss_buffer_desc valueBuf;

        valueBuf.value = (void *)vp->vp_octets;
        valueBuf.length = vp->length;

        duplicateBuffer(valueBuf, value);
    }

    if (display_value != GSS_C_NO_BUFFER &&
        vp->type != PW_TYPE_OCTETS) {
        char displayString[MAX_STRING_LEN];
        gss_buffer_desc displayBuf;

        displayBuf.length = vp_prints_value(displayString,
                                            sizeof(displayString), vp, 0);
        displayBuf.value = (void *)displayString;

        duplicateBuffer(displayBuf, display_value);
    }

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    return true;
}

bool
gss_eap_radius_attr_provider::getFragmentedAttribute(uint16_t attribute,
                                                     uint16_t vendor,
                                                     int *authenticated,
                                                     int *complete,
                                                     gss_buffer_t value) const
{
    OM_uint32 major, minor;

    major = gssEapRadiusGetAvp(&minor, m_vps, attribute, vendor, value, TRUE);

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    return !GSS_ERROR(major);
}

bool
gss_eap_radius_attr_provider::getFragmentedAttribute(uint32_t attrid,
                                                     int *authenticated,
                                                     int *complete,
                                                     gss_buffer_t value) const
{
    return getFragmentedAttribute(ATTRID(attrid), VENDOR(attrid),
                                  authenticated, complete, value);
}

bool
gss_eap_radius_attr_provider::getAttribute(uint16_t attribute,
                                           uint16_t vendor,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{

    return getAttribute(VENDORATTR(attribute, vendor),
                        authenticated, complete,
                        value, display_value, more);
}

gss_any_t
gss_eap_radius_attr_provider::mapToAny(int authenticated,
                                       gss_buffer_t type_id GSSEAP_UNUSED) const
{
    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    return (gss_any_t)copyAvps(m_vps);
}

void
gss_eap_radius_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id GSSEAP_UNUSED,
                                                    gss_any_t input) const
{
    VALUE_PAIR *vp = (VALUE_PAIR *)input;
    pairfree(&vp);
}

bool
gss_eap_radius_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_RADIUS, createAttrContext);

    return true;
}

void
gss_eap_radius_attr_provider::finalize(void)
{
    gss_eap_attr_ctx::unregisterProvider(ATTR_TYPE_RADIUS);
}

gss_eap_attr_provider *
gss_eap_radius_attr_provider::createAttrContext(void)
{
    return new gss_eap_radius_attr_provider;
}

OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   VALUE_PAIR **vps,
                   uint16_t attribute,
                   uint16_t vendor,
                   const gss_buffer_t buffer)
{
    uint32_t attrid = VENDORATTR(vendor, attribute);
    unsigned char *p = (unsigned char *)buffer->value;
    size_t remain = buffer->length;

    do {
        VALUE_PAIR *vp;
        size_t n = remain;

        /*
         * There's an extra byte of padding; RADIUS AVPs can only
         * be 253 octets.
         */
        if (n >= MAX_STRING_LEN)
            n = MAX_STRING_LEN - 1;

        vp = paircreate(attrid, PW_TYPE_OCTETS);
        if (vp == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        memcpy(vp->vp_octets, p, n);
        vp->length = n;

        pairadd(vps, vp);

        p += n;
        remain -= n;
    } while (remain != 0);

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusGetRawAvp(OM_uint32 *minor,
                      VALUE_PAIR *vps,
                      uint16_t attribute,
                      uint16_t vendor,
                      VALUE_PAIR **vp)
{
    uint32_t attr = VENDORATTR(vendor, attribute);

    *vp = pairfind(vps, attr);
    if (*vp == NULL) {
        *minor = GSSEAP_NO_SUCH_ATTR;
        return GSS_S_UNAVAILABLE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   VALUE_PAIR *vps,
                   uint16_t attribute,
                   uint16_t vendor,
                   gss_buffer_t buffer,
                   int concat)
{
    VALUE_PAIR *vp;
    unsigned char *p;
    uint32_t attr = VENDORATTR(vendor, attribute);

    if (buffer != GSS_C_NO_BUFFER) {
        buffer->length = 0;
        buffer->value = NULL;
    }

    vp = pairfind(vps, attr);
    if (vp == NULL) {
        *minor = GSSEAP_NO_SUCH_ATTR;
        return GSS_S_UNAVAILABLE;
    }

    if (buffer != GSS_C_NO_BUFFER) {
        do {
            buffer->length += vp->length;
        } while (concat && (vp = pairfind(vp->next, attr)) != NULL);

        buffer->value = GSSEAP_MALLOC(buffer->length);
        if (buffer->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        p = (unsigned char *)buffer->value;

        for (vp = pairfind(vps, attr);
             concat && vp != NULL;
             vp = pairfind(vp->next, attr)) {
            memcpy(p, vp->vp_octets, vp->length);
            p += vp->length;
        }
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusFreeAvps(OM_uint32 *minor,
                     VALUE_PAIR **vps)
{
    pairfree(vps);
    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusAttrProviderInit(OM_uint32 *minor)
{
    if (!gss_eap_radius_attr_provider::init()) {
        *minor = GSSEAP_RADSEC_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusAttrProviderFinalize(OM_uint32 *minor)
{
    gss_eap_radius_attr_provider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}

static JSONObject
avpToJson(const VALUE_PAIR *vp)
{
    JSONObject obj;

    GSSEAP_ASSERT(vp->length <= MAX_STRING_LEN);

    switch (vp->type) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_IPADDR:
    case PW_TYPE_DATE:
        obj.set("value", vp->lvalue);
        break;
    case PW_TYPE_STRING:
        obj.set("value", vp->vp_strvalue);
        break;
    default: {
        char *b64;

        if (base64Encode(vp->vp_octets, vp->length, &b64) < 0)
            throw std::bad_alloc();

        obj.set("value", b64);
        GSSEAP_FREE(b64);
        break;
    }
    }

    obj.set("type", vp->attribute);

    return obj;
}

static bool
jsonToAvp(VALUE_PAIR **pVp, JSONObject &obj)
{
    VALUE_PAIR *vp = NULL;
    DICT_ATTR *da;
    uint32_t attrid;

    JSONObject type = obj["type"];
    JSONObject value = obj["value"];

    if (!type.isInteger())
        goto fail;

    attrid = type.integer();
    da = dict_attrbyvalue(attrid);
    if (da != NULL) {
        vp = pairalloc(da);
    } else {
        int type = base64Valid(value.string()) ?
            PW_TYPE_OCTETS : PW_TYPE_STRING;
        vp = paircreate(attrid, type);
    }
    if (vp == NULL)
        throw std::bad_alloc();

    switch (vp->type) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_IPADDR:
    case PW_TYPE_DATE:
        if (!value.isInteger())
            goto fail;

        vp->length = 4;
        vp->lvalue = value.integer();
        break;
    case PW_TYPE_STRING: {
        if (!value.isString())
            goto fail;

        const char *str = value.string();
        size_t len = strlen(str);

        if (len >= MAX_STRING_LEN)
            goto fail;

        vp->length = len;
        memcpy(vp->vp_strvalue, str, len + 1);
        break;
    }
    case PW_TYPE_OCTETS:
    default: {
        if (!value.isString())
            goto fail;

        const char *str = value.string();
        ssize_t len = strlen(str);

        /* this optimization requires base64Decode only understand packed encoding */
        if (len >= BASE64_EXPAND(MAX_STRING_LEN))
            goto fail;

        len = base64Decode(str, vp->vp_octets);
        if (len < 0)
            goto fail;

        vp->length = len;
        break;
    }
    }

    *pVp = vp;

    return true;

fail:
    if (vp != NULL)
        pairbasicfree(vp);
    *pVp = NULL;
    return false;
}

const char *
gss_eap_radius_attr_provider::name(void) const
{
    return "radius";
}

bool
gss_eap_radius_attr_provider::initWithJsonObject(const gss_eap_attr_ctx *ctx,
                                                 JSONObject &obj)
{
    VALUE_PAIR **pNext = &m_vps;

    if (!gss_eap_attr_provider::initWithJsonObject(ctx, obj))
        return false;

    JSONObject attrs = obj["attributes"];
    size_t nelems = attrs.size();

    for (size_t i = 0; i < nelems; i++) {
        JSONObject attr = attrs[i];
        VALUE_PAIR *vp;

        if (!jsonToAvp(&vp, attr))
            return false;

        *pNext = vp;
        pNext = &vp->next;
    }

    m_authenticated = obj["authenticated"].integer() ? true : false;

    return true;
}

const char *
gss_eap_radius_attr_provider::prefix(void) const
{
    return "urn:ietf:params:gss-eap:radius-avp";
}

JSONObject
gss_eap_radius_attr_provider::jsonRepresentation(void) const
{
    JSONObject obj, attrs = JSONObject::array();

    for (VALUE_PAIR *vp = m_vps; vp != NULL; vp = vp->next) {
        JSONObject attr = avpToJson(vp);
        attrs.append(attr);
    }

    obj.set("attributes", attrs);

    obj.set("authenticated", m_authenticated);

    return obj;
}

time_t
gss_eap_radius_attr_provider::getExpiryTime(void) const
{
    VALUE_PAIR *vp;

    vp = pairfind(m_vps, PW_SESSION_TIMEOUT);
    if (vp == NULL || vp->lvalue == 0)
        return 0;

    return time(NULL) + vp->lvalue;
}

OM_uint32
gssEapRadiusMapError(OM_uint32 *minor,
                     struct rs_error *err)
{
    int code;

    GSSEAP_ASSERT(err != NULL);

    code = rs_err_code(err, 0);

    if (code == RSE_OK) {
        *minor = 0;
        return GSS_S_COMPLETE;
    }

    *minor = ERROR_TABLE_BASE_rse + code;

    gssEapSaveStatusInfo(*minor, "%s", rs_err_msg(err));
    rs_err_free(err);

    return GSS_S_FAILURE;
}

OM_uint32
gssEapCreateRadiusContext(OM_uint32 *minor,
                          gss_cred_id_t cred,
                          struct rs_context **pRadContext)
{
    const char *configFile = RS_CONFIG_FILE;
    struct rs_context *radContext;
    struct rs_alloc_scheme ralloc;
    struct rs_error *err;
    OM_uint32 major;

    *pRadContext = NULL;

    if (rs_context_create(&radContext) != 0) {
        *minor = GSSEAP_RADSEC_CONTEXT_FAILURE;
        return GSS_S_FAILURE;
    }

    if (cred->radiusConfigFile.value != NULL)
        configFile = (const char *)cred->radiusConfigFile.value;

    ralloc.calloc  = GSSEAP_CALLOC;
    ralloc.malloc  = GSSEAP_MALLOC;
    ralloc.free    = GSSEAP_FREE;
    ralloc.realloc = GSSEAP_REALLOC;

    rs_context_set_alloc_scheme(radContext, &ralloc);

    if (rs_context_read_config(radContext, configFile) != 0) {
        err = rs_err_ctx_pop(radContext);
        goto fail;
    }

    if (rs_context_init_freeradius_dict(radContext, NULL) != 0) {
        err = rs_err_ctx_pop(radContext);
        goto fail;
    }

    *pRadContext = radContext;

    *minor = 0;
    return GSS_S_COMPLETE;

fail:
    major = gssEapRadiusMapError(minor, err);
    rs_context_destroy(radContext);

    return major;
}

#endif /* GSSEAP_ENABLE_ACCEPTOR */

OM_uint32
gssEapRadiusAddAttr(OM_uint32 *minor, struct wpabuf **buf, uint16_t attr,
                    uint16_t vendor, gss_buffer_t buffer)
{
    if (radius_add_tlv(buf, attr, vendor, (u8 *)buffer->value,
                       buffer->length) < 0) {
        *minor = ENOMEM; /* could be length too long, though */
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}
