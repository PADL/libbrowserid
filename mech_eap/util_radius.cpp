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

#define RS_MAP_ERROR(code)  (ERROR_TABLE_BASE_rse + (code))

static rs_avp *copyAvps(rs_const_avp *src);

static OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   rs_avp *vps,
                   const gss_eap_attrid &attrid,
                   gss_buffer_t buffer,
                   int concat);

static OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   rs_avp **vps,
                   const gss_eap_attrid &attrid,
                   const gss_buffer_t buffer);

static gss_eap_attrid
avpToAttrId(rs_const_avp *vp)
{
    gss_eap_attrid attrid;

    rs_avp_attrid(vp, &attrid.second, &attrid.first);

    return attrid;
}

gss_eap_radius_attr_provider::gss_eap_radius_attr_provider(void)
{
    m_vps = NULL;
    m_authenticated = false;
}

gss_eap_radius_attr_provider::~gss_eap_radius_attr_provider(void)
{
    if (m_vps != NULL)
        rs_avp_free(&m_vps);
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
        m_vps = copyAvps(radius->getAvps());

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
            GSSEAP_ASSERT(rs_avp_find(m_vps, PW_MESSAGE_AUTHENTICATOR, 0) != NULL);
            m_authenticated = true;
        }
    }

    return true;
}

static bool
alreadyAddedAttributeP(std::vector <gss_eap_attrid> &attrs,
                       gss_eap_attrid &attrid)
{
    for (std::vector<gss_eap_attrid>::const_iterator a = attrs.begin();
         a != attrs.end();
         ++a) {
        if (attrid.first == (*a).first &&
            attrid.second == (*a).second)
            return true;
    }

    return false;
}

static bool
isSecretAttributeP(const gss_eap_attrid &attrid)
{
    bool bSecretAttribute = false;

    switch (attrid.first) {
    case VENDORPEC_MICROSOFT:
        switch (attrid.second) {
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
isSecretAttributeP(rs_const_avp *vp)
{
    return isSecretAttributeP(avpToAttrId(vp));
}

static bool
isInternalAttributeP(const gss_eap_attrid &attrid)
{
    bool bInternalAttribute = false;

    /* should have been filtered */
    GSSEAP_ASSERT(!isSecretAttributeP(attrid));

    switch (attrid.first) {
    case VENDORPEC_UKERNA:
        switch (attrid.second) {
        case PW_SAML_AAA_ASSERTION:
            bInternalAttribute = true;
            break;
        default:
            break;
        }
        break;
    case 0:
	switch (attrid.second) {
	            case PW_GSS_ACCEPTOR_SERVICE_NAME:
        case PW_GSS_ACCEPTOR_HOST_NAME:
        case PW_GSS_ACCEPTOR_SERVICE_SPECIFICS:
        case PW_GSS_ACCEPTOR_REALM_NAME:
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
isInternalAttributeP(rs_const_avp *vp)
{
    return isInternalAttributeP(avpToAttrId(vp));
}

static bool
isFragmentedAttributeP(const gss_eap_attrid &attrid)
{
    /* A bit of a hack for the PAC for now. Should be configurable. */
    return (attrid.first == VENDORPEC_UKERNA) &&
        !isInternalAttributeP(attrid);
}

/*
 * Copy AVP list, same as paircopy except it filters out attributes
 * containing keys.
 */
static rs_avp *
copyAvps(rs_const_avp *src)
{
    rs_const_avp *vp;
    rs_avp *dst = NULL;

    for (vp = src; vp != NULL; vp = rs_avp_next_const(vp)) {
        rs_avp *vpcopy;

        if (isSecretAttributeP(vp))
            continue;

        vpcopy = rs_avp_dup(vp);
        if (vpcopy == NULL) {
            rs_avp_free(&dst);
            throw std::bad_alloc();
        }

        rs_avp_append(&dst, vpcopy);
     }

    return dst;
}

bool
gss_eap_radius_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute,
                                                void *data) const
{
    rs_avp *vp;
    std::vector <gss_eap_attrid> seen;

    for (vp = m_vps; vp != NULL; vp = rs_avp_next(vp)) {
        gss_buffer_desc desc;
        gss_eap_attrid attrid;
        char buf[64];

        /* Don't advertise attributes that are internal to the GSS-EAP mechanism */
        if (isInternalAttributeP(vp))
            continue;

        rs_avp_attrid(vp, &attrid.second, &attrid.first);

        if (alreadyAddedAttributeP(seen, attrid))
            continue;

        if (rs_attr_display_name(attrid.second, attrid.first,
                                 buf, sizeof(buf), TRUE) != RSE_OK ||
            strncmp(buf, "Attr-", 5) != 0)
            continue;

        desc.value = &buf[5];
        desc.length = strlen((char *)desc.value);

        if (!addAttribute(m_manager, this, &desc, data))
            return false;

        seen.push_back(attrid);
    }

    return true;
}

static bool
getAttributeId(const gss_buffer_t desc,
               gss_eap_attrid *attrid)
{
    char *strAttr, *s;
    int canon, code;

    if (desc->length == 0)
        return false;

    canon = isdigit(*(char *)desc->value);

    /* need to duplicate because attr may not be NUL terminated */
    strAttr = (char *)GSSEAP_MALLOC((canon ? 5 : 0) + desc->length + 1);
    if (strAttr == NULL)
        throw new std::bad_alloc();

    s = strAttr;

    if (canon) {
        memcpy(s, "Attr-", 5);
        s += 5;
    }

    memcpy(s, desc->value, desc->length);
    s += desc->length;
    *s = '\0';

    code = rs_attr_parse_name(strAttr, &attrid->second, &attrid->first);

    GSSEAP_FREE(strAttr);

    return (code == RSE_OK);
}

bool
gss_eap_radius_attr_provider::setAttribute(int complete GSSEAP_UNUSED,
                                           const gss_eap_attrid &attrid,
                                           const gss_buffer_t value)
{
    OM_uint32 major = GSS_S_UNAVAILABLE, minor;

    if (!isSecretAttributeP(attrid) &&
        !isInternalAttributeP(attrid)) {
        deleteAttribute(attrid);

        major = gssEapRadiusAddAvp(&minor, &m_vps, attrid, value);
    }

    return !GSS_ERROR(major);
}

bool
gss_eap_radius_attr_provider::setAttribute(int complete,
                                           const gss_buffer_t attr,
                                           const gss_buffer_t value)
{
    gss_eap_attrid attrid;

    if (!getAttributeId(attr, &attrid))
        return false;

    return setAttribute(complete, attrid, value);
}

bool
gss_eap_radius_attr_provider::deleteAttribute(const gss_eap_attrid &attrid)
{
    if (isSecretAttributeP(attrid) ||
        isInternalAttributeP(attrid) ||
        rs_avp_find(m_vps, attrid.second, attrid.first) == NULL)
        return false;

    return (rs_avp_delete(&m_vps, attrid.second, attrid.first) == RSE_OK);
}

bool
gss_eap_radius_attr_provider::deleteAttribute(const gss_buffer_t attr)
{
    gss_eap_attrid attrid;

    if (!getAttributeId(attr, &attrid))
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
    gss_eap_attrid attrid;

    if (!getAttributeId(attr, &attrid))
        return false;

    return getAttribute(attrid,
                        authenticated, complete,
                        value, display_value, more);
}

bool
gss_eap_radius_attr_provider::getAttribute(const gss_eap_attrid &attrid,
                                           int *authenticated,
                                           int *complete,
                                           gss_buffer_t value,
                                           gss_buffer_t display_value,
                                           int *more) const
{
    rs_const_avp *vp;
    int i = *more, count = 0;

    *more = 0;

    if (i == -1)
        i = 0;

    if (isSecretAttributeP(attrid) ||
        isInternalAttributeP(attrid)) {
        return false;
    } else if (isFragmentedAttributeP(attrid)) {
        return getFragmentedAttribute(attrid,
                                      authenticated,
                                      complete,
                                      value);
    }

    for (vp = rs_avp_find_const(m_vps, attrid.second, attrid.first);
         vp != NULL;
         vp = rs_avp_find_const(rs_avp_next_const(vp), attrid.second, attrid.first)) {
        if (count++ == i) {
            if (rs_avp_find_const(rs_avp_next_const(vp), attrid.second, attrid.first) != NULL)
                *more = count;
            break;
        }
    }

    if (vp == NULL && *more == 0)
        return false;

    if (value != GSS_C_NO_BUFFER) {
        gss_buffer_desc valueBuf;

        rs_avp_octets_value_byref((rs_avp *)vp,
                                  (unsigned char **)&valueBuf.value,
                                  &valueBuf.length);

        duplicateBuffer(valueBuf, value);
    }

    if (display_value != GSS_C_NO_BUFFER &&
        !rs_avp_is_octets(vp)) {
        char displayString[RS_MAX_STRING_LEN];
        gss_buffer_desc displayBuf;

        displayBuf.length = rs_avp_display_value(vp, displayString,
                                                 sizeof(displayString));
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
gss_eap_radius_attr_provider::getFragmentedAttribute(const gss_eap_attrid &attrid,
                                                     int *authenticated,
                                                     int *complete,
                                                     gss_buffer_t value) const
{
    OM_uint32 major, minor;

    major = gssEapRadiusGetAvp(&minor, m_vps, attrid, value, TRUE);

    if (authenticated != NULL)
        *authenticated = m_authenticated;
    if (complete != NULL)
        *complete = true;

    return !GSS_ERROR(major);
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
    rs_avp *vp = (rs_avp *)input;
    rs_avp_free(&vp);
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

static OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   rs_avp **vps,
                   const gss_eap_attrid &attrid,
                   const gss_buffer_t buffer)
{
    unsigned char *p = (unsigned char *)buffer->value;
    size_t remain = buffer->length;

    do {
        rs_avp *vp;
        size_t n = remain;

        /*
         * There's an extra byte of padding; RADIUS AVPs can only
         * be 253 octets.
         */
        if (n >= RS_MAX_STRING_LEN)
            n = RS_MAX_STRING_LEN - 1;

        vp = rs_avp_alloc(attrid.second, attrid.first);
        if (vp == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        rs_avp_octets_set(vp, p, n);

        rs_avp_append(vps, vp);

        p += n;
        remain -= n;
    } while (remain != 0);

    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   struct rs_packet *pkt,
                   unsigned int attribute,
                   unsigned int vendor,
                   const gss_buffer_t buffer)
{
    gss_eap_attrid attrid(vendor, attribute);
    int code;

    code = rs_packet_append_avp(pkt, attrid.second, attrid.first,
                                buffer->value, buffer->length);
    if (code != RSE_OK) {
        *minor = RS_MAP_ERROR(code);
        return GSS_S_FAILURE;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusGetRawAvp(OM_uint32 *minor,
                      rs_const_avp *vps,
                      unsigned int attribute,
                      unsigned int vendor,
                      rs_const_avp **vp)
{
    *vp = rs_avp_find_const(vps, attribute, vendor);
    if (*vp == NULL) {
        *minor = GSSEAP_NO_SUCH_ATTR;
        return GSS_S_UNAVAILABLE;
    }

    return GSS_S_COMPLETE;
}

static OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   rs_avp *vps,
                   const gss_eap_attrid &attrid,
                   gss_buffer_t buffer,
                   int concat)
{
    rs_const_avp *vp;
    int err;

    if (buffer != GSS_C_NO_BUFFER) {
        buffer->length = 0;
        buffer->value = NULL;
    }

    vp = rs_avp_find_const(vps, attrid.second, attrid.first);
    if (vp == NULL) {
        *minor = GSSEAP_NO_SUCH_ATTR;
        return GSS_S_UNAVAILABLE;
    }

    if (buffer != GSS_C_NO_BUFFER) {
        if (concat)
            rs_avp_fragmented_value(vp, NULL, &buffer->length);
        else
            buffer->length = rs_avp_length(vp);

        buffer->value = GSSEAP_MALLOC(buffer->length);
        if (buffer->value == NULL) {
            *minor = ENOMEM;
            return GSS_S_FAILURE;
        }

        if (concat)
            err = rs_avp_fragmented_value(vp, (unsigned char *)buffer->value, &buffer->length);
        else
            err = rs_avp_octets_value(vp, (unsigned char *)buffer->value, &buffer->length);

        if (err != 0) {
            *minor = RS_MAP_ERROR(err);
            return GSS_S_FAILURE;
        }
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   struct rs_packet *pkt,
                   unsigned int attribute,
                   unsigned int vendor,
                   gss_buffer_t buffer,
                   int concat)
{
    rs_avp **vps;
    gss_eap_attrid attrid(vendor, attribute);

    rs_packet_avps(pkt, &vps);

    return gssEapRadiusGetAvp(minor, *vps, attrid, buffer, concat);
}

OM_uint32
gssEapRadiusFreeAvps(OM_uint32 *minor,
                     rs_avp **vps)
{
    rs_avp_free(vps);
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
avpToJson(rs_const_avp *vp)
{
    JSONObject obj;
    gss_eap_attrid attrid;

    GSSEAP_ASSERT(rs_avp_length(vp) <= RS_MAX_STRING_LEN);

    switch (rs_avp_typeof(vp)) {
    case RS_TYPE_INTEGER:
        obj.set("value", rs_avp_integer_value(vp));
        break;
    case RS_TYPE_DATE:
        obj.set("value", rs_avp_date_value(vp));
        break;
    case RS_TYPE_STRING:
        obj.set("value", rs_avp_string_value(vp));
        break;
    default: {
        char *b64;

        if (base64Encode(rs_avp_octets_value_const_ptr(vp),
                         rs_avp_length(vp), &b64) < 0)
            throw std::bad_alloc();

        obj.set("value", b64);
        GSSEAP_FREE(b64);
        break;
    }
    }

    attrid = avpToAttrId(vp);

    obj.set("type", attrid.second);
    if (attrid.first != 0)
        obj.set("vendor", attrid.first);

    return obj;
}

static bool
jsonToAvp(rs_avp **pVp, JSONObject &obj)
{
    rs_avp *vp = NULL;
    gss_eap_attrid attrid;

    JSONObject type = obj["type"];
    JSONObject vendor = obj["vendor"];
    JSONObject value = obj["value"];

    if (!type.isInteger())
        goto fail;
    attrid.second = type.integer();

    if (!vendor.isNull()) {
        if (!vendor.isInteger())
            goto fail;
        attrid.first = vendor.integer();
    } else {
        attrid.first = 0;
    }

    vp = rs_avp_alloc(attrid.second, attrid.first);
    if (vp == NULL)
        throw std::bad_alloc();

    switch (rs_avp_typeof(vp)) {
    case RS_TYPE_INTEGER:
    case RS_TYPE_IPADDR:
    case RS_TYPE_DATE:
        if (!value.isInteger())
            goto fail;

        if (rs_avp_integer_set(vp, value.integer()) != RSE_OK)
            goto fail;

        break;
    case RS_TYPE_STRING: {
        if (!value.isString())
            goto fail;

        if (rs_avp_string_set(vp, value.string()) != RSE_OK)
            goto fail;

        break;
    }
    case RS_TYPE_OCTETS:
    default: {
        unsigned char buf[RS_MAX_STRING_LEN];

        if (!value.isString())
            goto fail;

        const char *str = value.string();
        ssize_t len = strlen(str);

        /* this optimization requires base64Decode only understand packed encoding */
        if (len >= BASE64_EXPAND(RS_MAX_STRING_LEN))
            goto fail;

        len = base64Decode(str, buf);
        if (len < 0)
            goto fail;

        if (rs_avp_octets_set(vp, buf, len) != RSE_OK)
            goto fail;

        break;
    }
    }

    *pVp = vp;

    return true;

fail:
    if (vp != NULL)
        rs_avp_free(&vp);
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
    if (!gss_eap_attr_provider::initWithJsonObject(ctx, obj))
        return false;

    JSONObject attrs = obj["attributes"];
    size_t nelems = attrs.size();

    for (size_t i = 0; i < nelems; i++) {
        JSONObject attr = attrs[i];
        rs_avp *vp;

        if (!jsonToAvp(&vp, attr))
            return false;

        rs_avp_append(&m_vps, vp);
    }

    m_authenticated = obj["authenticated"].integer() ? true : false;

    return true;
}

const char *
gss_eap_radius_attr_provider::prefix(void) const
{
    return "urn:ietf:params:gss:radius-attribute";
}

JSONObject
gss_eap_radius_attr_provider::jsonRepresentation(void) const
{
    JSONObject obj, attrs = JSONObject::array();

    for (rs_avp *vp = m_vps; vp != NULL; vp = rs_avp_next(vp)) {
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
    rs_const_avp *vp;
    uint32_t value;

    vp = rs_avp_find(m_vps, PW_SESSION_TIMEOUT, 0);
    if (vp == NULL)
        return 0;

    value = rs_avp_integer_value(vp);
    if (value == 0)
        return 0;

    return time(NULL) + value;
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

    *minor = RS_MAP_ERROR(code);

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

    *pRadContext = radContext;

    *minor = 0;
    return GSS_S_COMPLETE;

fail:
    major = gssEapRadiusMapError(minor, err);
    rs_context_destroy(radContext);

    return major;
}
