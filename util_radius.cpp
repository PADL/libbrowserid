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
gss_eap_radius_attr_provider::initFromExistingContext(const gss_eap_attr_ctx *manager,
                                                      const gss_eap_attr_provider *ctx)
{
    const gss_eap_radius_attr_provider *radius;

    if (!gss_eap_attr_provider::initFromExistingContext(manager, ctx))
        return false;

    radius = static_cast<const gss_eap_radius_attr_provider *>(ctx);

    if (radius->m_vps != NULL)
        m_vps = copyAvps(const_cast<VALUE_PAIR *>(radius->getAvps()));

    m_authenticated = radius->m_authenticated;

    return true;
}

bool
gss_eap_radius_attr_provider::initFromGssContext(const gss_eap_attr_ctx *manager,
                                                 const gss_cred_id_t gssCred,
                                                 const gss_ctx_id_t gssCtx)
{
    if (!gss_eap_attr_provider::initFromGssContext(manager, gssCred, gssCtx))
        return false;

    if (gssCtx != GSS_C_NO_CONTEXT) {
        if (gssCtx->acceptorCtx.vps != NULL) {
            m_vps = copyAvps(gssCtx->acceptorCtx.vps);
            if (m_vps == NULL)
                return false;

            /* We assume libradsec validated this for us */
            assert(pairfind(m_vps, PW_MESSAGE_AUTHENTICATOR) != NULL);
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
    bool ret = false;

    switch (vendor) {
    case VENDORPEC_MS:
        switch (attrid) {
        case PW_MS_MPPE_SEND_KEY:
        case PW_MS_MPPE_RECV_KEY:
            ret = true;
            break;
        default:
            break;
        }
    default:
        break;
    }

    return ret;
}

static bool
isSecretAttributeP(uint32_t attribute)
{
    return isSecretAttributeP(ATTRID(attribute), VENDOR(attribute));
}

static bool
isHiddenAttributeP(uint16_t attrid, uint16_t vendor)
{
    bool ret = false;

    /* should have been filtered */
    assert(!isSecretAttributeP(attrid, vendor));

    switch (vendor) {
    case VENDORPEC_UKERNA:
        ret = true;
        break;
    default:
        break;
    }

    return ret;
}

static bool
isHiddenAttributeP(uint32_t attribute)
{
    return isHiddenAttributeP(ATTRID(attribute), VENDOR(attribute));
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
            throw new std::bad_alloc;
            return NULL;
        }
        *pDst = vpcopy;
        pDst = &vpcopy->next;
     }

    return dst;
}

bool
gss_eap_radius_attr_provider::getAttributeTypes(gss_eap_attr_enumeration_cb addAttribute, void *data) const
{
    VALUE_PAIR *vp;
    std::vector <std::string> seen;

    for (vp = m_vps; vp != NULL; vp = vp->next) {
        gss_buffer_desc attribute;
        char attrid[64];

        if (isHiddenAttributeP(vp->attribute))
            continue;

        if (alreadyAddedAttributeP(seen, vp))
            continue;

        snprintf(attrid, sizeof(attrid), "%s%d",
            (char *)radiusUrnPrefix.value, vp->attribute);

        attribute.value = attrid;
        attribute.length = strlen(attrid);

        if (!addAttribute(this, &attribute, data))
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
gss_eap_radius_attr_provider::setAttribute(int complete,
                                           uint32_t attrid,
                                           const gss_buffer_t value)
{
    OM_uint32 major = GSS_S_UNAVAILABLE, minor;

    if (!isSecretAttributeP(attrid) &&
        !isHiddenAttributeP(attrid)) {
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
    if (isSecretAttributeP(attrid) || isHiddenAttributeP(attrid) ||
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

    if (isHiddenAttributeP(attrid))
        return false;

    if (i == -1)
        i = 0;

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

    if (display_value != GSS_C_NO_BUFFER) {
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
                                       gss_buffer_t type_id) const
{
    if (authenticated && !m_authenticated)
        return (gss_any_t)NULL;

    return (gss_any_t)copyAvps(m_vps);
}

void
gss_eap_radius_attr_provider::releaseAnyNameMapping(gss_buffer_t type_id,
                                                    gss_any_t input) const
{
    pairfree((VALUE_PAIR **)&input);
}

bool
gss_eap_radius_attr_provider::init(void)
{
    gss_eap_attr_ctx::registerProvider(ATTR_TYPE_RADIUS,
                                       "urn:ietf:params:gss-eap:radius-avp",
                                       gss_eap_radius_attr_provider::createAttrContext);
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

        if (n > MAX_STRING_LEN)
            n = MAX_STRING_LEN;

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

    return (*vp == NULL) ? GSS_S_UNAVAILABLE : GSS_S_COMPLETE;
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

    buffer->length = 0;
    buffer->value = NULL;

    vp = pairfind(vps, attr);
    if (vp == NULL)
        return GSS_S_UNAVAILABLE;

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
    return GSS_S_COMPLETE;
}

/*
 * Encoding is:
 * 4 octet NBO attribute ID | 4 octet attribute length | attribute data
 */
static size_t
avpSize(const VALUE_PAIR *vp)
{
    size_t size = 4 + 1;

    if (vp != NULL)
        size += vp->length;

    return size;
}

static bool
avpExport(const VALUE_PAIR *vp,
          unsigned char **pBuffer,
          size_t *pRemain)
{
    unsigned char *p = *pBuffer;
    size_t remain = *pRemain;

    assert(remain >= avpSize(vp));

    store_uint32_be(vp->attribute, p);

    switch (vp->type) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_IPADDR:
    case PW_TYPE_DATE:
        p[4] = 4;
        store_uint32_be(vp->lvalue, p + 5);
        break;
    default:
        assert(vp->length <= MAX_STRING_LEN);
        p[4] = (uint8_t)vp->length;
        memcpy(p + 5, vp->vp_octets, vp->length);
        break;
    }

    *pBuffer += 5 + p[4];
    *pRemain -= 5 + p[4];

    return true;

}

static bool
avpImport(VALUE_PAIR **pVp,
          unsigned char **pBuffer,
          size_t *pRemain)
{
    unsigned char *p = *pBuffer;
    size_t remain = *pRemain;
    VALUE_PAIR *vp = NULL;
    DICT_ATTR *da;
    uint32_t attrid;

    if (remain < avpSize(NULL))
        goto fail;

    attrid = load_uint32_be(p);
    p += 4;
    remain -= 4;

    da = dict_attrbyvalue(attrid);
    if (da == NULL)
        goto fail;

    vp = pairalloc(da);
    if (vp == NULL) {
        throw new std::bad_alloc;
        goto fail;
    }

    if (remain < p[0])
        goto fail;

    switch (vp->type) {
    case PW_TYPE_INTEGER:
    case PW_TYPE_IPADDR:
    case PW_TYPE_DATE:
        if (p[0] != 4)
            goto fail;

        vp->length = 4;
        vp->lvalue = load_uint32_be(p + 1);
        p += 5;
        remain -= 5;
        break;
    case PW_TYPE_STRING:
        /* check enough room to NUL terminate */
        if (p[0] == MAX_STRING_LEN)
            goto fail;
        else
        /* fallthrough */
    default:
        if (p[0] > MAX_STRING_LEN)
            goto fail;

        vp->length = (uint32_t)p[0];
        memcpy(vp->vp_octets, p + 1, vp->length);

        if (vp->type == PW_TYPE_STRING)
            vp->vp_strvalue[vp->length] = '\0';

        p += 1 + vp->length;
        remain -= 1 + vp->length;
        break;
    }

    *pVp = vp;
    *pBuffer = p;
    *pRemain = remain;

    return true;

fail:
    pairbasicfree(vp);
    return false;
}

bool
gss_eap_radius_attr_provider::initFromBuffer(const gss_eap_attr_ctx *ctx,
                                             const gss_buffer_t buffer)
{
    unsigned char *p = (unsigned char *)buffer->value;
    size_t remain = buffer->length;
    VALUE_PAIR **pNext = &m_vps;

    if (!gss_eap_attr_provider::initFromBuffer(ctx, buffer))
        return false;

    do {
        VALUE_PAIR *attr;

        if (!avpImport(&attr, &p, &remain))
            return false;

        *pNext = attr;
        pNext = &attr->next;
    } while (remain != 0);

    return true;
}

void
gss_eap_radius_attr_provider::exportToBuffer(gss_buffer_t buffer) const
{
    VALUE_PAIR *vp;
    unsigned char *p;
    size_t remain = 0;

    for (vp = m_vps; vp != NULL; vp = vp->next) {
        remain += avpSize(vp);
    }

    buffer->value = GSSEAP_MALLOC(remain);
    if (buffer->value == NULL) {
        throw new std::bad_alloc;
        return;
    }
    buffer->length = remain;

    p = (unsigned char *)buffer->value;

    for (vp = m_vps; vp != NULL; vp = vp->next) {
        avpExport(vp, &p, &remain);
    }

    assert(remain == 0);
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

    assert(err != NULL);

    code = rs_err_code(err, 0);

    if (code == RSE_OK) {
        *minor = 0;
        return GSS_S_COMPLETE;
    }

    *minor = ERROR_TABLE_BASE_rse + code;

    gssEapSaveStatusInfo(*minor, "%s", rs_err_msg(err, 0));
    rs_err_free(err);

    return GSS_S_FAILURE;
}
