/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
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
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * BrowserID attribute provider implementation.
 */

#include "gssapiP_bid.h"

#ifdef GSSBID_ENABLE_ACCEPTOR

#define BID_MAP_ERROR(code)  (ERROR_TABLE_BASE_lbid + (code))

BIDGSSJWTAttributeProvider::BIDGSSJWTAttributeProvider(void)
{
    m_attrs = NULL;
}

BIDGSSJWTAttributeProvider::~BIDGSSJWTAttributeProvider(void)
{
    delete m_attrs;
}

bool
BIDGSSJWTAttributeProvider::initWithExistingContext(const BIDGSSAttributeContext *manager,
                                                    const BIDGSSAttributeProvider *ctx)
{
    const BIDGSSJWTAttributeProvider *jwt;

    if (!BIDGSSAttributeProvider::initWithExistingContext(manager, ctx))
        return false;

    jwt = static_cast<const BIDGSSJWTAttributeProvider *>(ctx);

    if (jwt->m_attrs != NULL)
        m_attrs = new JSONObject(*jwt->m_attrs);

    return true;
}

bool
BIDGSSJWTAttributeProvider::initWithGssContext(const BIDGSSAttributeContext *manager,
                                               const gss_cred_id_t gssCred,
                                               const gss_ctx_id_t gssCtx)
{
    if (!BIDGSSAttributeProvider::initWithGssContext(manager, gssCred, gssCtx))
        return false;

    if (gssCtx != GSS_C_NO_CONTEXT) {
        BIDError err;
        json_t *jAttrs = NULL;

        err = BIDGetIdentityJsonObject(gssCtx->bidContext,
                                       gssCtx->bidIdentity,
                                       NULL,
                                       &jAttrs);
        if (err != BID_S_OK || !json_is_object(jAttrs)) {
            json_decref(jAttrs);
            return false;
        }

        m_attrs = new JSONObject(jAttrs, false); /* steal reference */

        BID_ASSERT(m_attrs->isObject());
    }

    return true;
}

static bool
isStringBuffer(const gss_buffer_t value)
{
    size_t i;
    const unsigned char *p = (const unsigned char *)value->value;

    for (i = 0; i < value->length; i++) {
        if (!isprint(p[i]))
            return false;
    }

    return true;
}

bool
BIDGSSJWTAttributeProvider::getAttributeTypes(BIDGSSAttributeIterator addAttribute,
                                              void *data) const
{
    JSONIterator iter = m_attrs->iterator();

    do {
        gss_buffer_desc attribute;

        attribute.value = (void *)iter.key();
        attribute.length = strlen((const char *)attribute.value);

        if (!addAttribute(m_manager, this, &attribute, data))
            return false;
    } while (iter.next());

    return true;
}

bool
BIDGSSJWTAttributeProvider::setAttribute(int complete GSSBID_UNUSED,
                                         const gss_buffer_t attr,
                                         const gss_buffer_t value)
{
    bool isString = isStringBuffer(value);
    char *szValue;
    ssize_t cbBuffer;

    if (isString) {
        szValue = (char *)value->value;
    } else {
        cbBuffer = base64Encode(value->value, value->length, &szValue);
        if (cbBuffer < 0)
            return false;
    }

    m_attrs->set((const char *)attr->value, szValue);

    if (!isString)
        GSSBID_FREE(szValue);

    return true;
}

bool
BIDGSSJWTAttributeProvider::deleteAttribute(const gss_buffer_t attr)
{
    m_attrs->del((const char *)attr->value);
    return true;
}

bool
BIDGSSJWTAttributeProvider::getAttribute(const gss_buffer_t attr,
                                         int *authenticated,
                                         int *complete,
                                         gss_buffer_t value,
                                         gss_buffer_t display_value,
                                         int *more) const
{
    JSONObject jAttr = m_attrs->get(attr);
    gss_buffer_desc valueBuf = GSS_C_EMPTY_BUFFER;
    char tmpBuf[128];
    int nValues, i = *more;
    bool bFreeValue = false, bIsBinary = false;
    char *szValue = NULL;

    *more = 0;

    nValues = jAttr.isArray() ? jAttr.size() : 1;
    if (i == -1)
        i = 0;
    if (i >= nValues)
        return false;

    if (jAttr.isArray())
        jAttr = jAttr.get(i);

    switch (jAttr.type()) {
    case JSON_OBJECT:
    case JSON_ARRAY:
        valueBuf.value = (char *)jAttr.dump();
        bFreeValue = true;
        break;
    case JSON_STRING:
        szValue = (char *)jAttr.string();
        if (base64Valid(szValue) &&
            _BIDBase64UrlDecode(szValue, (unsigned char **)&valueBuf.value, &valueBuf.length) == BID_S_OK)
            bFreeValue = bIsBinary = true;
        else
            valueBuf.value = (void *)szValue;
        break;
    case JSON_INTEGER:
        snprintf(tmpBuf, sizeof(tmpBuf), "%"JSON_INTEGER_FORMAT, jAttr.integer());
        valueBuf.value = (void *)tmpBuf;
        break;
    case JSON_REAL:
        snprintf(tmpBuf, sizeof(tmpBuf), "%.17g", jAttr.real());
        valueBuf.value = (void *)tmpBuf;
    case JSON_TRUE:
    case JSON_FALSE:
        valueBuf.value = (void *)(jAttr.boolean() ? "TRUE" : "FALSE");
        break;
    case JSON_NULL:
        tmpBuf[0] = '\0';
        valueBuf.value = (void *)tmpBuf;
        break;
    }

    if (valueBuf.value != NULL)
        valueBuf.length = strlen((char *)valueBuf.value);

    if (authenticated != NULL)
        *authenticated = true;
    if (complete != NULL)
        *complete = true;
    if (value != NULL)
        duplicateBuffer(valueBuf, value);
    if (display_value != NULL && !bIsBinary)
        duplicateBuffer(valueBuf, display_value);
    if (bFreeValue)
        BIDFree(valueBuf.value);
    if (nValues > ++i)
        *more = i;

    return true;
}

gss_any_t
BIDGSSJWTAttributeProvider::mapToAny(int authenticated GSSBID_UNUSED,
                                     gss_buffer_t type_id GSSBID_UNUSED) const
{
    if (m_attrs == NULL)
        return (gss_any_t)NULL;

    return (gss_any_t)m_attrs->get();
}

void
BIDGSSJWTAttributeProvider::releaseAnyNameMapping(gss_buffer_t type_id GSSBID_UNUSED,
                                                  gss_any_t input) const
{
    json_decref((json_t *)input);
}

bool
BIDGSSJWTAttributeProvider::init(void)
{
    BIDGSSAttributeContext::registerProvider(ATTR_TYPE_JWT, createAttrContext);

    return true;
}

void
BIDGSSJWTAttributeProvider::finalize(void)
{
    BIDGSSAttributeContext::unregisterProvider(ATTR_TYPE_JWT);
}

BIDGSSAttributeProvider *
BIDGSSJWTAttributeProvider::createAttrContext(void)
{
    return new BIDGSSJWTAttributeProvider;
}

OM_uint32
gssBidJwtAttrProviderInit(OM_uint32 *minor)
{
    if (!BIDGSSJWTAttributeProvider::init())
        return GSS_S_FAILURE;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssBidJwtAttrProviderFinalize(OM_uint32 *minor)
{
    BIDGSSJWTAttributeProvider::finalize();

    *minor = 0;
    return GSS_S_COMPLETE;
}

const char *
BIDGSSJWTAttributeProvider::name(void) const
{
    return "jwt";
}

bool
BIDGSSJWTAttributeProvider::initWithJsonObject(const BIDGSSAttributeContext *ctx,
                                               JSONObject &obj)
{
    if (!BIDGSSAttributeProvider::initWithJsonObject(ctx, obj))
        return false;

    m_attrs = new JSONObject(obj);

    return true;
}

const char *
BIDGSSJWTAttributeProvider::prefix(void) const
{
    return "urn:ietf:params:gss:jwt";
}

JSONObject
BIDGSSJWTAttributeProvider::jsonRepresentation(void) const
{
    return JSONObject(*m_attrs);
}

time_t
BIDGSSJWTAttributeProvider::getExpiryTime(void) const
{
    return (*m_attrs)["exp"].integer() / 1000;
}

#endif /* GSSBID_ENABLE_ACCEPTOR */

OM_uint32
gssBidApiToWireError(OM_uint32 minor)
{
    if (minor >= ERROR_TABLE_BASE_bidg && minor <= GSSBID_BAD_INVOCATION) {
        minor -= ERROR_TABLE_BASE_bidg;
        minor |= GSSBID_GSS_WIRE_ERROR;
    } else if (IS_BROWSERID_ERROR(minor)) {
        minor -= (OM_uint32)ERROR_TABLE_BASE_lbid;
    } else {
        minor = 0;
    }

    return minor;
}

OM_uint32
gssBidWireToApiError(OM_uint32 minor)
{
    if (minor & GSSBID_GSS_WIRE_ERROR) {
        minor &= ~(GSSBID_GSS_WIRE_ERROR);
        minor += ERROR_TABLE_BASE_bidg;

        if (minor > GSSBID_BAD_INVOCATION)
            minor = 0; /* unknown */
    } else if (minor != 0 && minor <= BID_S_UNKNOWN_ERROR_CODE) {
        minor += (OM_uint32)ERROR_TABLE_BASE_lbid;
    } else {
        minor = 0;
    }

    return minor;
}

OM_uint32
gssBidMapError(OM_uint32 *minor, BIDError err)
{
    OM_uint32 major;
    const char *msg;

    *minor = 0;

    switch (err) {
    case BID_S_OK:
        major = GSS_S_COMPLETE;
        *minor = 0;
        break;
    case BID_S_NO_MEMORY:
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        break;
    case BID_S_BAD_AUDIENCE:
    case BID_S_MISSING_PRINCIPAL:
    case BID_S_UNKNOWN_PRINCIPAL_TYPE:
        major = GSS_S_BAD_NAME;
        break;
    case BID_S_INTERACT_UNAVAILABLE:
    case BID_S_INTERACT_FAILURE:
    case BID_S_INTERACT_REQUIRED:
        major = GSS_S_CRED_UNAVAIL;
        *minor = GSSBID_NO_DEFAULT_CRED;
        break;
    case BID_S_INVALID_JSON:
    case BID_S_INVALID_BASE64:
    case BID_S_INVALID_ASSERTION:
    case BID_S_MISSING_ALGORITHM:
    case BID_S_TOO_MANY_CERTS:
    case BID_S_UNTRUSTED_ISSUER:
    case BID_S_INVALID_ISSUER:
    case BID_S_MISSING_ISSUER:
    case BID_S_MISSING_AUDIENCE:
        major = GSS_S_DEFECTIVE_TOKEN;
        break;
    case BID_S_EXPIRED_ASSERTION:
    case BID_S_EXPIRED_CERT:
        major = GSS_S_CREDENTIALS_EXPIRED;
        break;
    case BID_S_MISSING_CHANNEL_BINDINGS:
    case BID_S_CHANNEL_BINDINGS_MISMATCH:
        major = GSS_S_BAD_BINDINGS;
        break;
    case BID_S_UNKNOWN_ERROR_CODE:
        major = GSS_S_BAD_STATUS;
        break;
    case BID_S_INVALID_SIGNATURE:
        major = GSS_S_BAD_SIG;
        break;
    case BID_S_UNAVAILABLE:
    case BID_S_NOT_IMPLEMENTED:
        major = GSS_S_UNAVAILABLE;
        break;
    case BID_S_NO_CONTEXT:
    case BID_S_INVALID_PARAMETER:
    case BID_S_INVALID_USAGE:
    case BID_S_UNKNOWN_JSON_KEY:
    case BID_S_CANNOT_ENCODE_JSON:
    case BID_S_CANNOT_ENCODE_BASE64:
    case BID_S_UNKNOWN_ALGORITHM:
    case BID_S_INVALID_KEY:
    case BID_S_INVALID_KEYSET:
    case BID_S_NO_KEY:
    case BID_S_CRYPTO_ERROR:
    case BID_S_HTTP_ERROR:
    case BID_S_BUFFER_TOO_SMALL:
    case BID_S_BUFFER_TOO_LONG:
    case BID_S_REMOTE_VERIFY_FAILURE:
    case BID_S_MISSING_CERT:
    case BID_S_UNKNOWN_ATTRIBUTE:
    case BID_S_NO_SESSION_KEY:
    case BID_S_DOCUMENT_NOT_MODIFIED:
    case BID_S_INVALID_AUDIENCE_URN:
    default:
        major = GSS_S_FAILURE;
        break;
    }

    if (GSS_ERROR(major)) {
        if (*minor == 0)
            *minor = BID_MAP_ERROR(err);
        BIDErrorToString(err, &msg);
        gssBidSaveStatusInfo(*minor, "BrowserID: %s", msg);
    }

    return major;
}
