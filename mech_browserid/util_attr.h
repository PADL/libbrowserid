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
 * Attribute provider interface.
 */

#ifndef _UTIL_ATTR_H_
#define _UTIL_ATTR_H_ 1

#ifdef __cplusplus
#include <string>
#include <new>

using namespace gss_bid_util;

struct gss_bid_attr_provider;
struct gss_bid_attr_ctx;

typedef bool
(*gss_bid_attr_enumeration_cb)(const gss_bid_attr_ctx *ctx,
                               const gss_bid_attr_provider *source,
                               const gss_buffer_t attribute,
                               void *data);

#define ATTR_TYPE_JWT               0U                  /* JSON web token */
#ifdef HAVE_OPENSAML
#define ATTR_TYPE_SAML_ASSERTION    1U                  /* SAML assertion */
#define ATTR_TYPE_SAML              2U                  /* SAML attributes */
#endif
#define ATTR_TYPE_LOCAL             3U                  /* Local attributes */
#define ATTR_TYPE_MIN               ATTR_TYPE_JWT
#define ATTR_TYPE_MAX               ATTR_TYPE_LOCAL

#define ATTR_FLAG_DISABLE_LOCAL     0x00000001

/*
 * Attribute provider: this represents a source of attributes derived
 * from the security context.
 */
struct gss_bid_attr_provider
{
public:
    gss_bid_attr_provider(void) {}
    virtual ~gss_bid_attr_provider(void) {}

    bool initWithManager(const gss_bid_attr_ctx *manager)
    {
        m_manager = manager;
        return true;
    }

    virtual bool initWithExistingContext(const gss_bid_attr_ctx *manager,
                                         const gss_bid_attr_provider *ctx GSSBID_UNUSED)
    {
        return initWithManager(manager);
    }

    virtual bool initWithGssContext(const gss_bid_attr_ctx *manager,
                                    const gss_cred_id_t cred GSSBID_UNUSED,
                                    const gss_ctx_id_t ctx GSSBID_UNUSED)
    {
        return initWithManager(manager);
    }

    virtual bool getAttributeTypes(gss_bid_attr_enumeration_cb GSSBID_UNUSED,
                                   void *data GSSBID_UNUSED) const
    {
        return false;
    }

    virtual bool setAttribute(int complete GSSBID_UNUSED,
                              const gss_buffer_t attr GSSBID_UNUSED,
                              const gss_buffer_t value GSSBID_UNUSED)
    {
        return false;
    }

    virtual bool deleteAttribute(const gss_buffer_t value GSSBID_UNUSED)
    {
        return false;
    }

    virtual bool getAttribute(const gss_buffer_t attr GSSBID_UNUSED,
                              int *authenticated GSSBID_UNUSED,
                              int *complete GSSBID_UNUSED,
                              gss_buffer_t value GSSBID_UNUSED,
                              gss_buffer_t display_value GSSBID_UNUSED,
                              int *more GSSBID_UNUSED) const
    {
        return false;
    }

    virtual gss_any_t mapToAny(int authenticated GSSBID_UNUSED,
                               gss_buffer_t type_id GSSBID_UNUSED) const
    {
        return NULL;
    }

    virtual void releaseAnyNameMapping(gss_buffer_t type_id GSSBID_UNUSED,
                                       gss_any_t input GSSBID_UNUSED) const
    {
    }

    /* prefix to be prepended to attributes emitted by gss_get_name_attribute */
    virtual const char *prefix(void) const
    {
        return NULL;
    }

    /* optional key for storing JSON dictionary */
    virtual const char *name(void) const
    {
        return NULL;
    }

    virtual bool initWithJsonObject(const gss_bid_attr_ctx *manager,
                                    JSONObject &object GSSBID_UNUSED)
    {
        return initWithManager(manager);
    }


    virtual JSONObject jsonRepresentation(void) const
    {
        return JSONObject::null();
    }

    virtual time_t getExpiryTime(void) const { return 0; }

    virtual OM_uint32 mapException(OM_uint32 *minor GSSBID_UNUSED,
                                   std::exception &e GSSBID_UNUSED) const
    {
        return GSS_S_CONTINUE_NEEDED;
    }

    static bool init(void) { return true; }
    static void finalize(void) {}

    static gss_bid_attr_provider *createAttrContext(void) { return NULL; }

protected:
    const gss_bid_attr_ctx *m_manager;

private:
    /* make non-copyable */
    gss_bid_attr_provider(const gss_bid_attr_provider&);
    gss_bid_attr_provider& operator=(const gss_bid_attr_provider&);
};

typedef gss_bid_attr_provider *(*gss_bid_attr_create_provider)(void);

/*
 * Attribute context: this manages a set of providers for a given
 * security context.
 */
struct gss_bid_attr_ctx
{
public:
    gss_bid_attr_ctx(void);
    ~gss_bid_attr_ctx(void);

    bool initWithExistingContext(const gss_bid_attr_ctx *manager);
    bool initWithGssContext(const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_bid_attr_enumeration_cb, void *data) const;
    bool getAttributeTypes(gss_buffer_set_t *attrs);

    bool setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    bool deleteAttribute(const gss_buffer_t value);
    bool getAttribute(const gss_buffer_t attr,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;
    gss_any_t mapToAny(int authenticated,
                       gss_buffer_t type_id) const;
    void releaseAnyNameMapping(gss_buffer_t type_id,
                               gss_any_t input) const;

    void exportToBuffer(gss_buffer_t buffer) const;
    bool initWithBuffer(const gss_buffer_t buffer);

    static std::string
    composeAttributeName(const gss_buffer_t prefix,
                         const gss_buffer_t suffix);
    static void
    decomposeAttributeName(const gss_buffer_t attribute,
                           gss_buffer_t prefix,
                           gss_buffer_t suffix);
    static void
    composeAttributeName(const gss_buffer_t prefix,
                         const gss_buffer_t suffix,
                         gss_buffer_t attribute);

    std::string
    composeAttributeName(unsigned int type,
                         const gss_buffer_t suffix);
    void
    decomposeAttributeName(const gss_buffer_t attribute,
                           unsigned int *type,
                           gss_buffer_t suffix) const;
    void
    composeAttributeName(unsigned int type,
                         const gss_buffer_t suffix,
                         gss_buffer_t attribute) const;

    gss_bid_attr_provider *getProvider(unsigned int type) const;

    static void
    registerProvider(unsigned int type,
                     gss_bid_attr_create_provider factory);
    static void
    unregisterProvider(unsigned int type);

    time_t getExpiryTime(void) const;
    OM_uint32 mapException(OM_uint32 *minor, std::exception &e) const;

private:
    bool providerEnabled(unsigned int type) const;
    void releaseProvider(unsigned int type);

    unsigned int attributePrefixToType(const gss_buffer_t prefix) const;
    gss_buffer_desc attributeTypeToPrefix(unsigned int type) const;

    bool initWithJsonObject(JSONObject &object);
    JSONObject jsonRepresentation(void) const;

    gss_bid_attr_provider *getPrimaryProvider(void) const;

    /* make non-copyable */
    gss_bid_attr_ctx(const gss_bid_attr_ctx&);
    gss_bid_attr_ctx& operator=(const gss_bid_attr_ctx&);

    uint32_t m_flags;
    gss_bid_attr_provider *m_providers[ATTR_TYPE_MAX + 1];
};

#endif /* __cplusplus */

#include "util_browserid.h"
#include "util_saml.h"
#include "util_shib.h"

#ifdef __cplusplus

static inline void
duplicateBuffer(gss_buffer_desc &src, gss_buffer_t dst)
{
    OM_uint32 minor;

    if (GSS_ERROR(duplicateBuffer(&minor, &src, dst)))
        throw std::bad_alloc();
}

static inline void
duplicateBuffer(std::string &str, gss_buffer_t buffer)
{
    gss_buffer_desc tmp;

    tmp.length = str.length();
    tmp.value = (char *)str.c_str();

    duplicateBuffer(tmp, buffer);
}

#else
struct gss_bid_attr_ctx;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C wrappers for attribute context functions. These match their
 * GSS naming extension equivalents. The caller is required to
 * obtain the name mutex.
 */

OM_uint32
gssBidCreateAttrContext(OM_uint32 *minor,
                        gss_cred_id_t acceptorCred,
                        gss_ctx_id_t acceptorCtx,
                        struct gss_bid_attr_ctx **pAttrCtx,
                        time_t *pExpiryTime);

OM_uint32
gssBidInquireName(OM_uint32 *minor,
                  gss_name_t name,
                  int *name_is_MN,
                  gss_OID *MN_mech,
                  gss_buffer_set_t *attrs);

OM_uint32
gssBidGetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more);

OM_uint32
gssBidDeleteNameAttribute(OM_uint32 *minor,
                          gss_name_t name,
                          gss_buffer_t attr);

OM_uint32
gssBidSetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       int complete,
                       gss_buffer_t attr,
                       gss_buffer_t value);

OM_uint32
gssBidExportAttrContext(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t buffer);

OM_uint32
gssBidImportAttrContext(OM_uint32 *minor,
                        gss_buffer_t buffer,
                        gss_name_t name);

OM_uint32
gssBidDuplicateAttrContext(OM_uint32 *minor,
                           gss_name_t in,
                           gss_name_t out);

OM_uint32
gssBidMapNameToAny(OM_uint32 *minor,
                   gss_name_t name,
                   int authenticated,
                   gss_buffer_t type_id,
                   gss_any_t *output);

OM_uint32
gssBidReleaseAnyNameMapping(OM_uint32 *minor,
                            gss_name_t name,
                            gss_buffer_t type_id,
                            gss_any_t *input);

OM_uint32
gssBidReleaseAttrContext(OM_uint32 *minor,
                         gss_name_t name);

OM_uint32
gssBidAttrProvidersFinalize(OM_uint32 *minor);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_ATTR_H_ */
