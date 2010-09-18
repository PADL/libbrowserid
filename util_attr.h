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

#ifndef _UTIL_ATTR_H_
#define _UTIL_ATTR_H_ 1

#define ATTR_TYPE_RADIUS            0U
#define ATTR_TYPE_SAML_ASSERTION    1U
#define ATTR_TYPE_SAML              2U
#define ATTR_TYPE_LOCAL             3U
#define ATTR_TYPE_MIN               ATTR_TYPE_RADIUS
#define ATTR_TYPE_MAX               (ATTR_TYPE_LOCAL + 1U)

#ifdef __cplusplus
#include <string>

struct gss_eap_attr_provider;
struct gss_eap_attr_ctx;

typedef bool
(*gss_eap_attr_enumeration_cb)(const gss_eap_attr_provider *source,
                               const gss_buffer_t attribute,
                               void *data);

struct gss_eap_attr_provider
{
public:
    gss_eap_attr_provider(void) {}
    virtual ~gss_eap_attr_provider(void) {}

    bool initWithManager(const gss_eap_attr_ctx *manager)
    {
        m_manager = manager;
        return true;
    }

    virtual bool initFromExistingContext(const gss_eap_attr_ctx *manager,
                                         const gss_eap_attr_provider *ctx)
    {
        return initWithManager(manager);
    }

    virtual bool initFromGssContext(const gss_eap_attr_ctx *manager,
                                    const gss_cred_id_t cred,
                                    const gss_ctx_id_t ctx)
    {
        return initWithManager(manager);
    }

    virtual bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const
    {
        return false;
    }

    virtual void setAttribute(int complete,
                              const gss_buffer_t attr,
                              const gss_buffer_t value) {}
    virtual void deleteAttribute(const gss_buffer_t value) {}
    virtual bool getAttribute(const gss_buffer_t attr,
                              int *authenticated,
                              int *complete,
                              gss_buffer_t value,
                              gss_buffer_t display_value,
                              int *more) const { return false; }

    virtual gss_any_t mapToAny(int authenticated,
                               gss_buffer_t type_id) const { return NULL; }
    virtual void releaseAnyNameMapping(gss_buffer_t type_id,
                                       gss_any_t input) const {}

    virtual void exportToBuffer(gss_buffer_t buffer) const {}
    virtual bool initFromBuffer(const gss_eap_attr_ctx *manager,
                                const gss_buffer_t buffer)
    {
        return initWithManager(manager);
    }

    static bool init() { return true; }
    static void finalize() {}

    static gss_eap_attr_provider *createAttrContext(void) { return NULL; }

protected:
    const gss_eap_attr_ctx *m_manager;

private:
    /* make non-copyable */
    gss_eap_attr_provider(const gss_eap_attr_provider&);
    gss_eap_attr_provider& operator=(const gss_eap_attr_provider&);
};

typedef gss_eap_attr_provider *(*gss_eap_attr_create_provider)(void);

struct gss_eap_attr_ctx
{
public:
    gss_eap_attr_ctx(void);
    ~gss_eap_attr_ctx(void);

    bool initFromExistingContext(const gss_eap_attr_ctx *manager);
    bool initFromGssContext(const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
    bool getAttributeTypes(gss_buffer_set_t *attrs);

    void setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    void deleteAttribute(const gss_buffer_t value);
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
    bool initFromBuffer(const gss_buffer_t buffer);

    static unsigned int
    attributePrefixToType(const gss_buffer_t prefix);

    static const gss_buffer_t
    attributeTypeToPrefix(unsigned int type);

    static void
    decomposeAttributeName(const gss_buffer_t attribute,
                           gss_buffer_t prefix,
                           gss_buffer_t suffix);
    static void
    composeAttributeName(const gss_buffer_t prefix,
                         const gss_buffer_t suffix,
                         gss_buffer_t attribute);
    static void
    decomposeAttributeName(const gss_buffer_t attribute,
                           unsigned int *type,
                           gss_buffer_t suffix);
    static void
    composeAttributeName(unsigned int type,
                         const gss_buffer_t suffix,
                         gss_buffer_t attribute);

    static std::string
    composeAttributeName(const gss_buffer_t prefix,
                         const gss_buffer_t suffix);
    static std::string
    composeAttributeName(unsigned int type,
                         const gss_buffer_t suffix);

    gss_eap_attr_provider *getProvider(unsigned int type) const;
    gss_eap_attr_provider *getProvider(const gss_buffer_t prefix) const;

    static void
    registerProvider(unsigned int type,
                     const char *prefix,
                     gss_eap_attr_create_provider factory);
    static void
    unregisterProvider(unsigned int type);

private:
    /* make non-copyable */
    gss_eap_attr_ctx(const gss_eap_attr_ctx&);
    gss_eap_attr_ctx& operator=(const gss_eap_attr_ctx&);

    gss_eap_attr_provider *m_providers[ATTR_TYPE_MAX];
};

#include "util_radius.h"
#include "util_saml.h"
#include "util_shib.h"

#include <string>
#include <new>

static inline void
duplicateBuffer(gss_buffer_desc &src, gss_buffer_t dst)
{
    OM_uint32 minor;

    if (GSS_ERROR(duplicateBuffer(&minor, &src, dst)))
        throw new std::bad_alloc();
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
struct gss_eap_attr_ctx;
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct gss_eap_attr_ctx *
gssEapCreateAttrContext(gss_cred_id_t acceptorCred,
                        gss_ctx_id_t acceptorCtx);

OM_uint32
gssEapInquireName(OM_uint32 *minor,
                  gss_name_t name,
                  int *name_is_MN,
                  gss_OID *MN_mech,
                  gss_buffer_set_t *attrs);

OM_uint32
gssEapGetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       gss_buffer_t attr,
                       int *authenticated,
                       int *complete,
                       gss_buffer_t value,
                       gss_buffer_t display_value,
                       int *more);

OM_uint32
gssEapDeleteNameAttribute(OM_uint32 *minor,
                          gss_name_t name,
                          gss_buffer_t attr);

OM_uint32
gssEapSetNameAttribute(OM_uint32 *minor,
                       gss_name_t name,
                       int complete,
                       gss_buffer_t attr,
                       gss_buffer_t value);

OM_uint32
gssEapExportAttrContext(OM_uint32 *minor,
                        gss_name_t name,
                        gss_buffer_t buffer);

OM_uint32
gssEapImportAttrContext(OM_uint32 *minor,
                        gss_buffer_t buffer,
                        gss_name_t name);

OM_uint32
gssEapDuplicateAttrContext(OM_uint32 *minor,
                           gss_name_t in,
                           gss_name_t out);

OM_uint32
gssEapMapNameToAny(OM_uint32 *minor,
                   gss_name_t name,
                   int authenticated,
                   gss_buffer_t type_id,
                   gss_any_t *output);

OM_uint32
gssEapReleaseAnyNameMapping(OM_uint32 *minor,
                            gss_name_t name,
                            gss_buffer_t type_id,
                            gss_any_t *input);

OM_uint32
gssEapReleaseAttrContext(OM_uint32 *minor,
                         gss_name_t name);

OM_uint32
gssEapAttrProvidersInit(OM_uint32 *minor);

OM_uint32
gssEapAttrProvidersFinalize(OM_uint32 *minor);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_ATTR_H_ */
