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
 * SAML attribute provider.
 */

#ifndef _UTIL_SIMPLESAML_H_
#define _UTIL_SIMPLESAML_H_ 1

#include "util_attr.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

#ifdef __cplusplus

struct gss_eap_simplesaml_assertion_provider : gss_eap_attr_provider {
public:
    gss_eap_simplesaml_assertion_provider(void);
    ~gss_eap_simplesaml_assertion_provider(void);

    bool initWithExistingContext(const gss_eap_attr_ctx *source,
                                 const gss_eap_attr_provider *ctx);
    bool initWithGssContext(const gss_eap_attr_ctx *source,
                            const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
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

    const char *prefix(void) const;
    const char *name(void) const { return NULL; }
    bool initWithJsonObject(const gss_eap_attr_ctx *manager GSSEAP_UNUSED,
                           JSONObject &object GSSEAP_UNUSED) {
        return false;
    }
    JSONObject jsonRepresentation(void) const {
        return JSONObject::null();
    }

    bool authenticated(void) const {
        return m_authenticated;
    }

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

    json_t* getJsonAssertion() const;

private:
    xmlDocPtr m_assertion;
    bool m_authenticated;
    void processAttribute(xmlNodePtr attribute, json_t *jattributes) const;
    void processAttributeStatement(xmlNodePtr attributeStatement, json_t *jattributes) const;
    json_t *processNameID(xmlNodePtr nameid) const;
    json_t *processSubject(xmlNodePtr subject) const;
};

struct gss_eap_nameid_attr_provider : gss_eap_attr_provider {
public:
    gss_eap_nameid_attr_provider(void) {}
    ~gss_eap_nameid_attr_provider(void) {}

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
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

    const char *prefix(void) const;
    const char *name(void) const {
        return NULL;
    }
    bool initWithJsonObject(const gss_eap_attr_ctx *manager GSSEAP_UNUSED,
                            JSONObject &object GSSEAP_UNUSED) {
        return false;
    }
    JSONObject jsonRepresentation(void) const {
        return JSONObject::null();
    }

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
    bool getAssertion(int *authenticated, json_t **jassertion) const;
    xmlNodePtr getNameIDNode(xmlDocPtr assertion) const;
};

struct gss_eap_saml_attr_provider : gss_eap_attr_provider {
public:
    gss_eap_saml_attr_provider(void) {}
    ~gss_eap_saml_attr_provider(void) {}

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
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

    const char *prefix(void) const;
    const char *name(void) const {
        return NULL;
    }
    bool initWithJsonObject(const gss_eap_attr_ctx *manager GSSEAP_UNUSED,
                            JSONObject &object GSSEAP_UNUSED) {
        return false;
    }
    JSONObject jsonRepresentation(void) const {
        return JSONObject::null();
    }

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
    bool getAssertion(int *authenticated, json_t **jassertion) const;
};

extern "C" {
#endif

OM_uint32 gssEapSimpleSamlAttrProvidersInit(OM_uint32 *minor);
OM_uint32 gssEapSimpleSamlAttrProvidersFinalize(OM_uint32 *minor);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_SIMPLESAML_H_ */
