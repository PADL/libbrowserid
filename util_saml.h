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

#ifndef _UTIL_SAML_H_
#define _UTIL_SAML_H_ 1

#ifdef __cplusplus

namespace opensaml {
    namespace saml2 {
        class Attribute;
        class Assertion;
        class NameID;
    };
};

struct gss_eap_saml_assertion_provider : gss_eap_attr_provider {
public:
    gss_eap_saml_assertion_provider(void);
    ~gss_eap_saml_assertion_provider(void);

    bool initFromExistingContext(const gss_eap_attr_ctx *source,
                                 const gss_eap_attr_provider *ctx);
    bool initFromGssContext(const gss_eap_attr_ctx *source,
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

    void exportToBuffer(gss_buffer_t buffer) const;
    bool initFromBuffer(const gss_eap_attr_ctx *ctx,
                        const gss_buffer_t buffer);

    opensaml::saml2::Assertion *initAssertion(void);

    opensaml::saml2::Assertion *getAssertion(void) const {
        return m_assertion;
    }
    bool authenticated(void) const {
        return m_authenticated;
    }

    time_t getExpiryTime(void) const;
    OM_uint32 mapException(OM_uint32 *minor, std::exception &e) const;

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
    static opensaml::saml2::Assertion *
        parseAssertion(const gss_buffer_t buffer);

    void setAssertion(const opensaml::saml2::Assertion *assertion,
                      bool authenticated = false);
    void setAssertion(const gss_buffer_t buffer,
                      bool authenticated = false);

    opensaml::saml2::Assertion *m_assertion;
    bool m_authenticated;
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

    void exportToBuffer(gss_buffer_t buffer) const;
    bool initFromBuffer(const gss_eap_attr_ctx *ctx,
                        const gss_buffer_t buffer);

    bool getAttribute(const gss_buffer_t attr,
                      int *authenticated,
                      int *complete,
                      const opensaml::saml2::Attribute **pAttribute) const;
    bool getAssertion(int *authenticated,
                      opensaml::saml2::Assertion **pAssertion,
                      bool createIfAbsent = false) const;

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
};

extern "C" {
#endif

OM_uint32 gssEapSamlAttrProvidersInit(OM_uint32 *minor);
OM_uint32 gssEapSamlAttrProvidersFinalize(OM_uint32 *minor);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_SAML_H_ */
