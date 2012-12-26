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
 * Local attribute provider.
 */

#ifndef _UTIL_SHIB_H_
#define _UTIL_SHIB_H_ 1

#ifdef __cplusplus

#include <vector>

namespace shibsp {
    class Attribute;
};

namespace shibresolver {
    class ShibbolethResolver;
};

struct gss_bid_shib_attr_provider : gss_bid_attr_provider {
public:
    gss_bid_shib_attr_provider(void);
    ~gss_bid_shib_attr_provider(void);

    bool initWithExistingContext(const gss_bid_attr_ctx *source,
                                 const gss_bid_attr_provider *ctx);
    bool initWithGssContext(const gss_bid_attr_ctx *source,
                            const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    bool deleteAttribute(const gss_buffer_t value);
    bool getAttributeTypes(gss_bid_attr_enumeration_cb, void *data) const;
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
    const char *name(void) const;
    bool initWithJsonObject(const gss_bid_attr_ctx *manager,
                            JSONObject &obj);
    JSONObject jsonRepresentation(void) const;

    static bool init(void);
    static void finalize(void);

    OM_uint32 mapException(OM_uint32 *minor, std::exception &e) const;

    static gss_bid_attr_provider *createAttrContext(void);

    std::vector<shibsp::Attribute *> getAttributes(void) const {
        return m_attributes;
    }

private:
    static shibsp::Attribute *
        duplicateAttribute(const shibsp::Attribute *src);
    static std::vector <shibsp::Attribute *>
        duplicateAttributes(const std::vector <shibsp::Attribute *>src);

    ssize_t getAttributeIndex(const gss_buffer_t attr) const;
    const shibsp::Attribute *getAttribute(const gss_buffer_t attr) const;

    bool authenticated(void) const { return m_authenticated; }

    bool m_initialized;
    bool m_authenticated;
    std::vector<shibsp::Attribute *> m_attributes;
};

extern "C" {
#endif

OM_uint32 gssBidLocalAttrProviderInit(OM_uint32 *minor);
OM_uint32 gssBidLocalAttrProviderFinalize(OM_uint32 *minor);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_SHIB_H_ */
