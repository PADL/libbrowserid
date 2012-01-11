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
 * RADIUS attribute provider.
 */

#ifndef _UTIL_RADIUS_H_
#define _UTIL_RADIUS_H_ 1

#ifdef __cplusplus

typedef std::pair <unsigned int, unsigned int> gss_eap_attrid;

struct gss_eap_radius_attr_provider : gss_eap_attr_provider {
public:
    gss_eap_radius_attr_provider(void);
    ~gss_eap_radius_attr_provider(void);

    bool initWithExistingContext(const gss_eap_attr_ctx *source,
                                 const gss_eap_attr_provider *ctx);
    bool initWithGssContext(const gss_eap_attr_ctx *source,
                            const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
    bool setAttribute(int complete,
                      const gss_buffer_t attr,
                      const gss_buffer_t value);
    bool deleteAttribute(const gss_buffer_t attr);
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
    bool initWithJsonObject(const gss_eap_attr_ctx *manager,
                           JSONObject &obj);
    JSONObject jsonRepresentation(void) const;

    bool getAttribute(const gss_eap_attrid &attrid,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;
    bool setAttribute(int complete,
                      const gss_eap_attrid &attrid,
                      const gss_buffer_t value);
    bool deleteAttribute(const gss_eap_attrid &attrid);

    bool getFragmentedAttribute(const gss_eap_attrid &attrid,
                                int *authenticated,
                                int *complete,
                                gss_buffer_t value) const;

    bool authenticated(void) const { return m_authenticated; }

    time_t getExpiryTime(void) const;

    static bool init(void);
    static void finalize(void);

    static gss_eap_attr_provider *createAttrContext(void);

private:
    rs_const_avp *getAvps(void) const {
        return m_vps;
    }

    rs_avp *m_vps;
    bool m_authenticated;
};

/* For now */
extern "C" {
#endif

OM_uint32
gssEapRadiusAddAvp(OM_uint32 *minor,
                   struct rs_packet *pkt,
                   unsigned int type,
                   unsigned int vendor,
                   const gss_buffer_t buffer);

OM_uint32
gssEapRadiusGetAvp(OM_uint32 *minor,
                   struct rs_packet *pkt,
                   unsigned int type,
                   unsigned int vendor,
                   gss_buffer_t buffer,
                   int concat);

OM_uint32
gssEapRadiusGetRawAvp(OM_uint32 *minor,
                      rs_const_avp *vps,
                      unsigned int type,
                      unsigned int vendor,
                      rs_const_avp **vp);
OM_uint32
gssEapRadiusFreeAvps(OM_uint32 *minor,
                     rs_avp **vps);

OM_uint32 gssEapRadiusAttrProviderInit(OM_uint32 *minor);
OM_uint32 gssEapRadiusAttrProviderFinalize(OM_uint32 *minor);

OM_uint32
gssEapRadiusMapError(OM_uint32 *minor,
                     struct rs_error *err);

OM_uint32
gssEapCreateRadiusContext(OM_uint32 *minor,
                          gss_cred_id_t cred,
                          struct rs_context **pRadContext);

/* This really needs to be a function call on Windows */
#define RS_CONFIG_FILE      SYSCONFDIR "/radsec.conf"

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_RADIUS_H_ */
