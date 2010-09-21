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

#ifndef _UTIL_RADIUS_H_
#define _UTIL_RADIUS_H_ 1

#ifdef __cplusplus

struct gss_eap_radius_attr_provider : gss_eap_attr_provider {
public:
    gss_eap_radius_attr_provider(void);
    ~gss_eap_radius_attr_provider(void);

    bool initFromExistingContext(const gss_eap_attr_ctx *source,
                                 const gss_eap_attr_provider *ctx);
    bool initFromGssContext(const gss_eap_attr_ctx *source,
                            const gss_cred_id_t cred,
                            const gss_ctx_id_t ctx);

    bool getAttributeTypes(gss_eap_attr_enumeration_cb, void *data) const;
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
    bool initFromBuffer(const gss_eap_attr_ctx *ctx,
                        const gss_buffer_t buffer);

    bool getAttribute(int attribute,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;
    bool getAttribute(int attribute,
                      int vendor,
                      int *authenticated,
                      int *complete,
                      gss_buffer_t value,
                      gss_buffer_t display_value,
                      int *more) const;

    bool authenticated() const { return m_authenticated; }

    static bool init();
    static void finalize();

    static gss_eap_attr_provider *createAttrContext(void);

private:
    bool initFromGssCred(const gss_cred_id_t cred);
    static VALUE_PAIR *copyAvps(const VALUE_PAIR *in);
    const VALUE_PAIR *getAvps(void) const {
        return m_avps;
    }

    rc_handle *m_rh;
    VALUE_PAIR *m_avps;
    bool m_authenticated;
};

/* For now */
#define PW_SAML_ASSERTION           1936

extern "C" {
#endif

OM_uint32
addAvpFromBuffer(OM_uint32 *minor,
                 rc_handle *rh,
                 VALUE_PAIR **vp,
                 int type,
                 gss_buffer_t buffer);

OM_uint32
getBufferFromAvps(OM_uint32 *minor,
                  VALUE_PAIR *vps,
                  int type,
                  gss_buffer_t buffer,
                  int concat);

OM_uint32 gssEapRadiusAttrProviderInit(OM_uint32 *minor);
OM_uint32 gssEapRadiusAttrProviderFinalize(OM_uint32 *minor);

OM_uint32
gssEapRadiusAllocHandle(OM_uint32 *minor,
                        const gss_cred_id_t cred,
                        rc_handle **pHandle);

#define RC_CONFIG_FILE      SYSCONFDIR "/radiusclient/radiusclient.conf"

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_RADIUS_H_ */
