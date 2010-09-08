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

#ifndef _UTIL_SAML_H_
#define _UTIL_SAML_H_ 1

struct eap_gss_saml_assertion;

OM_uint32
samlDuplicateAssertion(OM_uint32 *minor,
                       const struct eap_gss_saml_assertion *in,
                       struct eap_gss_saml_assertion **out);

OM_uint32
samlExportAssertion(OM_uint32 *minor,
                    struct eap_gss_saml_assertion *assertion,
                    gss_buffer_t buffer);

OM_uint32
samlFreeAssertion(OM_uint32 *minor,
                  struct eap_gss_saml_assertion *assertion);

OM_uint32
samlGetAttributeTypes(OM_uint32 *minor,
                      const struct eap_gss_saml_assertion *assertion,
                      void *data,
                      OM_uint32 (*addAttribute)(OM_uint32 *, void *, gss_buffer_t));

OM_uint32
samlGetAttribute(OM_uint32 *minor,
                 const struct eap_gss_saml_assertion *assertion,
                 gss_buffer_t attr,
                 int *authenticated,
                 int *complete,
                 gss_buffer_t value,
                 gss_buffer_t display_value,
                 int *more);

OM_uint32
samlSetAttribute(OM_uint32 *minor,
                 struct eap_gss_saml_assertion *assertion,
                 int complete,
                 gss_buffer_t attr,
                 gss_buffer_t value);

#endif /* _UTIL_SAML_H_ */
