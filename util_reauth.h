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

#ifndef _UTIL_REAUTH_H_
#define _UTIL_REAUTH_H_ 1

#define KRB5_AUTHDATA_RADIUS_AVP        513

OM_uint32
gssInitSecContext(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_ctx_id_t *context_handle,
                  gss_name_t target_name,
                  gss_OID mech_type,
                  OM_uint32 req_flags,
                  OM_uint32 time_req,
                  gss_channel_bindings_t input_chan_bindings,
                  gss_buffer_t input_token,
                  gss_OID *actual_mech_type,
                  gss_buffer_t output_token,
                  OM_uint32 *ret_flags,
                  OM_uint32 *time_rec);

OM_uint32
gssAcceptSecContext(OM_uint32 *minor,
                    gss_ctx_id_t *context_handle,
                    gss_cred_id_t cred,
                    gss_buffer_t input_token,
                    gss_channel_bindings_t input_chan_bindings,
                    gss_name_t *src_name,
                    gss_OID *mech_type,
                    gss_buffer_t output_token,
                    OM_uint32 *ret_flags,
                    OM_uint32 *time_rec,
                    gss_cred_id_t *delegated_cred_handle);

OM_uint32
gssReleaseCred(OM_uint32 *minor,
               gss_cred_id_t *cred_handle);

OM_uint32
gssReleaseName(OM_uint32 *minor,
               gss_name_t *name);

OM_uint32
gssDeleteSecContext(OM_uint32 *minor,
                    gss_ctx_id_t *context_handle,
                    gss_buffer_t output_token);

OM_uint32
gssInquireSecContextByOid(OM_uint32 *minor,
                          const gss_ctx_id_t context_handle,
                          const gss_OID desired_object,
                          gss_buffer_set_t *data_set);

OM_uint32
gssKrbExtractAuthzDataFromSecContext(OM_uint32 *minor,
                                     const gss_ctx_id_t ctx,
                                     int ad_type,
                                     gss_buffer_t ad_data);

OM_uint32
gssStoreCred(OM_uint32 *minor,
             const gss_cred_id_t input_cred_handle,
             gss_cred_usage_t input_usage,
             const gss_OID desired_mech,
             OM_uint32 overwrite_cred,
             OM_uint32 default_cred,
             gss_OID_set *elements_stored,
             gss_cred_usage_t *cred_usage_stored);

OM_uint32
gssEapMakeReauthCreds(OM_uint32 *minor,
                      gss_ctx_id_t ctx,
                      gss_cred_id_t cred,
                      gss_buffer_t credBuf);

OM_uint32
gssEapStoreReauthCreds(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t credBuf);


OM_uint32
gssEapGlueToMechName(OM_uint32 *minor,
                     gss_name_t glueName,
                     gss_name_t *pMechName);

OM_uint32
gssEapMechToGlueName(OM_uint32 *minor,
                     gss_name_t mechName,
                     gss_name_t *pGlueName);

OM_uint32
gssEapReauthComplete(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    gss_cred_id_t cred,
                    const gss_OID mech,
                    OM_uint32 timeRec);

OM_uint32
gssEapReauthInitialize(OM_uint32 *minor);

#endif /* _UTIL_REAUTH_H_ */
