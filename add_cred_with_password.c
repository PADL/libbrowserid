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
 * Wrapper for acquiring a credential handle using a password.
 */

#include "gssapiP_eap.h"

OM_uint32
gss_add_cred_with_password(OM_uint32 *minor,
                           const gss_cred_id_t input_cred_handle,
                           const gss_name_t desired_name,
                           const gss_OID desired_mech,
                           const gss_buffer_t password,
                           gss_cred_usage_t cred_usage,
                           OM_uint32 initiator_time_req,
                           OM_uint32 acceptor_time_req,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *initiator_time_rec,
                           OM_uint32 *acceptor_time_rec)
{
    OM_uint32 major;
    OM_uint32 time_req, time_rec = 0;
    gss_OID_set_desc mechs;

    *minor = 0;
    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    if (cred_usage == GSS_C_ACCEPT)
        time_req = acceptor_time_req;
    else
        time_req = initiator_time_req;

    mechs.count = 1;
    mechs.elements = desired_mech;

    major = gssEapAcquireCred(minor,
                              desired_name,
                              password,
                              time_req,
                              &mechs,
                              cred_usage,
                              output_cred_handle,
                              actual_mechs,
                              &time_rec);

    if (initiator_time_rec != NULL)
        *initiator_time_rec = time_rec;
    if (acceptor_time_rec != NULL)
        *acceptor_time_rec = time_rec;

    return major;
}
