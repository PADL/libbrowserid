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

struct eap_gss_avp_list {
};

OM_uint32
radiusDuplicateAVPs(OM_uint32 *minor,
                    const struct eap_gss_avp_list *in,
                    struct eap_gss_avp_list **out)
{
    GSSEAP_NOT_IMPLEMENTED;
}

OM_uint32
radiusFreeAVPs(OM_uint32 *minor,
               struct eap_gss_avp_list *avps)
{
    if (avps != NULL) {
        GSSEAP_NOT_IMPLEMENTED;
    }
}

OM_uint32
radiusGetAttributeTypes(OM_uint32 *minor,
                        const struct eap_gss_avp_list *avps,
                        void *data,
                        OM_uint32 (*addAttribute)(OM_uint32 *, void *, gss_buffer_t))
{
    GSSEAP_NOT_IMPLEMENTED;
}

OM_uint32
radiusGetAVP(OM_uint32 *minor,
             const struct eap_gss_avp_list *avps,
             gss_buffer_t attr,
             int *authenticated,
             int *complete,
             gss_buffer_t value,
             gss_buffer_t display_value,
             int *more)
{
    GSSEAP_NOT_IMPLEMENTED;
}

OM_uint32
radiusSetAVP(OM_uint32 *minor,
             struct eap_gss_avp_list *avps,
             int complete,
             gss_buffer_t attr,
             gss_buffer_t value)
{
    GSSEAP_NOT_IMPLEMENTED;
}
