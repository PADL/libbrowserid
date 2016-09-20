/*
 * Copyright (c) 2016, JANET(UK)
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

void
gssEapTraceStatus(const char *function,
                  OM_uint32 major, OM_uint32 minor)
{
    gss_buffer_desc  gss_code_buf, mech_buf;
    OM_uint32 tmpmaj, tmpmin, ctx = 0;
    gss_code_buf.value = NULL;
    mech_buf.value = NULL;
    tmpmaj = gss_display_status(&tmpmin,  major,
                                GSS_C_GSS_CODE, GSS_C_NO_OID, &ctx,
                                &gss_code_buf);
    if (!GSS_ERROR(tmpmaj)) {
        if (minor == 0)
            tmpmaj = makeStringBuffer(&tmpmin, "no minor", &mech_buf);
        else tmpmaj = gssEapDisplayStatus(&tmpmin, minor, &mech_buf);
    }
    if (!GSS_ERROR(tmpmaj)) {
        wpa_printf(MSG_INFO, "%s: %.*s/%.*s",
                   function, (int) gss_code_buf.length, (char *) gss_code_buf.value,
                   (int) mech_buf.length, (char *) mech_buf.value);
    }
    else {
        wpa_printf(MSG_INFO, "%s: %u/%u", function, major, minor);
    }
    tmpmaj = gss_release_buffer(&tmpmin, &gss_code_buf);
    tmpmaj = gss_release_buffer(&tmpmin, &mech_buf);
}

