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

OM_uint32
gss_inquire_context(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    gss_name_t *src_name,
                    gss_name_t *targ_name,
                    OM_uint32 *lifetime_rec,
                    gss_OID *mech_type,
                    OM_uint32 *ctx_flags,
                    int *locally_initiated,
                    int *open)
{
    OM_uint32 major, tmpMinor;

    *minor = 0;

    if (ctx == GSS_C_NO_CONTEXT) {
        major = GSS_S_NO_CONTEXT;
        goto cleanup;
    }

    if (src_name != NULL) {
        major = gss_duplicate_name(minor, ctx->initiatorName, src_name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (targ_name != NULL) {
        major = gss_duplicate_name(minor, ctx->acceptorName, targ_name);
        if (GSS_ERROR(major))
            goto cleanup;
    }

    if (lifetime_rec != NULL) {
        time_t now = time(NULL);
        time_t lifetime;

        if (ctx->expiryTime == ~0)
            lifetime = GSS_C_INDEFINITE;
        else
            lifetime = now - ctx->expiryTime;

        if (lifetime < 0)
            lifetime = 0;

        *lifetime_rec = lifetime;
    }

    if (ctx_flags != NULL) {
        *ctx_flags = ctx->gssFlags;
    }

    if (locally_initiated != NULL) {
        *locally_initiated = CTX_IS_INITIATOR(ctx);
    }

    if (open != NULL) {
        *open = CTX_IS_ESTABLISHED(ctx);
    }

    major = GSS_S_COMPLETE;

cleanup:
    if (GSS_ERROR(major)) {
        gssEapReleaseName(&tmpMinor, src_name);
        gssEapReleaseName(&tmpMinor, targ_name);
    }

    return major;
}
