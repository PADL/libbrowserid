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
 * Enumerate the features supported by the GSS BrowserID mechanism.
 */

#include "gssapiP_bid.h"

#define MA_ADD(ma, set)    do { \
    major = gss_add_oid_set_member(minor, (gss_OID)(ma), (set));            \
    if (GSS_ERROR(major))                                                   \
        goto cleanup;                                                       \
    } while (0)

#define MA_SUPPORTED(ma)    MA_ADD((ma), mech_attrs)
#define MA_KNOWN(ma)        MA_ADD((ma), known_mech_attrs)

OM_uint32 GSSAPI_CALLCONV
gss_inquire_attrs_for_mech(OM_uint32 *minor,
                           gss_const_OID mech_oid,
                           gss_OID_set *mech_attrs,
                           gss_OID_set *known_mech_attrs)
{
    OM_uint32 major, tmpMinor;

    if (mech_attrs != NULL)
        *mech_attrs = GSS_C_NO_OID_SET;
    if (known_mech_attrs != NULL)
        *known_mech_attrs = GSS_C_NO_OID_SET;

    if (!gssBidIsConcreteMechanismOid((const gss_OID)mech_oid)) {
        *minor = GSSBID_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (mech_attrs != NULL) {
        major = gss_create_empty_oid_set(minor, mech_attrs);
        if (GSS_ERROR(major))
            goto cleanup;

#ifdef HAVE_GSS_INQUIRE_ATTRS_FOR_MECH
        if (oidEqual(mech_oid, GSS_BROWSERID_MECHANISM))
            MA_SUPPORTED(GSS_C_MA_MECH_PSEUDO);
        else
            MA_SUPPORTED(GSS_C_MA_MECH_CONCRETE);
        MA_SUPPORTED(GSS_C_MA_ITOK_FRAMED);
        MA_SUPPORTED(GSS_C_MA_AUTH_INIT);
        MA_SUPPORTED(GSS_C_MA_AUTH_INIT_INIT);
        if (!oidEqual(mech_oid, GSS_BROWSERID_NONE_MECHANISM)) {
            MA_SUPPORTED(GSS_C_MA_INTEG_PROT);
            MA_SUPPORTED(GSS_C_MA_CONF_PROT);
            MA_SUPPORTED(GSS_C_MA_MIC);
            MA_SUPPORTED(GSS_C_MA_WRAP);
            MA_SUPPORTED(GSS_C_MA_OOS_DET);
        }
        MA_SUPPORTED(GSS_C_MA_REPLAY_DET);
        MA_SUPPORTED(GSS_C_MA_CBINDINGS);
        MA_SUPPORTED(GSS_C_MA_CTX_TRANS);
#endif
    }

    if (known_mech_attrs != NULL) {
        major = gss_create_empty_oid_set(minor, known_mech_attrs);
        if (GSS_ERROR(major))
            goto cleanup;

#ifdef HAVE_GSS_INQUIRE_ATTRS_FOR_MECH
        MA_KNOWN(GSS_C_MA_MECH_CONCRETE);
        MA_KNOWN(GSS_C_MA_MECH_PSEUDO);
        MA_KNOWN(GSS_C_MA_MECH_COMPOSITE);
        MA_KNOWN(GSS_C_MA_MECH_NEGO);
        MA_KNOWN(GSS_C_MA_MECH_GLUE);
        MA_KNOWN(GSS_C_MA_NOT_MECH);
        MA_KNOWN(GSS_C_MA_DEPRECATED);
        MA_KNOWN(GSS_C_MA_NOT_DFLT_MECH);
        MA_KNOWN(GSS_C_MA_ITOK_FRAMED);
        MA_KNOWN(GSS_C_MA_AUTH_INIT);
        MA_KNOWN(GSS_C_MA_AUTH_TARG);
        MA_KNOWN(GSS_C_MA_AUTH_INIT_INIT);
        MA_KNOWN(GSS_C_MA_AUTH_TARG_INIT);
        MA_KNOWN(GSS_C_MA_AUTH_INIT_ANON);
        MA_KNOWN(GSS_C_MA_AUTH_TARG_ANON);
        MA_KNOWN(GSS_C_MA_DELEG_CRED);
        MA_KNOWN(GSS_C_MA_INTEG_PROT);
        MA_KNOWN(GSS_C_MA_CONF_PROT);
        MA_KNOWN(GSS_C_MA_MIC);
        MA_KNOWN(GSS_C_MA_WRAP);
        MA_KNOWN(GSS_C_MA_PROT_READY);
        MA_KNOWN(GSS_C_MA_REPLAY_DET);
        MA_KNOWN(GSS_C_MA_OOS_DET);
        MA_KNOWN(GSS_C_MA_CBINDINGS);
        MA_KNOWN(GSS_C_MA_PFS);
        MA_KNOWN(GSS_C_MA_COMPRESS);
        MA_KNOWN(GSS_C_MA_CTX_TRANS);
#endif
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_oid_set(&tmpMinor, mech_attrs);
        gss_release_oid_set(&tmpMinor, known_mech_attrs);
    }

    return major;
}
