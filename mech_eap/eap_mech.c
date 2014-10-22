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
 * Initialisation and finalise functions.
 */

#include "gssapiP_eap.h"

static OM_uint32
eapPeerRegisterMethods(OM_uint32 *minor)
{
    OM_uint32 ret = 0;

#ifdef EAP_MD5
    if (ret == 0)
        ret = eap_peer_md5_register();
#endif /* EAP_MD5 */

#ifdef EAP_TLS
    if (ret == 0)
        ret = eap_peer_tls_register();
#endif /* EAP_TLS */

#ifdef EAP_MSCHAPv2
    if (ret == 0)
        ret = eap_peer_mschapv2_register();
#endif /* EAP_MSCHAPv2 */

#ifdef EAP_PEAP
    if (ret == 0)
        ret = eap_peer_peap_register();
#endif /* EAP_PEAP */

#ifdef EAP_TTLS
    if (ret == 0)
        ret = eap_peer_ttls_register();
#endif /* EAP_TTLS */

#ifdef EAP_GTC
    if (ret == 0)
        ret = eap_peer_gtc_register();
#endif /* EAP_GTC */

#ifdef EAP_OTP
    if (ret == 0)
        ret = eap_peer_otp_register();
#endif /* EAP_OTP */

#ifdef EAP_SIM
    if (ret == 0)
        ret = eap_peer_sim_register();
#endif /* EAP_SIM */

#ifdef EAP_LEAP
    if (ret == 0)
        ret = eap_peer_leap_register();
#endif /* EAP_LEAP */

#ifdef EAP_PSK
    if (ret == 0)
        ret = eap_peer_psk_register();
#endif /* EAP_PSK */

#ifdef EAP_AKA
    if (ret == 0)
        ret = eap_peer_aka_register();
#endif /* EAP_AKA */

#ifdef EAP_AKA_PRIME
    if (ret == 0)
        ret = eap_peer_aka_prime_register();
#endif /* EAP_AKA_PRIME */

#ifdef EAP_FAST
    if (ret == 0)
        ret = eap_peer_fast_register();
#endif /* EAP_FAST */

#ifdef EAP_PAX
    if (ret == 0)
        ret = eap_peer_pax_register();
#endif /* EAP_PAX */

#ifdef EAP_SAKE
    if (ret == 0)
        ret = eap_peer_sake_register();
#endif /* EAP_SAKE */

#ifdef EAP_GPSK
    if (ret == 0)
        ret = eap_peer_gpsk_register();
#endif /* EAP_GPSK */

#ifdef EAP_WSC
    if (ret == 0)
        ret = eap_peer_wsc_register();
#endif /* EAP_WSC */

#ifdef EAP_IKEV2
    if (ret == 0)
        ret = eap_peer_ikev2_register();
#endif /* EAP_IKEV2 */

#ifdef EAP_VENDOR_TEST
    if (ret == 0)
        ret = eap_peer_vendor_test_register();
#endif /* EAP_VENDOR_TEST */

#ifdef EAP_TNC
    if (ret == 0)
        ret = eap_peer_tnc_register();
#endif /* EAP_TNC */

    if (ret == 0)
        return GSS_S_COMPLETE;

    *minor = GSSEAP_LIBEAP_INIT_FAILURE;
    return GSS_S_FAILURE;
}

static OM_uint32
gssEapInitLibEap(OM_uint32 *minor)
{
    return eapPeerRegisterMethods(minor);
}

static OM_uint32
gssEapInitLibRadsec(OM_uint32 *minor)
{
    if (0) {
        *minor = GSSEAP_RADSEC_INIT_FAILURE;
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

void gssEapFinalize(void) GSSEAP_DESTRUCTOR;

OM_uint32
gssEapInitiatorInit(OM_uint32 *minor)
{
    OM_uint32 major;

    initialize_eapg_error_table();
    initialize_rse_error_table();

    major = gssEapInitLibEap(minor);
    if (GSS_ERROR(major))
        return major;

    major = gssEapInitLibRadsec(minor);
    if (GSS_ERROR(major))
        return major;

#ifdef GSSEAP_ENABLE_REAUTH
    major = gssEapReauthInitialize(minor);
    if (GSS_ERROR(major))
        return major;
#endif

    *minor = 0;
    return GSS_S_COMPLETE;
}

void
gssEapFinalize(void)
{
    eap_peer_unregister_methods();
}

#ifdef GSSEAP_CONSTRUCTOR
static void gssEapInitiatorInitAssert(void) GSSEAP_CONSTRUCTOR;

static void
gssEapInitiatorInitAssert(void)
{
    OM_uint32 major, minor;

    major = gssEapInitiatorInit(&minor);

    GSSEAP_ASSERT(!GSS_ERROR(major));
}
#endif
