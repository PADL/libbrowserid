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

    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

static OM_uint32
eapServerRegisterMethods(OM_uint32 *minor)
{
    OM_uint32 ret = 0;

#ifdef EAP_SERVER_IDENTITY
    if (ret == 0)
        ret = eap_server_identity_register();
#endif /* EAP_SERVER_IDENTITY */

#ifdef EAP_SERVER_MD5
    if (ret == 0)
        ret = eap_server_md5_register();
#endif /* EAP_SERVER_MD5 */

#ifdef EAP_SERVER_TLS
    if (ret == 0)
        ret = eap_server_tls_register();
#endif /* EAP_SERVER_TLS */

#ifdef EAP_SERVER_MSCHAPV2
    if (ret == 0)
        ret = eap_server_mschapv2_register();
#endif /* EAP_SERVER_MSCHAPV2 */

#ifdef EAP_SERVER_PEAP
    if (ret == 0)
        ret = eap_server_peap_register();
#endif /* EAP_SERVER_PEAP */

#ifdef EAP_SERVER_TLV
    if (ret == 0)
        ret = eap_server_tlv_register();
#endif /* EAP_SERVER_TLV */
#ifdef EAP_SERVER_GTC
    if (ret == 0)
        ret = eap_server_gtc_register();
#endif /* EAP_SERVER_GTC */

#ifdef EAP_SERVER_TTLS
    if (ret == 0)
        ret = eap_server_ttls_register();
#endif /* EAP_SERVER_TTLS */

#ifdef EAP_SERVER_SIM
    if (ret == 0)
        ret = eap_server_sim_register();
#endif /* EAP_SERVER_SIM */

#ifdef EAP_SERVER_AKA
    if (ret == 0)
        ret = eap_server_aka_register();
#endif /* EAP_SERVER_AKA */

#ifdef EAP_SERVER_AKA_PRIME
    if (ret == 0)
        ret = eap_server_aka_prime_register();
#endif /* EAP_SERVER_AKA_PRIME */

#ifdef EAP_SERVER_PAX
    if (ret == 0)
        ret = eap_server_pax_register();
#endif /* EAP_SERVER_PAX */

#ifdef EAP_SERVER_PSK
    if (ret == 0)
        ret = eap_server_psk_register();
#endif /* EAP_SERVER_PSK */

#ifdef EAP_SERVER_SAKE
    if (ret == 0)
        ret = eap_server_sake_register();
#endif /* EAP_SERVER_SAKE */

#ifdef EAP_SERVER_GPSK
    if (ret == 0)
        ret = eap_server_gpsk_register();
#endif /* EAP_SERVER_GPSK */

#ifdef EAP_SERVER_VENDOR_TEST
    if (ret == 0)
        ret = eap_server_vendor_test_register();
#endif /* EAP_SERVER_VENDOR_TEST */

#ifdef EAP_SERVER_FAST
    if (ret == 0)
        ret = eap_server_fast_register();
#endif /* EAP_SERVER_FAST */

#ifdef EAP_SERVER_WSC
    if (ret == 0)
        ret = eap_server_wsc_register();
#endif /* EAP_SERVER_WSC */

#ifdef EAP_SERVER_IKEV2
    if (ret == 0)
        ret = eap_server_ikev2_register();
#endif /* EAP_SERVER_IKEV2 */

#ifdef EAP_SERVER_TNC
    if (ret == 0)
        ret = eap_server_tnc_register();
#endif /* EAP_SERVER_TNC */

    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

static OM_uint32
gssEapInitLibEap(OM_uint32 *minor)
{
    return eapPeerRegisterMethods(minor);
}

static OM_uint32
gssEapInitLibRadius(OM_uint32 *minor)
{
    return GSS_S_COMPLETE;
}

static void gssEapInit(void) __attribute__((constructor));
static void gssEapFinalize(void) __attribute__((destructor));

static void
gssEapInit(void)
{
    OM_uint32 major, minor;

    major = gssEapInitLibEap(&minor);
    assert(major == GSS_S_COMPLETE);

    major = gssEapInitLibRadius(&minor);
    assert(major == GSS_S_COMPLETE);

    major = eapServerRegisterMethods(&minor);
    assert(major == GSS_S_COMPLETE);

    major = gssEapRadiusAttrProviderInit(&minor);
    assert(major == GSS_S_COMPLETE);

    major = gssEapSamlAttrProvidersInit(&minor);
    assert(major == GSS_S_COMPLETE);

    major = gssEapLocalAttrProviderInit(&minor);
    assert(major == GSS_S_COMPLETE);

#ifdef GSSEAP_ENABLE_REAUTH
    major = gssEapReauthInitialize(&minor);
    assert(major == GSS_S_COMPLETE);
#endif
}

static void
gssEapFinalize(void)
{
    OM_uint32 minor;

    gssEapLocalAttrProviderFinalize(&minor);
    gssEapSamlAttrProvidersFinalize(&minor);
    gssEapRadiusAttrProviderFinalize(&minor);

    eap_peer_unregister_methods();
    eap_server_unregister_methods();
}

