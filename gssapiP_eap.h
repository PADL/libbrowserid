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

#ifndef _GSSAPIP_EAP_H_
#define _GSSAPIP_EAP_H_ 1

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

/* GSS includes */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "gssapi_eap.h"
#include "util.h"

/* EAP includes */
#include <common.h>
#include <eap_peer/eap.h>
#include <eap_peer/eap_config.h>
#include <crypto/tls.h>                     /* XXX testing implementation only */
#include <wpabuf.h>

/* Kerberos includes */
#include <krb5.h>

#define NAME_FLAG_NAI                       0x00000001
#define NAME_FLAG_SERVICE                   0x00000002
#define NAME_FLAG_SAML                      0x00000010
#define NAME_FLAG_RADIUS                    0x00000020

#define NAME_HAS_ATTRIBUTES(name)           ((name)->flags & \
                                             (NAME_FLAG_SAML | NAME_FLAG_RADIUS))

struct eap_gss_saml_assertion;
struct eap_gss_avp_list;

struct gss_name_struct {
    GSSEAP_MUTEX mutex; /* mutex protecting attributes */
    OM_uint32 flags;
    krb5_principal krbPrincipal; /* this is immutable */
    struct eap_gss_saml_assertion *assertion;
    struct eap_gss_avp_list *avps;
};

#define CRED_FLAG_INITIATE                  0x00000001
#define CRED_FLAG_ACCEPT                    0x00000002
#define CRED_FLAG_DEFAULT_IDENTITY          0x00000004
#define CRED_FLAG_PASSWORD                  0x00000008

struct gss_cred_id_struct {
    GSSEAP_MUTEX mutex;
    OM_uint32 flags;
    gss_name_t name;
    gss_buffer_desc password;
    gss_OID_set mechanisms;
    time_t expiryTime;
};

#define CTX_FLAG_INITIATOR                  0x00000001

#define CTX_IS_INITIATOR(ctx)               (((ctx)->flags & CTX_FLAG_INITIATOR) != 0)

enum eap_gss_state {
    EAP_STATE_AUTHENTICATE = 0,
#if 0
    EAP_STATE_KEY_TRANSPORT,
    EAP_STATE_SECURE_ASSOCIATION,
#endif
    EAP_STATE_GSS_CHANNEL_BINDINGS,
    EAP_STATE_ESTABLISHED
};

#define CTX_IS_ESTABLISHED(ctx)             ((ctx)->state == EAP_STATE_ESTABLISHED)

/* Initiator context flags */
#define CTX_FLAG_EAP_SUCCESS                0x00010000
#define CTX_FLAG_EAP_RESTART                0x00020000
#define CTX_FLAG_EAP_FAIL                   0x00040000
#define CTX_FLAG_EAP_RESP                   0x00080000
#define CTX_FLAG_EAP_NO_RESP                0x00100000
#define CTX_FLAG_EAP_REQ                    0x00200000
#define CTX_FLAG_EAP_PORT_ENABLED           0x00400000
#define CTX_FLAG_EAP_ALT_ACCEPT             0x00800000
#define CTX_FLAG_EAP_ALT_REJECT             0x01000000

struct eap_gss_initiator_ctx {
    unsigned int idleWhile;
    struct eap_peer_config eapPeerConfig;
    struct eap_sm *eap;
    struct wpabuf reqData;
};

struct eap_gss_acceptor_ctx {
    struct eap_eapol_interface *eapPolInterface;
    void *tlsContext;
    struct eap_sm *eap;
};

struct gss_ctx_id_struct {
    GSSEAP_MUTEX mutex;
    enum eap_gss_state state;
    OM_uint32 flags;
    OM_uint32 gssFlags;
    gss_OID mechanismUsed;
    krb5_enctype encryptionType;
    krb5_keyblock rfc3961Key;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    time_t expiryTime;
    uint64_t sendSeq, recvSeq;
    void *seqState;
    union {
        struct eap_gss_initiator_ctx initiator;
        #define initiatorCtx         ctxU.initiator
        struct eap_gss_acceptor_ctx  acceptor;
        #define acceptorCtx          ctxU.acceptor
    } ctxU;
};

#define TOK_FLAG_SENDER_IS_ACCEPTOR         0x01
#define TOK_FLAG_WRAP_CONFIDENTIAL          0x02
#define TOK_FLAG_ACCEPTOR_SUBKEY            0x04

#define KEY_USAGE_ACCEPTOR_SEAL             22
#define KEY_USAGE_ACCEPTOR_SIGN             23
#define KEY_USAGE_INITIATOR_SEAL            24
#define KEY_USAGE_INITIATOR_SIGN            25
#define KEY_USAGE_CHANNEL_BINDINGS          64

/* wrap_iov.c */
OM_uint32
gssEapWrapOrGetMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int conf_req_flag,
                   int *conf_state,
                   gss_iov_buffer_desc *iov,
                   int iov_count,
                   enum gss_eap_token_type toktype);

OM_uint32
gssEapUnwrapOrVerifyMIC(OM_uint32 *minor_status,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_eap_token_type toktype);


#endif /* _GSSAPIP_EAP_H_ */
