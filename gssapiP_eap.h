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
#include <time.h>

/* GSS includes */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "gssapi_eap.h"

/* EAP includes */
#define IEEE8021X_EAPOL 1

#include <common.h>
#include <eap_peer/eap.h>
#include <eap_peer/eap_config.h>
#include <wpabuf.h>

/* Kerberos includes */
#include <krb5.h>

struct gss_name_struct {
    OM_uint32 flags;
    krb5_principal kerberosName;
    void *aaa;
    void *assertion;
};

#define CRED_FLAG_INITIATOR                 0x00000001
#define CRED_FLAG_ACCEPTOR                  0x00000002
#define CRED_FLAG_DEFAULT_IDENTITY          0x00000004
#define CRED_FLAG_PASSWORD                  0x00000008

struct gss_cred_id_struct {
    OM_uint32 flags;
    gss_name_t name;
    gss_buffer_desc password;
    time_t expiryTime;
};

#define CTX_FLAG_INITIATOR                  0x00000001

#define CTX_IS_INITIATOR(ctx)               (((ctx)->flags & CTX_FLAG_INITIATOR) != 0)

enum eap_gss_state {
    EAP_STATE_AUTHENTICATE = 1,
    EAP_STATE_KEY_TRANSPORT,
    EAP_STATE_SECURE_ASSOCIATION,
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
    struct wpabuf *eapReqData;
    unsigned int idleWhile;
    struct eap_peer_config eapConfig;
    struct eap_sm *eap;
};

/* Acceptor context flags */
struct eap_gss_acceptor_ctx {
};

struct gss_ctx_id_struct {
    enum eap_gss_state state;
    OM_uint32 flags;
    OM_uint32 gssFlags;
    krb5_context kerberosCtx;
    gss_OID mechanismUsed;
    krb5_enctype encryptionType;
    krb5_cksumtype checksumType;
    krb5_keyblock *encryptionKey;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    time_t expiryTime;
    union {
        struct eap_gss_initiator_ctx initiator;
        #define initiatorCtx         ctxU.initiator
        struct eap_gss_acceptor_ctx  acceptor;
        #define acceptorCtx          ctxU.acceptor
    } ctxU;
    uint64_t sendSeq, recvSeq;
    void *seqState;
};

#define TOK_FLAG_SENDER_IS_ACCEPTOR         0x01
#define TOK_FLAG_WRAP_CONFIDENTIAL          0x02
#define TOK_FLAG_ACCEPTOR_SUBKEY            0x04

enum gss_eap_token_type {
    TOK_TYPE_MIC     = 0x0404,
    TOK_TYPE_WRAP    = 0x0504,
    TOK_TYPE_DELETE  = 0x0405
};

/* Helper APIs */
OM_uint32 gssEapAllocContext(OM_uint32 *minor, gss_ctx_id_t *pCtx);
OM_uint32 gssEapReleaseContext(OM_uint32 *minor, gss_ctx_id_t *pCtx);

OM_uint32 gssEapAllocName(OM_uint32 *minor, gss_name_t *pName);
OM_uint32 gssEapReleaseName(OM_uint32 *minor, gss_name_t *pName);

OM_uint32 gssEapAllocCred(OM_uint32 *minor, gss_cred_id_t *pCred);
OM_uint32 gssEapReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred);

/* Kerberos token services */
#define KRB_USAGE_ACCEPTOR_SEAL             22
#define KRB_USAGE_ACCEPTOR_SIGN             23
#define KRB_USAGE_INITIATOR_SEAL            24
#define KRB_USAGE_INITIATOR_SIGN            25

#if 0
#define KRB_KEYTYPE(key)                    ((key)->keytype)
#else
#define KRB_KEYTYPE(key)                    ((key)->enctype)
#endif

/* util_crypt.c */
int
gssEapEncrypt(krb5_context context, int dce_style, size_t ec,
              size_t rrc, krb5_keyblock *key, int usage, krb5_pointer iv,
              gss_iov_buffer_desc *iov, int iov_count);

int
gssEapDecrypt(krb5_context context, int dce_style, size_t ec,
              size_t rrc, krb5_keyblock *key, int usage, krb5_pointer iv,
              gss_iov_buffer_desc *iov, int iov_count);

krb5_cryptotype
gssEapTranslateCryptoFlag(OM_uint32 type);

gss_iov_buffer_t
gssEapLocateIov(gss_iov_buffer_desc *iov,
                int iov_count,
                OM_uint32 type);

void
gssEapIovMessageLength(gss_iov_buffer_desc *iov,
                       int iov_count,
                       size_t *data_length,
                       size_t *assoc_data_length);

void
gssEapReleaseIov(gss_iov_buffer_desc *iov, int iov_count);

int
gssEapIsIntegrityOnly(gss_iov_buffer_desc *iov, int iov_count);

int
gssEapAllocIov(gss_iov_buffer_t iov, size_t size);

/* util_cksum.c */
int
gssEapSign(krb5_context context,
           krb5_cksumtype type,
           size_t rrc,
           krb5_keyblock *key,
           krb5_keyusage sign_usage,
           gss_iov_buffer_desc *iov,
           int iov_count);

int
gssEapVerify(krb5_context context,
             krb5_cksumtype type,
             size_t rrc,  
             krb5_keyblock *key,
             krb5_keyusage sign_usage,
             gss_iov_buffer_desc *iov,
             int iov_count,
             int *valid);

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

/* Helper macros */
#define GSSEAP_CALLOC(count, size)      (calloc((count), (size)))
#define GSSEAP_FREE(ptr)                (free((ptr)))
#define GSSEAP_MALLOC(size)             (malloc((size)))
#define GSSEAP_REALLOC(ptr, size)       (realloc((ptr), (size)))

#define GSSEAP_NOT_IMPLEMENTED          do {            \
        assert(0 && "not implemented");                 \
        *minor = ENOSYS;                                \
        return GSS_S_FAILURE;                           \
    } while (0)

#endif /* _GSSAPIP_EAP_H_ */

