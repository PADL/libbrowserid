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

#ifndef _GSSAPIP_EAP_H_
#define _GSSAPIP_EAP_H_ 1

#include "config.h"

#ifdef HAVE_HEIMDAL_VERSION
#define KRB5_DEPRECATED         /* so we can use krb5_free_unparsed_name() */
#endif

#include <assert.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef WIN32
#ifndef MAXHOSTNAMELEN
# include <WinSock2.h>
# define MAXHOSTNAMELEN NI_MAXHOST
#endif
#ifdef HAVE_HEIMDAL_VERSION
#endif
#endif

/* GSS headers */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#ifdef HAVE_HEIMDAL_VERSION
typedef struct gss_any *gss_any_t;
#else
#include <gssapi/gssapi_ext.h>
#endif
#include "gssapi_eap.h"

#ifndef HAVE_GSS_INQUIRE_ATTRS_FOR_MECH
typedef const gss_OID_desc *gss_const_OID;
#endif

/* Kerberos headers */
#include <krb5.h>

/* EAP headers */
#include <includes.h>
#include <common.h>
#include <eap_peer/eap.h>
#include <eap_peer/eap_config.h>
#include <eap_peer/eap_methods.h>
#include <eap_common/eap_common.h>
#include <wpabuf.h>

#ifdef GSSEAP_ENABLE_ACCEPTOR
/* libradsec headers */
#include <radsec/radsec.h>
#include <radsec/request.h>
#include <radsec/radius.h>
#endif

#include "gsseap_err.h"
#include "radsec_err.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These name flags are informative and not actually used by anything yet */
#define NAME_FLAG_NAI                       0x00000001
#define NAME_FLAG_SERVICE                   0x00000002
#define NAME_FLAG_COMPOSITE                 0x00000004

struct gss_eap_saml_attr_ctx;
struct gss_eap_attr_ctx;

#ifdef HAVE_HEIMDAL_VERSION
struct gss_name_t_desc_struct
#else
struct gss_name_struct
#endif
{
    GSSEAP_MUTEX mutex; /* mutex protects attrCtx */
    OM_uint32 flags;
    gss_OID mechanismUsed; /* this is immutable */
    krb5_principal krbPrincipal; /* this is immutable */
#ifdef GSSEAP_ENABLE_ACCEPTOR
    struct gss_eap_attr_ctx *attrCtx;
#endif
};

#define CRED_FLAG_INITIATE                  0x00010000
#define CRED_FLAG_ACCEPT                    0x00020000
#define CRED_FLAG_PASSWORD                  0x00040000
#define CRED_FLAG_DEFAULT_CCACHE            0x00080000
#define CRED_FLAG_RESOLVED                  0x00100000
#define CRED_FLAG_TARGET                    0x00200000
#define CRED_FLAG_CERTIFICATE               0x00400000
#define CRED_FLAG_CONFIG_BLOB               0x00800000
#define CRED_FLAG_PUBLIC_MASK               0x0000FFFF

#ifdef HAVE_HEIMDAL_VERSION
struct gss_cred_id_t_desc_struct
#else
struct gss_cred_id_struct
#endif
{
    GSSEAP_MUTEX mutex;
    OM_uint32 flags;
    gss_name_t name;
    gss_name_t target; /* for initiator */
    gss_buffer_desc password;
    gss_OID_set mechanisms;
    time_t expiryTime;
    gss_buffer_desc radiusConfigFile;
    gss_buffer_desc radiusConfigStanza;
    gss_buffer_desc caCertificate;
    gss_buffer_desc subjectNameConstraint;
    gss_buffer_desc subjectAltNameConstraint;
    gss_buffer_desc clientCertificate;
    gss_buffer_desc privateKey;
#if defined(GSSEAP_ENABLE_REAUTH) && !defined(GSSEAP_SSP)
    krb5_ccache krbCredCache;
    gss_cred_id_t reauthCred;
#endif
#ifdef GSSEAP_SSP
    volatile ULONG SspFlags;        /* extra flags */
    volatile LUID LogonId;          /* logon session */
    volatile ULONG ProcessID;       /* PID (0 for all processes in session) */
    PCCERT_CONTEXT CertContext;     /* optional certificate context */
    LIST_ENTRY ListEntry;           /* list pointer for credentials list */
    volatile LONG RefCount;         /* reference count */
#endif
};

#define CTX_FLAG_INITIATOR                  0x00000001
#define CTX_FLAG_KRB_REAUTH                 0x00000002
#define CTX_FLAG_CHANNEL_BINDINGS_VERIFIED  0x00000004
#define CTX_FLAG_SERVER_PROBE               0x00000008

#define CTX_IS_INITIATOR(ctx)               (((ctx)->flags & CTX_FLAG_INITIATOR) != 0)

#define CTX_IS_ESTABLISHED(ctx)             ((ctx)->state == GSSEAP_STATE_ESTABLISHED)

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
#define CTX_FLAG_EAP_MASK                   0xFFFF0000

#define CONFIG_BLOB_CLIENT_CERT             0
#define CONFIG_BLOB_PRIVATE_KEY             1
#define CONFIG_BLOB_MAX                     2

struct gss_eap_initiator_ctx {
    unsigned int idleWhile;
    struct eap_peer_config eapPeerConfig;
    struct eap_sm *eap;
    struct wpabuf reqData;
    struct wpa_config_blob configBlobs[CONFIG_BLOB_MAX];
};

#ifdef GSSEAP_ENABLE_ACCEPTOR
struct gss_eap_acceptor_ctx {
    struct rs_context *radContext;
    struct rs_connection *radConn;
    char *radServer;
    gss_buffer_desc state;
    rs_avp *vps;
};
#endif

#ifdef HAVE_HEIMDAL_VERSION
struct gss_ctx_id_t_desc_struct
#else
struct gss_ctx_id_struct
#endif
{
    GSSEAP_MUTEX mutex;
    enum gss_eap_state state;
    OM_uint32 flags;
    OM_uint32 gssFlags;
    gss_OID mechanismUsed;
    krb5_cksumtype checksumType;
    krb5_enctype encryptionType;
    krb5_keyblock rfc3961Key;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    time_t expiryTime;
    uint64_t sendSeq, recvSeq;
    void *seqState;
    gss_cred_id_t cred;
    union {
        struct gss_eap_initiator_ctx initiator;
        #define initiatorCtx         ctxU.initiator
#ifdef GSSEAP_ENABLE_ACCEPTOR
        struct gss_eap_acceptor_ctx  acceptor;
        #define acceptorCtx          ctxU.acceptor
#endif
#ifdef GSSEAP_ENABLE_REAUTH
        gss_ctx_id_t                 reauth;
        #define reauthCtx            ctxU.reauth
#endif
    } ctxU;
    const struct gss_eap_token_buffer_set *inputTokens;
    const struct gss_eap_token_buffer_set *outputTokens;
#ifdef GSSEAP_SSP
    volatile LUID LogonId;          /* logon session */
    HANDLE TokenHandle;             /* token for acceptor contexts */
    UNICODE_STRING AccountName;     /* mapped account from LSA */
    ULONG UserFlags;                /* flags from profile */
    LSA_SEC_HANDLE LsaHandle;       /* handle for user-mode contexts */
    PVOID ProfileBuffer;            /* profile buffer */
    ULONG ProfileBufferLength;      /* profile buffer length */
    NTSTATUS SubStatus;             /* logon substatus */
    LIST_ENTRY ListEntry;           /* list pointer for user-mode contexts */
    volatile LONG RefCount;         /* reference count */
#endif
};

#define TOK_FLAG_SENDER_IS_ACCEPTOR         0x01
#define TOK_FLAG_WRAP_CONFIDENTIAL          0x02
#define TOK_FLAG_ACCEPTOR_SUBKEY            0x04

#define KEY_USAGE_ACCEPTOR_SEAL             22
#define KEY_USAGE_ACCEPTOR_SIGN             23
#define KEY_USAGE_INITIATOR_SEAL            24
#define KEY_USAGE_INITIATOR_SIGN            25

#define KEY_USAGE_GSSEAP_CHBIND_MIC         60
#define KEY_USAGE_GSSEAP_ACCTOKEN_MIC       61
#define KEY_USAGE_GSSEAP_INITOKEN_MIC       62

/* accept_sec_context.c */
OM_uint32
gssEapAcceptSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t input_token,
                       gss_channel_bindings_t input_chan_bindings,
                       gss_name_t *src_name,
                       gss_OID *mech_type,
                       gss_buffer_t output_token,
                       OM_uint32 *ret_flags,
                       OM_uint32 *time_rec,
                       gss_cred_id_t *delegated_cred_handle);

/* init_sec_context.c */
OM_uint32
gssEapInitSecContext(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     gss_ctx_id_t ctx,
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

OM_uint32
gssEapWrapIovLength(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count);
OM_uint32
gssEapWrap(OM_uint32 *minor,
           gss_ctx_id_t ctx,
           int conf_req_flag,
           gss_qop_t qop_req,
           gss_buffer_t input_message_buffer,
           int *conf_state,
           gss_buffer_t output_message_buffer);

unsigned char
rfc4121Flags(gss_ctx_id_t ctx, int receiving);

/* display_status.c */
void
gssEapSaveStatusInfo(OM_uint32 minor, const char *format, ...);

OM_uint32
gssEapDisplayStatus(OM_uint32 *minor,
                    OM_uint32 status_value,
                    gss_buffer_t status_string);

#define IS_WIRE_ERROR(err)              ((err) > GSSEAP_RESERVED && \
                                         (err) <= GSSEAP_RADIUS_PROT_FAILURE)

#ifdef GSSEAP_ENABLE_ACCEPTOR
#define IS_RADIUS_ERROR(err)            ((err) >= ERROR_TABLE_BASE_rse && \
                                         (err) <= ERROR_TABLE_BASE_rse + RSE_MAX)
#else
#define IS_RADIUS_ERROR(err)            (0)
#endif

/* exchange_meta_data.c */
OM_uint32 GSSAPI_CALLCONV
gssEapExchangeMetaData(OM_uint32 *minor,
                       gss_const_OID mech,
                       gss_cred_id_t cred,
                       gss_ctx_id_t *ctx,
                       const gss_name_t name,
                       OM_uint32 req_flags,
                       gss_const_buffer_t meta_data);

/* export_sec_context.c */
OM_uint32
gssEapExportSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_buffer_t token);

/* import_sec_context.c */
OM_uint32
gssEapImportContext(OM_uint32 *minor,
                    gss_buffer_t token,
                    gss_ctx_id_t ctx);

/* inquire_sec_context_by_oid.c */
#define NEGOEX_INITIATOR_SALT      "gss-eap-negoex-initiator"
#define NEGOEX_INITIATOR_SALT_LEN  (sizeof(NEGOEX_INITIATOR_SALT) - 1)

#define NEGOEX_ACCEPTOR_SALT       "gss-eap-negoex-acceptor"
#define NEGOEX_ACCEPTOR_SALT_LEN   (sizeof(NEGOEX_ACCEPTOR_SALT) - 1)

/* pseudo_random.c */
OM_uint32
gssEapPseudoRandom(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int prf_key,
                   const gss_buffer_t prf_in,
                   gss_buffer_t prf_out);

/* query_mechanism_info.c */
OM_uint32
gssQueryMechanismInfo(OM_uint32 *minor,
                      gss_const_OID mech_oid,
                      unsigned char auth_scheme[16]);

/* query_meta_data.c */
OM_uint32
gssEapQueryMetaData(OM_uint32 *minor,
                    gss_const_OID mech GSSEAP_UNUSED,
                    gss_cred_id_t cred,
                    gss_ctx_id_t *context_handle,
                    const gss_name_t name,
                    OM_uint32 req_flags GSSEAP_UNUSED,
                    gss_buffer_t meta_data);

/* eap_mech.c */
OM_uint32
gssEapInitiatorInit(OM_uint32 *minor);

void
gssEapFinalize(void);

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPIP_EAP_H_ */
