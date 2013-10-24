/*
 * Copyright (c) 2013 PADL Software Pty Ltd.
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
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the gss_browserid software
 *    and any accompanying software that uses the gss_browserid software.
 *    The source code must either be included in the distribution or be
 *    available for no more than the cost of distribution plus a nominal
 *    fee, and must be freely redistributable under reasonable conditions.
 *    For an executable file, complete source code means the source code
 *    for all modules it contains. It does not include source code for
 *    modules or files that typically accompany the major components of
 *    the operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL PADL SOFTWARE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
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

#ifndef _GSSAPIP_BID_H_
#define _GSSAPIP_BID_H_ 1

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
#endif

/* GSS headers */
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#ifdef HAVE_HEIMDAL_VERSION
typedef struct gss_any *gss_any_t;
#else
#include <gssapi/gssapi_ext.h>
#endif
#include "gssapi_browserid.h"

#ifndef HAVE_GSS_INQUIRE_ATTRS_FOR_MECH
typedef const gss_OID_desc *gss_const_OID;
#endif

/* Kerberos headers */
#include <krb5.h>

#include <jansson.h>
#include <browserid.h>
#include <bid_private.h> /* XXX */

#include "gssbrowserid_err.h"
#include "libbrowserid_err.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NAME_FLAG_EMAIL                     0x00000001
#define NAME_FLAG_SERVICE                   0x00000002
#define NAME_FLAG_COMPOSITE                 0x00000004

struct BIDGSSSAMLAttributeContext;
struct BIDGSSAttributeContext;

#ifdef HAVE_HEIMDAL_VERSION
struct gss_name_t_desc_struct
#else
struct gss_name_struct
#endif
{
    GSSBID_MUTEX mutex; /* mutex protects attrCtx */
    OM_uint32 flags;
    gss_OID mechanismUsed; /* this is immutable */
    krb5_principal krbPrincipal; /* this is immutable */
#ifdef GSSBID_ENABLE_ACCEPTOR
    struct BIDGSSAttributeContext *attrCtx;
#endif
};

#define CRED_FLAG_INITIATE                  0x00010000
#define CRED_FLAG_ACCEPT                    0x00020000
#define CRED_FLAG_ASSERTION                 0x00040000
#define CRED_FLAG_DEFAULT_CCACHE            0x00080000
#define CRED_FLAG_RESOLVED                  0x00100000
#define CRED_FLAG_TARGET                    0x00200000
#define CRED_FLAG_PUBLIC_MASK               0x0000FFFF

#ifdef HAVE_HEIMDAL_VERSION
struct gss_cred_id_t_desc_struct
#else
struct gss_cred_id_struct
#endif
{
    GSSBID_MUTEX mutex;
    OM_uint32 flags;
    gss_name_t name;
    gss_name_t target; /* for initiator */
    gss_buffer_desc assertion;
    gss_OID_set mechanisms;
    time_t expiryTime;
    BIDContext bidContext;
    BIDTicketCache bidTicketCache;
    BIDReplayCache bidReplayCache;
};

#define CTX_FLAG_INITIATOR                  0x00000001
#define CTX_FLAG_REAUTH                     0x00000002
#define CTX_FLAG_CAN_MUTUAL_AUTH            0x00000004
#define CTX_FLAG_EXTRA_ROUND_TRIP           0x00000008

#define CTX_IS_INITIATOR(ctx)               (((ctx)->flags & CTX_FLAG_INITIATOR) != 0)

#define CTX_IS_ESTABLISHED(ctx)             ((ctx)->state == GSSBID_STATE_ESTABLISHED)

#ifdef HAVE_HEIMDAL_VERSION
struct gss_ctx_id_t_desc_struct
#else
struct gss_ctx_id_struct
#endif
{
    GSSBID_MUTEX mutex;
    enum gss_bid_state state;
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
    BIDContext bidContext;
    BIDIdentity bidIdentity;
    struct gss_bid_initiator_ctx {
        gss_buffer_desc serverSubject;
        gss_buffer_desc serverHash;
        gss_buffer_desc serverCert;
    } initiatorCtx;
};

#define TOK_FLAG_SENDER_IS_ACCEPTOR         0x01
#define TOK_FLAG_WRAP_CONFIDENTIAL          0x02
#define TOK_FLAG_ACCEPTOR_SUBKEY            0x04

#define KEY_USAGE_ACCEPTOR_SEAL             22
#define KEY_USAGE_ACCEPTOR_SIGN             23
#define KEY_USAGE_INITIATOR_SEAL            24
#define KEY_USAGE_INITIATOR_SIGN            25

/* accept_sec_context.c */

OM_uint32
gssBidAcceptSecContext(OM_uint32 *minor,
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
gssBidInitSecContext(OM_uint32 *minor,
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
gssBidWrapOrGetMIC(OM_uint32 *minor,
                   gss_ctx_id_t ctx,
                   int conf_req_flag,
                   int *conf_state,
                   gss_iov_buffer_desc *iov,
                   int iov_count,
                   enum gss_bid_token_type toktype);

OM_uint32
gssBidUnwrapOrVerifyMIC(OM_uint32 *minor_status,
                        gss_ctx_id_t ctx,
                        int *conf_state,
                        gss_qop_t *qop_state,
                        gss_iov_buffer_desc *iov,
                        int iov_count,
                        enum gss_bid_token_type toktype);

OM_uint32
gssBidWrapIovLength(OM_uint32 *minor,
                    gss_ctx_id_t ctx,
                    int conf_req_flag,
                    gss_qop_t qop_req,
                    int *conf_state,
                    gss_iov_buffer_desc *iov,
                    int iov_count);
OM_uint32
gssBidWrap(OM_uint32 *minor,
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
gssBidSaveStatusInfo(OM_uint32 minor, const char *format, ...);

OM_uint32
gssBidDisplayStatus(OM_uint32 *minor,
                    OM_uint32 status_value,
                    gss_buffer_t status_string);

#define IS_BROWSERID_ERROR(err)         (((int32_t)err) >= ERROR_TABLE_BASE_lbid && \
                                         ((int32_t)err) <= ERROR_TABLE_BASE_lbid + BID_S_UNKNOWN_ERROR_CODE)

/* exchange_meta_data.c */
OM_uint32 GSSAPI_CALLCONV
gssBidExchangeMetaData(OM_uint32 *minor,
                       gss_const_OID mech,
                       gss_cred_id_t cred,
                       gss_ctx_id_t *ctx,
                       const gss_name_t name,
                       OM_uint32 req_flags,
                       gss_const_buffer_t meta_data);

/* export_sec_context.c */
OM_uint32
gssBidExportSecContext(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_buffer_t token);

/* import_sec_context.c */
OM_uint32
gssBidImportContext(OM_uint32 *minor,
                    gss_buffer_t token,
                    gss_ctx_id_t ctx);

/* inquire_sec_context_by_oid.c */
#define NEGOEX_INITIATOR_SALT      "gss-browserid-negoex-initiator"
#define NEGOEX_INITIATOR_SALT_LEN  (sizeof(NEGOEX_INITIATOR_SALT) - 1)

#define NEGOEX_ACCEPTOR_SALT       "gss-browserid-negoex-acceptor"
#define NEGOEX_ACCEPTOR_SALT_LEN   (sizeof(NEGOEX_ACCEPTOR_SALT) - 1)

/* pseudo_random.c */
OM_uint32
gssBidPseudoRandom(OM_uint32 *minor,
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
gssBidQueryMetaData(OM_uint32 *minor,
                    gss_const_OID mech GSSBID_UNUSED,
                    gss_cred_id_t cred,
                    gss_ctx_id_t *context_handle,
                    const gss_name_t name,
                    OM_uint32 req_flags GSSBID_UNUSED,
                    gss_buffer_t meta_data);

void
gssBidFinalize(void);

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPIP_BID_H_ */
