/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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
/*
 * Portions Copyright 2003-2010 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * Utility functions.
 */

#ifndef _UTIL_H_
#define _UTIL_H_ 1

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <string.h>
#include <errno.h>

#include <krb5.h>

#ifdef WIN32
# ifndef __cplusplus
# define inline __inline
# endif
#define snprintf _snprintf
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MIN
#define MIN(_a,_b)  ((_a)<(_b)?(_a):(_b))
#endif

#if !defined(WIN32) && !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#define GSSBID_UNUSED __attribute__ ((__unused__))
#else
#define GSSBID_UNUSED
#endif

/* util_buffer.c */
OM_uint32
makeStringBuffer(OM_uint32 *minor,
                 const char *string,
                 gss_buffer_t buffer);

#define makeStringBufferOrCleanup(src, dst)             \
    do {                                                \
        major = makeStringBuffer((minor), (src), (dst));\
        if (GSS_ERROR(major))                           \
            goto cleanup;                               \
    } while (0)

OM_uint32
bufferToString(OM_uint32 *minor,
               const gss_buffer_t buffer,
               char **pString);

OM_uint32
duplicateBuffer(OM_uint32 *minor,
                const gss_buffer_t src,
                gss_buffer_t dst);

#define duplicateBufferOrCleanup(src, dst)              \
    do {                                                \
        major = duplicateBuffer((minor), (src), (dst)); \
        if (GSS_ERROR(major))                           \
            goto cleanup;                               \
    } while (0)

static inline int
bufferEqual(const gss_buffer_t b1, const gss_buffer_t b2)
{
    return (b1->length == b2->length &&
            memcmp(b1->value, b2->value, b2->length) == 0);
}

static inline int
bufferEqualString(const gss_buffer_t b1, const char *s)
{
    gss_buffer_desc b2;

    b2.length = strlen(s);
    b2.value = (char *)s;

    return bufferEqual(b1, &b2);
}

/* util_cksum.c */
int
gssBidSign(krb5_context context,
           krb5_cksumtype type,
           size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
           krb5_crypto crypto,
#else
           krb5_keyblock *key,
#endif
           krb5_keyusage sign_usage,
           gss_iov_buffer_desc *iov,
           int iov_count);

int
gssBidVerify(krb5_context context,
             krb5_cksumtype type,
             size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
             krb5_crypto crypto,
#else
             krb5_keyblock *key,
#endif
             krb5_keyusage sign_usage,
             gss_iov_buffer_desc *iov,
             int iov_count,
             int *valid);

/* util_context.c */
#define BROWSERID_EXPORT_CONTEXT_V1        1

#define GSSBID_CONFIG_FILE                 SYSCONFDIR "/gss/browserid.json"

enum gss_bid_token_type {
    TOK_TYPE_NONE                    = 0x0000,  /* no token */
    TOK_TYPE_MIC                     = 0x0404,  /* RFC 4121 MIC token */
    TOK_TYPE_WRAP                    = 0x0504,  /* RFC 4121 wrap token */
    TOK_TYPE_EXPORT_NAME             = 0x0401,  /* RFC 2743 exported name */
    TOK_TYPE_EXPORT_NAME_COMPOSITE   = 0x0402,  /* exported composite name */
    TOK_TYPE_INITIATOR_CONTEXT       = 0xB1D1,  /* initiator-sent context token */
    TOK_TYPE_ACCEPTOR_CONTEXT        = 0xB1D2,  /* acceptor-sent context token */
    TOK_TYPE_DELETE_CONTEXT          = 0xB1D3,  /* RFC 2743 delete context */
};

#define GSSBID_WIRE_FLAGS_MASK          ( GSS_C_MUTUAL_FLAG             | \
                                          GSS_C_DCE_STYLE               | \
                                          GSS_C_IDENTIFY_FLAG           | \
                                          GSS_C_EXTENDED_ERROR_FLAG       )

OM_uint32 gssBidAllocContext(OM_uint32 *minor,
                             int isInitiator,
                             gss_const_OID mech,
                             gss_ctx_id_t *pCtx);
OM_uint32 gssBidReleaseContext(OM_uint32 *minor, gss_ctx_id_t *pCtx);

OM_uint32
gssBidVerifyToken(OM_uint32 *minor,
                  const gss_buffer_t inputToken,
                  enum gss_bid_token_type *actualToken,
                  gss_buffer_t innerInputToken,
                  gss_OID *pMechanismUsed);

OM_uint32
gssBidMakeToken(OM_uint32 *minor,
                gss_ctx_id_t ctx,
                const gss_buffer_t innerToken,
                enum gss_bid_token_type tokenType,
                gss_buffer_t outputToken);

OM_uint32
gssBidContextReady(OM_uint32 *minor, gss_ctx_id_t ctx, gss_cred_id_t cred);;

OM_uint32
gssBidContextTime(OM_uint32 *minor,
                  gss_ctx_id_t context_handle,
                  OM_uint32 *time_rec);

/* util_cred.c */
OM_uint32 gssBidAllocCred(OM_uint32 *minor, gss_cred_id_t *pCred);
OM_uint32 gssBidReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred);

gss_OID
gssBidPrimaryMechForCred(gss_cred_id_t cred);

OM_uint32
gssBidAcquireCred(OM_uint32 *minor,
                  const gss_name_t desiredName,
                  OM_uint32 timeReq,
                  const gss_OID_set desiredMechs,
                  int cred_usage,
                  gss_cred_id_t *pCred,
                  gss_OID_set *pActualMechs,
                  OM_uint32 *timeRec);

OM_uint32
gssBidSetCredAssertion(OM_uint32 *minor,
                       gss_cred_id_t cred,
                       const gss_buffer_t password);

OM_uint32
gssBidSetCredService(OM_uint32 *minor,
                     gss_cred_id_t cred,
                     const gss_name_t target);

OM_uint32
gssBidSetCredTicketCacheName(OM_uint32 *minor,
                             gss_cred_id_t cred,
                             const gss_buffer_t cacheName);

OM_uint32
gssBidSetCredReplayCacheName(OM_uint32 *minor,
                             gss_cred_id_t cred,
                             const gss_buffer_t cacheName);

OM_uint32
gssBidResolveInitiatorCred(OM_uint32 *minor,
                           const gss_cred_id_t cred,
                           gss_ctx_id_t ctx,
                           const gss_name_t target,
                           OM_uint32 req_flags,
                           const gss_channel_bindings_t channelBindings,
                           gss_cred_id_t *resolvedCred);

int gssBidCredAvailable(gss_cred_id_t cred, gss_OID mech);

OM_uint32
gssBidInquireCred(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_name_t *name,
                  OM_uint32 *pLifetime,
                  gss_cred_usage_t *cred_usage,
                  gss_OID_set *mechanisms);

/* util_crypt.c */
int
gssBidEncrypt(krb5_context context, int dce_style, size_t ec,
              size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
              krb5_crypto crypto,
#else
              krb5_keyblock *key,
#endif
              int usage,
              gss_iov_buffer_desc *iov, int iov_count);

int
gssBidDecrypt(krb5_context context, int dce_style, size_t ec,
              size_t rrc,
#ifdef HAVE_HEIMDAL_VERSION
              krb5_crypto crypto,
#else
              krb5_keyblock *key,
#endif
              int usage,
              gss_iov_buffer_desc *iov, int iov_count);

int
gssBidMapCryptoFlag(OM_uint32 type);

gss_iov_buffer_t
gssBidLocateIov(gss_iov_buffer_desc *iov,
                int iov_count,
                OM_uint32 type);

void
gssBidIovMessageLength(gss_iov_buffer_desc *iov,
                       int iov_count,
                       size_t *data_length,
                       size_t *assoc_data_length);

void
gssBidReleaseIov(gss_iov_buffer_desc *iov, int iov_count);

int
gssBidIsIntegrityOnly(gss_iov_buffer_desc *iov, int iov_count);

int
gssBidAllocIov(gss_iov_buffer_t iov, size_t size);

OM_uint32
gssBidDeriveRfc3961Key(OM_uint32 *minor,
                       const unsigned char *key,
                       size_t keyLength,
                       krb5_enctype enctype,
                       krb5_keyblock *pKey);

/* util_krb.c */

#ifndef KRB_MALLOC
/*
 * If your Kerberos library uses a different allocator to your
 * GSS mechanism glue, then you might wish to define these in
 * config.h or elsewhere. This should eventually go away when
 * we no longer need to allocate memory that is freed by the
 * Kerberos library.
 */
#define KRB_CALLOC                      calloc
#define KRB_MALLOC                      malloc
#define KRB_FREE                        free
#define KRB_REALLOC                     realloc
#endif /* KRB_MALLOC */

#ifdef HAVE_HEIMDAL_VERSION

#define KRB_TIME_FOREVER        ((time_t)~0L)

#define KRB_KEY_TYPE(key)       ((key)->keytype)
#define KRB_KEY_DATA(key)       ((key)->keyvalue.data)
#define KRB_KEY_LENGTH(key)     ((key)->keyvalue.length)

#define KRB_PRINC_LENGTH(princ) ((princ)->name.name_string.len)
#define KRB_PRINC_TYPE(princ)   ((princ)->name.name_type)
#define KRB_PRINC_NAME(princ)   ((princ)->name.name_string.val)
#define KRB_PRINC_REALM(princ)  ((princ)->realm)

#define KRB_KT_ENT_KEYBLOCK(e)  (&(e)->keyblock)
#define KRB_KT_ENT_FREE(c, e)   krb5_kt_free_entry((c), (e))

#define KRB_CRYPTO_CONTEXT(ctx) (krbCrypto)

#define KRB_DATA_INIT(d)        krb5_data_zero((d))

#define KRB_CHECKSUM_TYPE(c)    ((c)->cksumtype)
#define KRB_CHECKSUM_LENGTH(c)  ((c)->checksum.length)
#define KRB_CHECKSUM_DATA(c)    ((c)->checksum.data)

#define KRB_CHECKSUM_INIT(cksum, type, d)      do { \
        (cksum)->cksumtype = (type);                \
        (cksum)->checksum.length = (d)->length;     \
        (cksum)->checksum.data = (d)->value;        \
    } while (0)

#else

#define KRB_TIME_FOREVER        KRB5_INT32_MAX

#define KRB_KEY_TYPE(key)       ((key)->enctype)
#define KRB_KEY_DATA(key)       ((key)->contents)
#define KRB_KEY_LENGTH(key)     ((key)->length)

#define KRB_PRINC_LENGTH(princ) (krb5_princ_size(NULL, (princ)))
#define KRB_PRINC_TYPE(princ)   (krb5_princ_type(NULL, (princ)))
#define KRB_PRINC_NAME(princ)   (krb5_princ_name(NULL, (princ)))
#define KRB_PRINC_REALM(princ)  (krb5_princ_realm(NULL, (princ)))

#define KRB_KT_ENT_KEYBLOCK(e)  (&(e)->key)
#define KRB_KT_ENT_FREE(c, e)   krb5_free_keytab_entry_contents((c), (e))

#define KRB_CRYPTO_CONTEXT(ctx) (&(ctx)->rfc3961Key)

#define KRB_DATA_INIT(d)        do {        \
        (d)->magic = KV5M_DATA;             \
        (d)->length = 0;                    \
        (d)->data = NULL;                   \
    } while (0)

#define KRB_CHECKSUM_TYPE(c)    ((c)->checksum_type)
#define KRB_CHECKSUM_LENGTH(c)  ((c)->length)
#define KRB_CHECKSUM_DATA(c)    ((c)->contents)

#define KRB_CHECKSUM_INIT(cksum, type, d)      do { \
        (cksum)->checksum_type = (type);            \
        (cksum)->length = (d)->length;              \
        (cksum)->contents = (d)->value;             \
    } while (0)

#endif /* HAVE_HEIMDAL_VERSION */

#define KRB_KEY_INIT(key)       do {        \
        KRB_KEY_TYPE(key) = ENCTYPE_NULL;   \
        KRB_KEY_DATA(key) = NULL;           \
        KRB_KEY_LENGTH(key) = 0;            \
    } while (0)

#define GSSBID_KRB_INIT(ctx) do {                   \
        OM_uint32 tmpMajor;                         \
                                                    \
        tmpMajor  = gssBidKerberosInit(minor, ctx); \
        if (GSS_ERROR(tmpMajor)) {                  \
            return tmpMajor;                        \
        }                                           \
    } while (0)

OM_uint32
gssBidKerberosInit(OM_uint32 *minor, krb5_context *context);

OM_uint32
rfc3961ChecksumTypeForKey(OM_uint32 *minor,
                          krb5_keyblock *key,
                          krb5_cksumtype *cksumtype);

krb5_error_code
krbCryptoLength(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                krb5_crypto krbCrypto,
#else
                krb5_keyblock *key,
#endif
                int type,
                size_t *length);

krb5_error_code
krbPaddingLength(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                 krb5_crypto krbCrypto,
#else
                 krb5_keyblock *key,
#endif
                 size_t dataLength,
                 size_t *padLength);

krb5_error_code
krbBlockSize(krb5_context krbContext,
#ifdef HAVE_HEIMDAL_VERSION
                 krb5_crypto krbCrypto,
#else
                 krb5_keyblock *key,
#endif
                 size_t *blockSize);

krb5_error_code
krbEnctypeToString(krb5_context krbContext,
                   krb5_enctype enctype,
                   const char *prefix,
                   gss_buffer_t string);

/* util_lucid.c */
OM_uint32
gssBidExportLucidSecContext(OM_uint32 *minor,
                            gss_ctx_id_t ctx,
                            const gss_OID desiredObject,
                            gss_buffer_set_t *data_set);

/* util_mech.c */
extern gss_OID GSS_BROWSERID_MECHANISM;

#define OID_FLAG_NULL_VALID                 0x00000001
#define OID_FLAG_FAMILY_MECH_VALID          0x00000002
#define OID_FLAG_MAP_NULL_TO_DEFAULT_MECH   0x00000004
#define OID_FLAG_MAP_FAMILY_MECH_TO_NULL    0x00000008

OM_uint32
gssBidCanonicalizeOid(OM_uint32 *minor,
                      const gss_OID oid,
                      OM_uint32 flags,
                      gss_OID *pOid);

OM_uint32
gssBidReleaseOid(OM_uint32 *minor, gss_OID *oid);

OM_uint32
gssBidDefaultMech(OM_uint32 *minor,
                  gss_OID *oid);

OM_uint32
gssBidIndicateMechs(OM_uint32 *minor,
                    gss_OID_set *mechs);

OM_uint32
gssBidEnctypeToOid(OM_uint32 *minor,
                   krb5_enctype enctype,
                   gss_OID *pOid);

OM_uint32
gssBidOidToEnctype(OM_uint32 *minor,
                   const gss_OID oid,
                   krb5_enctype *enctype);

OM_uint32
gssBidRfc3961KeySize(OM_uint32 *minor,
                     krb5_enctype enctype,
                     size_t *keybytes);

int
gssBidIsMechanismOid(const gss_OID oid);

int
gssBidIsConcreteMechanismOid(const gss_OID oid);

OM_uint32
gssBidValidateMechs(OM_uint32 *minor,
                   const gss_OID_set mechs);

gss_buffer_t
gssBidOidToSaslName(const gss_OID oid);

gss_OID
gssBidSaslNameToOid(const gss_buffer_t name);

/* util_name.c */
#define EXPORT_NAME_FLAG_OID                    0x1
#define EXPORT_NAME_FLAG_COMPOSITE              0x2
#define EXPORT_NAME_FLAG_ALLOW_COMPOSITE        0x4

OM_uint32 gssBidAllocName(OM_uint32 *minor, gss_name_t *pName);
OM_uint32 gssBidReleaseName(OM_uint32 *minor, gss_name_t *pName);
OM_uint32 gssBidExportName(OM_uint32 *minor,
                           const gss_name_t name,
                           gss_buffer_t exportedName);
OM_uint32 gssBidExportNameInternal(OM_uint32 *minor,
                                   const gss_name_t name,
                                   gss_buffer_t exportedName,
                                   OM_uint32 flags);
OM_uint32 gssBidImportName(OM_uint32 *minor,
                           const gss_buffer_t input_name_buffer,
                           const gss_OID input_name_type,
                           const gss_OID input_mech_type,
                           gss_name_t *output_name);
OM_uint32 gssBidImportNameInternal(OM_uint32 *minor,
                                   const gss_buffer_t input_name_buffer,
                                   gss_name_t *output_name,
                                   OM_uint32 flags);
OM_uint32
gssBidDuplicateName(OM_uint32 *minor,
                    const gss_name_t input_name,
                    gss_name_t *dest_name);

OM_uint32
gssBidCanonicalizeName(OM_uint32 *minor,
                       const gss_name_t input_name,
                       const gss_OID mech_type,
                       gss_name_t *dest_name);

OM_uint32
gssBidDisplayName(OM_uint32 *minor,
                  gss_name_t name,
                  gss_buffer_t output_name_buffer,
                  gss_OID *output_name_type);

#define COMPARE_NAME_FLAG_IGNORE_EMPTY_REALMS   0x1

OM_uint32
gssBidCompareName(OM_uint32 *minor,
                  gss_name_t name1,
                  gss_name_t name2,
                  OM_uint32 flags,
                  int *name_equal);

/* util_oid.c */
OM_uint32
composeOid(OM_uint32 *minor_status,
           const char *prefix,
           size_t prefix_len,
           int suffix,
           gss_OID_desc *oid);

OM_uint32
decomposeOid(OM_uint32 *minor_status,
             const char *prefix,
             size_t prefix_len,
             gss_OID_desc *oid,
             int *suffix) ;

OM_uint32
duplicateOid(OM_uint32 *minor_status,
             const gss_OID_desc * const oid,
             gss_OID *new_oid);

OM_uint32
duplicateOidSet(OM_uint32 *minor,
                const gss_OID_set src,
                gss_OID_set *dst);

static inline int
oidEqual(const gss_OID_desc *o1, const gss_OID_desc *o2)
{
    if (o1 == GSS_C_NO_OID)
        return (o2 == GSS_C_NO_OID);
    else if (o2 == GSS_C_NO_OID)
        return (o1 == GSS_C_NO_OID);
    else
        return (o1->length == o2->length &&
                memcmp(o1->elements, o2->elements, o1->length) == 0);
}

/* util_ordering.c */
OM_uint32
sequenceInternalize(OM_uint32 *minor,
                    void **vqueue,
                    unsigned char **buf,
                    size_t *lenremain);

OM_uint32
sequenceExternalize(OM_uint32 *minor,
                    void *vqueue,
                    unsigned char **buf,
                    size_t *lenremain);

size_t
sequenceSize(void *vqueue);

OM_uint32
sequenceFree(OM_uint32 *minor, void **vqueue);

OM_uint32
sequenceCheck(OM_uint32 *minor, void **vqueue, uint64_t seqnum);

OM_uint32
sequenceInit(OM_uint32 *minor, void **vqueue, uint64_t seqnum,
             int do_replay, int do_sequence, int wide_nums);

/* util_sm.c */
enum gss_bid_state {
    GSSBID_STATE_INITIAL            = 0x01,     /* initial state */
    GSSBID_STATE_AUTHENTICATE       = 0x02,     /* exchange assertion */
    GSSBID_STATE_RETRY_INITIAL      = 0x04,     /* retry reauth */
    GSSBID_STATE_RETRY_AUTHENTICATE = 0x08,     /* retry reauth */
    GSSBID_STATE_ESTABLISHED        = 0x10,     /* context established */
};

#define GSSBID_STATE_NEXT(s)    ((s) << 1)

#define GSSBID_SM_STATE(ctx)                ((ctx)->state)

#define GSSBID_SM_TRANSITION(ctx, newstate)    do { (ctx)->state = (newstate); } while (0)
#define GSSBID_SM_TRANSITION_NEXT(ctx)      GSSBID_SM_TRANSITION((ctx), GSSBID_STATE_NEXT(GSSBID_SM_STATE((ctx))))

/* util_token.c */

size_t
tokenSize(const gss_OID_desc *mech, size_t body_size);

void
makeTokenHeader(const gss_OID_desc *mech,
                size_t body_size,
                unsigned char **buf,
                enum gss_bid_token_type tok_type);

OM_uint32
verifyTokenHeader(OM_uint32 *minor,
                  gss_OID mech,
                  size_t *body_size,
                  unsigned char **buf_in,
                  size_t toksize_in,
                  enum gss_bid_token_type *ret_tok_type);

/* Helper macros */

#ifndef GSSBID_MALLOC
#define GSSBID_CALLOC                   calloc
#define GSSBID_MALLOC                   malloc
#define GSSBID_FREE                     free
#define GSSBID_REALLOC                  realloc
#endif

#ifndef GSSAPI_CALLCONV
#define GSSAPI_CALLCONV                 KRB5_CALLCONV
#endif

#ifndef GSSBID_ASSERT
#include <assert.h>
#define GSSBID_ASSERT(x)                assert((x))
#endif /* !GSSBID_ASSERT */

#ifdef WIN32
#define GSSBID_CONSTRUCTOR
#define GSSBID_DESTRUCTOR
#else
#define GSSBID_CONSTRUCTOR              __attribute__((constructor))
#define GSSBID_DESTRUCTOR               __attribute__((destructor))
#endif

#define GSSBID_NOT_IMPLEMENTED          do {            \
        GSSBID_ASSERT(0 && "not implemented");          \
        *minor = ENOSYS;                                \
        return GSS_S_FAILURE;                           \
    } while (0)

#ifdef WIN32

#include <winbase.h>

#define GSSBID_GET_LAST_ERROR()         (GetLastError()) /* XXX FIXME */

#define GSSBID_MUTEX                    CRITICAL_SECTION
#define GSSBID_MUTEX_INIT(m)            (InitializeCriticalSection((m)), 0)
#define GSSBID_MUTEX_DESTROY(m)         DeleteCriticalSection((m))
#define GSSBID_MUTEX_LOCK(m)            EnterCriticalSection((m))
#define GSSBID_MUTEX_UNLOCK(m)          LeaveCriticalSection((m))
#define GSSBID_ONCE_LEAVE		do { return TRUE; } while (0)

/* Thread-local is handled separately */

#define GSSBID_THREAD_ONCE              INIT_ONCE
#define GSSBID_ONCE_CALLBACK(cb)        BOOL CALLBACK cb(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
#define GSSBID_ONCE(o, i)               InitOnceExecuteOnce((o), (i), NULL, NULL)
#define GSSBID_ONCE_INITIALIZER         INIT_ONCE_STATIC_INIT

#else

#include <pthread.h>

#define GSSBID_GET_LAST_ERROR()         (errno)

#define GSSBID_MUTEX                    pthread_mutex_t
#define GSSBID_MUTEX_INIT(m)            pthread_mutex_init((m), NULL)
#define GSSBID_MUTEX_DESTROY(m)         pthread_mutex_destroy((m))
#define GSSBID_MUTEX_LOCK(m)            pthread_mutex_lock((m))
#define GSSBID_MUTEX_UNLOCK(m)          pthread_mutex_unlock((m))

#define GSSBID_THREAD_KEY               pthread_key_t
#define GSSBID_KEY_CREATE(k, d)         pthread_key_create((k), (d))
#define GSSBID_GETSPECIFIC(k)           pthread_getspecific((k))
#define GSSBID_SETSPECIFIC(k, d)        pthread_setspecific((k), (d))

#define GSSBID_THREAD_ONCE              pthread_once_t
#define GSSBID_ONCE_CALLBACK(cb)        void cb(void)
#define GSSBID_ONCE(o, i)               pthread_once((o), (i))
#define GSSBID_ONCE_INITIALIZER         PTHREAD_ONCE_INIT
#define GSSBID_ONCE_LEAVE		do { } while (0)

#endif /* WIN32 */

/* Helper functions */
static inline void
store_uint16_be(uint16_t val, void *vp)
{
    unsigned char *p = (unsigned char *)vp;

    p[0] = (val >>  8) & 0xff;
    p[1] = (val      ) & 0xff;
}

static inline uint16_t
load_uint16_be(const void *cvp)
{
    const unsigned char *p = (const unsigned char *)cvp;

    return (p[1] | (p[0] << 8));
}

static inline void
store_uint32_be(uint32_t val, void *vp)
{
    unsigned char *p = (unsigned char *)vp;

    p[0] = (val >> 24) & 0xff;
    p[1] = (val >> 16) & 0xff;
    p[2] = (val >>  8) & 0xff;
    p[3] = (val      ) & 0xff;
}

static inline uint32_t
load_uint32_be(const void *cvp)
{
    const unsigned char *p = (const unsigned char *)cvp;

    return (p[3] | (p[2] << 8)
            | ((uint32_t) p[1] << 16)
            | ((uint32_t) p[0] << 24));
}

static inline void
store_uint64_be(uint64_t val, void *vp)
{
    unsigned char *p = (unsigned char *)vp;

    p[0] = (unsigned char)((val >> 56) & 0xff);
    p[1] = (unsigned char)((val >> 48) & 0xff);
    p[2] = (unsigned char)((val >> 40) & 0xff);
    p[3] = (unsigned char)((val >> 32) & 0xff);
    p[4] = (unsigned char)((val >> 24) & 0xff);
    p[5] = (unsigned char)((val >> 16) & 0xff);
    p[6] = (unsigned char)((val >>  8) & 0xff);
    p[7] = (unsigned char)((val      ) & 0xff);
}

static inline uint64_t
load_uint64_be(const void *cvp)
{
    const unsigned char *p = (const unsigned char *)cvp;

    return ((uint64_t)load_uint32_be(p) << 32) | load_uint32_be(p + 4);
}

static inline unsigned char *
store_buffer(gss_buffer_t buffer, void *vp, int wide_nums)
{
    unsigned char *p = (unsigned char *)vp;

    if (wide_nums) {
        store_uint64_be(buffer->length, p);
        p += 8;
    } else {
        store_uint32_be(buffer->length, p);
        p += 4;
    }

    if (buffer->value != NULL) {
        memcpy(p, buffer->value, buffer->length);
        p += buffer->length;
    }

    return p;
}

static inline unsigned char *
load_buffer(const void *cvp, size_t length, gss_buffer_t buffer)
{
    buffer->length = 0;
    buffer->value = GSSBID_MALLOC(length);
    if (buffer->value == NULL)
        return NULL;
    buffer->length = length;
    memcpy(buffer->value, cvp, length);
    return (unsigned char *)cvp + length;
}

static inline unsigned char *
store_oid(gss_OID oid, void *vp)
{
    gss_buffer_desc buf;

    if (oid != GSS_C_NO_OID) {
        buf.length = oid->length;
        buf.value = oid->elements;
    } else {
        buf.length = 0;
        buf.value = NULL;
    }

    return store_buffer(&buf, vp, FALSE);
}

static inline void
krbDataToGssBuffer(krb5_data *data, gss_buffer_t buffer)
{
    buffer->value = (void *)data->data;
    buffer->length = data->length;
}

static inline void
krbPrincComponentToGssBuffer(krb5_principal krbPrinc,
                             int index, gss_buffer_t buffer)
{
#ifdef HAVE_HEIMDAL_VERSION
    buffer->value = (void *)KRB_PRINC_NAME(krbPrinc)[index];
    buffer->length = strlen((char *)buffer->value);
#else
    buffer->value = (void *)krb5_princ_component(NULL, krbPrinc, index)->data;
    buffer->length = krb5_princ_component(NULL, krbPrinc, index)->length;
#endif /* HAVE_HEIMDAL_VERSION */
}

static inline void
krbPrincRealmToGssBuffer(krb5_principal krbPrinc, gss_buffer_t buffer)
{
#ifdef HAVE_HEIMDAL_VERSION
    buffer->value = (void *)KRB_PRINC_REALM(krbPrinc);
    buffer->length = strlen((char *)buffer->value);
#else
    krbDataToGssBuffer(KRB_PRINC_REALM(krbPrinc), buffer);
#endif
}

static inline void
gssBufferToKrbData(gss_buffer_t buffer, krb5_data *data)
{
    data->data = (char *)buffer->value;
    data->length = buffer->length;
}

/* util_tld.c */
struct gss_bid_status_info;

struct gss_bid_thread_local_data {
    krb5_context krbContext;
    struct gss_bid_status_info *statusInfo;
};

struct gss_bid_thread_local_data *
gssBidGetThreadLocalData(void);

void
gssBidDestroyStatusInfo(struct gss_bid_status_info *status);

void
gssBidDestroyKrbContext(krb5_context context);

#ifdef __cplusplus
}
#endif

#ifdef GSSBID_ENABLE_ACCEPTOR
#include "util_json.h"
#include "util_attr.h"
#include "util_base64.h"
#endif /* GSSBID_ENABLE_ACCEPTOR */

#endif /* _UTIL_H_ */
