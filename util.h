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

#ifndef _UTIL_H_
#define _UTIL_H_ 1

#include <string.h>
#include <errno.h>

#include <krb5.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MIN             /* Usually found in <sys/param.h>. */
#define MIN(_a,_b)  ((_a)<(_b)?(_a):(_b))
#endif

#define KRB_KEY_TYPE(key)       ((key)->enctype)
#define KRB_KEY_DATA(key)       ((key)->contents)
#define KRB_KEY_LENGTH(key)     ((key)->length)
#define KRB_KEY_INIT(key)       do {        \
        KRB_KEY_TYPE(key) = ENCTYPE_NULL;   \
        KRB_KEY_DATA(key) = NULL;           \
        KRB_KEY_LENGTH(key) = 0;            \
    } while (0)

enum gss_eap_token_type {
    TOK_TYPE_NONE                    = 0x0000,  /* no token */
    TOK_TYPE_MIC                     = 0x0404,  /* RFC 4121 MIC token */
    TOK_TYPE_WRAP                    = 0x0504,  /* RFC 4121 wrap token */
    TOK_TYPE_EXPORT_NAME             = 0x0401,  /* RFC 2743 exported name */
    TOK_TYPE_EXPORT_NAME_COMPOSITE   = 0x0402,  /* draft-ietf-kitten-gss-naming */
    TOK_TYPE_DELETE_CONTEXT          = 0x0405,  /* RFC 2743 delete context */
    TOK_TYPE_EAP_RESP                = 0x0601,  /* draft-howlett-eap-gss */
    TOK_TYPE_EAP_REQ                 = 0x0602,  /* draft-howlett-eap-gss */
    TOK_TYPE_GSS_CB                  = 0x0603,  /* draft-howlett-eap-gss */
};

#define EAP_EXPORT_CONTEXT_V1           1

/* util_buffer.c */
OM_uint32
makeStringBuffer(OM_uint32 *minor,
                 const char *string,
                 gss_buffer_t buffer);

OM_uint32
bufferToString(OM_uint32 *minor,
               const gss_buffer_t buffer,
               char **pString);

OM_uint32
duplicateBuffer(OM_uint32 *minor,
                const gss_buffer_t src,
                gss_buffer_t dst);

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

#if 0
OM_uint32
gssEapEncodeGssChannelBindings(OM_uint32 *minor,
                               gss_channel_bindings_t chanBindings,
                               gss_buffer_t encodedBindings);
#endif

/* util_context.c */
OM_uint32 gssEapAllocContext(OM_uint32 *minor, gss_ctx_id_t *pCtx);
OM_uint32 gssEapReleaseContext(OM_uint32 *minor, gss_ctx_id_t *pCtx);

OM_uint32
gssEapMakeToken(OM_uint32 *minor,
                gss_ctx_id_t ctx,
                const gss_buffer_t innerToken,
                enum gss_eap_token_type tokenType,
                gss_buffer_t outputToken);

OM_uint32
gssEapVerifyToken(OM_uint32 *minor,
                  gss_ctx_id_t ctx,
                  const gss_buffer_t inputToken,
                  enum gss_eap_token_type tokenType,
                  gss_buffer_t innerInputToken);

/* util_cred.c */
OM_uint32 gssEapAllocCred(OM_uint32 *minor, gss_cred_id_t *pCred);
OM_uint32 gssEapReleaseCred(OM_uint32 *minor, gss_cred_id_t *pCred);

OM_uint32
gssEapAcquireCred(OM_uint32 *minor,
                  const gss_name_t desiredName,
                  const gss_buffer_t password,
                  OM_uint32 timeReq,
                  const gss_OID_set desiredMechs,
                  int cred_usage,
                  gss_cred_id_t *pCred,
                  gss_OID_set *pActualMechs,
                  OM_uint32 *timeRec);

int gssEapCredAvailable(gss_cred_id_t cred, gss_OID mech);

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
gssEapMapCryptoFlag(OM_uint32 type);

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

OM_uint32
gssEapDeriveRfc3961Key(OM_uint32 *minor,
                       const unsigned char *key,
                       size_t keyLength,
                       krb5_enctype enctype,
                       krb5_keyblock *pKey);

/* util_krb.c */
OM_uint32
gssEapKerberosInit(OM_uint32 *minor, krb5_context *context);

OM_uint32
rfc3961ChecksumTypeForKey(OM_uint32 *minor,
                          krb5_keyblock *key,
                          krb5_cksumtype *cksumtype);

#define GSSEAP_KRB_INIT(ctx) do {                   \
        OM_uint32 tmpMajor;                         \
        tmpMajor  = gssEapKerberosInit(minor, ctx); \
        if (GSS_ERROR(tmpMajor)) {                  \
            return tmpMajor;                        \
        }                                           \
    } while (0)

/* util_mech.c */
int
gssEapInternalizeOid(const gss_OID oid,
                     gss_OID *const pInternalizedOid);

OM_uint32
gssEapDefaultMech(OM_uint32 *minor,
                  gss_OID *oid);

OM_uint32
gssEapIndicateMechs(OM_uint32 *minor,
                    gss_OID_set *mechs);

OM_uint32
gssEapEnctypeToOid(OM_uint32 *minor,
                   krb5_enctype enctype,
                   gss_OID *pOid);

OM_uint32
gssEapOidToEnctype(OM_uint32 *minor,
                   const gss_OID oid,
                   krb5_enctype *enctype);

int
gssEapIsMechanismOid(const gss_OID oid);

int
gssEapIsConcreteMechanismOid(const gss_OID oid);

OM_uint32
gssEapValidateMechs(OM_uint32 *minor,
                   const gss_OID_set mechs);

/* util_name.c */
#define EXPORT_NAME_FLAG_OID        0x1
#define EXPORT_NAME_FLAG_COMPOSITE  0x2

OM_uint32 gssEapAllocName(OM_uint32 *minor, gss_name_t *pName);
OM_uint32 gssEapReleaseName(OM_uint32 *minor, gss_name_t *pName);
OM_uint32 gssEapExportName(OM_uint32 *minor,
                           const gss_name_t name,
                           gss_buffer_t exportedName);
OM_uint32 gssEapExportNameInternal(OM_uint32 *minor,
                                   const gss_name_t name,
                                   gss_buffer_t exportedName,
                                   unsigned int flags);
OM_uint32 gssEapImportName(OM_uint32 *minor,
                           const gss_buffer_t input_name_buffer,
                           gss_OID input_name_type,
                           gss_name_t *output_name);
OM_uint32 gssEapImportNameInternal(OM_uint32 *minor,
                                   const gss_buffer_t input_name_buffer,
                                   gss_name_t *output_name,
                                   unsigned int flags);

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

/* util_token.c */
size_t
tokenSize(const gss_OID_desc *mech, size_t body_size);

void
makeTokenHeader(const gss_OID_desc *mech,
                size_t body_size,
                unsigned char **buf,
                enum gss_eap_token_type tok_type);

OM_uint32
verifyTokenHeader(OM_uint32 *minor,
                  gss_OID mech,
                  size_t *body_size,
                  unsigned char **buf_in,
                  size_t toksize_in,
                  enum gss_eap_token_type tok_type);

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

#include <pthread.h>

#define GSSEAP_MUTEX                    pthread_mutex_t
#define GSSEAP_MUTEX_INITIALIZER        PTHREAD_MUTEX_INITIALIZER

#define GSSEAP_MUTEX_INIT(m)            pthread_mutex_init((m), NULL)
#define GSSEAP_MUTEX_DESTROY(m)         pthread_mutex_destroy((m))
#define GSSEAP_MUTEX_LOCK(m)            pthread_mutex_lock((m))
#define GSSEAP_MUTEX_UNLOCK(m)          pthread_mutex_unlock((m))

#define GSSEAP_THREAD_KEY               pthread_key_t
#define GSSEAP_KEY_CREATE(k, d)         pthread_key_create((k), (d))
#define GSSEAP_GETSPECIFIC(k)           pthread_getspecific((k))
#define GSSEAP_SETSPECIFIC(k, d)        pthread_setspecific((k), (d))

#define GSSEAP_THREAD_ONCE              pthread_once_t
#define GSSEAP_ONCE(o, i)               pthread_once((o), (i))
#define GSSEAP_ONCE_INITIALIZER         PTHREAD_ONCE_INIT

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
    buffer->value = GSSEAP_MALLOC(length);
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

#ifdef __cplusplus
}
#endif

#include "util_attr.h"

#endif /* _UTIL_H_ */
