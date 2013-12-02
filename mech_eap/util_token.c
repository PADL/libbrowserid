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
 * Portions Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Utility routines for GSS tokens.
 */

#include "gssapiP_eap.h"

OM_uint32
gssEapEncodeInnerTokens(OM_uint32 *minor,
                        struct gss_eap_token_buffer_set *tokens,
                        gss_buffer_t buffer)
{
    OM_uint32 major, tmpMinor;
    size_t required = 0, i;
    unsigned char *p;

    buffer->value = NULL;
    buffer->length = 0;

    for (i = 0; i < tokens->buffers.count; i++) {
        required += 8 + tokens->buffers.elements[i].length;
    }

    /*
     * We must always return a non-NULL token otherwise the calling state
     * machine assumes we are finished. Hence care in case malloc(0) does
     * return NULL.
     */
    buffer->value = GSSEAP_MALLOC(required ? required : 1);
    if (buffer->value == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    buffer->length = required;
    p = (unsigned char *)buffer->value;

    for (i = 0; i < tokens->buffers.count; i++) {
        gss_buffer_t tokenBuffer = &tokens->buffers.elements[i];

        GSSEAP_ASSERT((tokens->types[i] & ITOK_FLAG_VERIFIED) == 0); /* private flag */

         /*
          * Extensions are encoded as type-length-value, where the upper
          * bit of the type indicates criticality.
          */
        store_uint32_be(tokens->types[i], &p[0]);
        store_uint32_be(tokenBuffer->length, &p[4]);
        memcpy(&p[8], tokenBuffer->value, tokenBuffer->length);

        p += 8 + tokenBuffer->length;
    }

    GSSEAP_ASSERT(p == (unsigned char *)buffer->value + required);
    GSSEAP_ASSERT(buffer->value != NULL);

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        gss_release_buffer(&tmpMinor, buffer);
    }

    return major;
}

OM_uint32
gssEapDecodeInnerTokens(OM_uint32 *minor,
                        const gss_buffer_t buffer,
                        struct gss_eap_token_buffer_set *tokens)
{
    OM_uint32 major, tmpMinor;
    unsigned char *p;
    size_t count = 0;
    size_t remain;

    tokens->buffers.count = 0;
    tokens->buffers.elements = NULL;
    tokens->types = NULL;

    if (buffer->length == 0) {
        major = GSS_S_COMPLETE;
        goto cleanup;
    }

    p = (unsigned char *)buffer->value;
    remain = buffer->length;

    do {
        OM_uint32 *ntypes;
        gss_buffer_desc tokenBuffer, *newTokenBuffers;

        if (remain < 8) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_TOK_TRUNC;
            goto cleanup;
        }

        if (tokens->buffers.count <= count) {
            if (count == 0)
                count = 1;
            else
                count *= 2;

            ntypes = GSSEAP_MALLOC(count * sizeof(OM_uint32));
            if (ntypes == NULL) {
                major = GSS_S_FAILURE;
                *minor = ENOMEM;
                goto cleanup;
            }
            if (tokens->types != NULL) {
                memcpy(ntypes, tokens->types, tokens->buffers.count * sizeof(OM_uint32));
                GSSEAP_FREE(tokens->types);
            }
            tokens->types = ntypes;

            newTokenBuffers = GSSEAP_MALLOC(count * sizeof(gss_buffer_desc));
            if (newTokenBuffers == NULL) {
                major = GSS_S_FAILURE;
                *minor = ENOMEM;
                goto cleanup;
            }
            if (tokens->buffers.elements != NULL) {
                memcpy(newTokenBuffers, tokens->buffers.elements,
                       tokens->buffers.count * sizeof(gss_buffer_desc));
                GSSEAP_FREE(tokens->buffers.elements);
            }
            tokens->buffers.elements = newTokenBuffers;
        }

        tokens->types[tokens->buffers.count] = load_uint32_be(&p[0]);
        tokenBuffer.length = load_uint32_be(&p[4]);

        if (remain < 8 + tokenBuffer.length) {
            major = GSS_S_DEFECTIVE_TOKEN;
            *minor = GSSEAP_TOK_TRUNC;
            goto cleanup;
        }
        tokenBuffer.value = &p[8];

        tokens->buffers.elements[tokens->buffers.count] = tokenBuffer;
        tokens->buffers.count++;

        p      += 8 + tokenBuffer.length;
        remain -= 8 + tokenBuffer.length;
    } while (remain != 0);

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major))
        gssEapReleaseInnerTokens(&tmpMinor, tokens, 0);

    return major;
}

/*
 * $Id: util_token.c 23457 2009-12-08 00:04:48Z tlyu $
 */

/* XXXX this code currently makes the assumption that a mech oid will
   never be longer than 127 bytes.  This assumption is not inherent in
   the interfaces, so the code can be fixed if the OSI namespace
   balloons unexpectedly. */

/*
 * Each token looks like this:
 * 0x60                 tag for APPLICATION 0, SEQUENCE
 *                              (constructed, definite-length)
 * <length>             possible multiple bytes, need to parse/generate
 * 0x06                 tag for OBJECT IDENTIFIER
 * <moid_length>        compile-time constant string (assume 1 byte)
 * <moid_bytes>         compile-time constant string
 * <inner_bytes>        the ANY containing the application token
 * bytes 0,1 are the token type
 * bytes 2,n are the token data
 *
 * Note that the token type field is a feature of RFC 1964 mechanisms and
 * is not used by other GSSAPI mechanisms.  As such, a token type of -1
 * is interpreted to mean that no token type should be expected or
 * generated.
 *
 * For the purposes of this abstraction, the token "header" consists of
 * the sequence tag and length octets, the mech OID DER encoding, and the
 * first two inner bytes, which indicate the token type.  The token
 * "body" consists of everything else.
 */

static size_t
der_length_size(size_t length)
{
    if (length < (1<<7))
        return 1;
    else if (length < (1<<8))
        return 2;
#if INT_MAX == 0x7fff
    else
        return 3;
#else
    else if (length < (1<<16))
        return 3;
    else if (length < (1<<24))
        return 4;
    else
        return 5;
#endif
}

static void
der_write_length(unsigned char **buf, size_t length)
{
    if (length < (1<<7)) {
        *(*buf)++ = (unsigned char)length;
    } else {
        *(*buf)++ = (unsigned char)(der_length_size(length)+127);
#if INT_MAX > 0x7fff
        if (length >= (1<<24))
            *(*buf)++ = (unsigned char)(length>>24);
        if (length >= (1<<16))
            *(*buf)++ = (unsigned char)((length>>16)&0xff);
#endif
        if (length >= (1<<8))
            *(*buf)++ = (unsigned char)((length>>8)&0xff);
        *(*buf)++ = (unsigned char)(length&0xff);
    }
}

/* returns decoded length, or < 0 on failure.  Advances buf and
   decrements bufsize */

static int
der_read_length(unsigned char **buf, ssize_t *bufsize)
{
    unsigned char sf;
    int ret;

    if (*bufsize < 1)
        return -1;

    sf = *(*buf)++;
    (*bufsize)--;
    if (sf & 0x80) {
        if ((sf &= 0x7f) > ((*bufsize)-1))
            return -1;
        if (sf > sizeof(int))
            return -1;
        ret = 0;
        for (; sf; sf--) {
            ret = (ret<<8) + (*(*buf)++);
            (*bufsize)--;
        }
    } else {
        ret = sf;
    }

    return ret;
}

/* returns the length of a token, given the mech oid and the body size */

size_t
tokenSize(const gss_OID_desc *mech, size_t body_size)
{
    GSSEAP_ASSERT(mech != GSS_C_NO_OID);

    /* set body_size to sequence contents size */
    body_size += 4 + (size_t) mech->length;         /* NEED overflow check */
    return 1 + der_length_size(body_size) + body_size;
}

/* fills in a buffer with the token header.  The buffer is assumed to
   be the right size.  buf is advanced past the token header */

void
makeTokenHeader(
    const gss_OID_desc *mech,
    size_t body_size,
    unsigned char **buf,
    enum gss_eap_token_type tok_type)
{
    *(*buf)++ = 0x60;
    der_write_length(buf, 4 + mech->length + body_size);
    *(*buf)++ = 0x06;
    *(*buf)++ = (unsigned char)mech->length;
    memcpy(*buf, mech->elements, mech->length);
    *buf += mech->length;
    GSSEAP_ASSERT(tok_type != TOK_TYPE_NONE);
    *(*buf)++ = (unsigned char)((tok_type>>8) & 0xff);
    *(*buf)++ = (unsigned char)(tok_type & 0xff);
}

/*
 * Given a buffer containing a token, reads and verifies the token,
 * leaving buf advanced past the token header, and setting body_size
 * to the number of remaining bytes.  Returns 0 on success,
 * G_BAD_TOK_HEADER for a variety of errors, and G_WRONG_MECH if the
 * mechanism in the token does not match the mech argument.  buf and
 * *body_size are left unmodified on error.
 */

OM_uint32
verifyTokenHeader(OM_uint32 *minor,
                  gss_OID mech,
                  size_t *body_size,
                  unsigned char **buf_in,
                  size_t toksize_in,
                  enum gss_eap_token_type *ret_tok_type)
{
    unsigned char *buf = *buf_in;
    ssize_t seqsize;
    gss_OID_desc toid;
    ssize_t toksize = (ssize_t)toksize_in;

    *minor = GSSEAP_BAD_TOK_HEADER;

    if (ret_tok_type != NULL)
        *ret_tok_type = TOK_TYPE_NONE;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (*buf++ != 0x60)
        return GSS_S_DEFECTIVE_TOKEN;

    seqsize = der_read_length(&buf, &toksize);
    if (seqsize < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (seqsize != toksize)
        return GSS_S_DEFECTIVE_TOKEN;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    if (*buf++ != 0x06)
        return GSS_S_DEFECTIVE_TOKEN;

    if ((toksize -= 1) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    toid.length = *buf++;

    if ((toksize -= toid.length) < 0)
        return GSS_S_DEFECTIVE_TOKEN;

    toid.elements = buf;
    buf += toid.length;

    if (mech->elements == NULL) {
        *mech = toid;
        if (toid.length == 0)
            return GSS_S_BAD_MECH;
    } else if (!oidEqual(&toid, mech)) {
        *minor = GSSEAP_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (ret_tok_type != NULL) {
        if ((toksize -= 2) < 0)
            return GSS_S_DEFECTIVE_TOKEN;

        *ret_tok_type = load_uint16_be(buf);
        buf += 2;
    }

    *buf_in = buf;
    *body_size = toksize;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32
gssEapAllocInnerTokens(OM_uint32 *minor,
                       size_t count,
                       struct gss_eap_token_buffer_set *tokens)
{
    OM_uint32 major;

    tokens->buffers.count = 0;
    tokens->buffers.elements = (gss_buffer_desc *)GSSEAP_CALLOC(count, sizeof(gss_buffer_desc));
    if (tokens->buffers.elements == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    tokens->types = (OM_uint32 *)GSSEAP_CALLOC(count, sizeof(OM_uint32));
    if (tokens->types == NULL) {
        major = GSS_S_FAILURE;
        *minor = ENOMEM;
        goto cleanup;
    }

    major = GSS_S_COMPLETE;
    *minor = 0;

cleanup:
    if (GSS_ERROR(major)) {
        if (tokens->buffers.elements != NULL) {
            GSSEAP_FREE(tokens->buffers.elements);
            tokens->buffers.elements = NULL;
        }
        if (tokens->types != NULL) {
            GSSEAP_FREE(tokens->types);
            tokens->types = NULL;
        }
    }

    return major;
}

OM_uint32
gssEapReleaseInnerTokens(OM_uint32 *minor,
                         struct gss_eap_token_buffer_set *tokens,
                         int freeBuffers)
{
    OM_uint32 tmpMinor;
    size_t i;

    if (tokens->buffers.elements != NULL) {
        if (freeBuffers) {
            for (i = 0; i < tokens->buffers.count; i++)
                gss_release_buffer(&tmpMinor, &tokens->buffers.elements[i]);
        }
        GSSEAP_FREE(tokens->buffers.elements);
        tokens->buffers.elements = NULL;
    }
    tokens->buffers.count = 0;

    if (tokens->types != NULL) {
        GSSEAP_FREE(tokens->types);
        tokens->types = NULL;
    }

    *minor = 0;
    return GSS_S_COMPLETE;
}
