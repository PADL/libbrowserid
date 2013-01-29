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
 * Copyright (c) 1995-2001 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "bid_private.h"

static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BASE64_EXPAND(n)        (n * 4 / 3 + 4)

#define DECODE_ERROR ((ssize_t)-1)

static ssize_t
pos(char c)
{
    const char *p;

    /* Also accept non-URL encoding */
    if (c == '+')
        c = '-';
    else if (c == '/')
        c = '_';
    for (p = base64url_chars; *p != '\0'; p++) {
	if (*p == c)
	    return p - base64url_chars;
    }

    return DECODE_ERROR;
}

BIDError
_BIDBase64UrlEncode(
    const unsigned char *data,
    size_t size,
    char **str,
    size_t *pcchStr)
{
    return _BIDBase64Encode(data, size, BID_ENCODING_BASE64_URL, str, pcchStr);
}

BIDError
_BIDBase64Encode(
    const unsigned char *data,
    size_t size,
    uint32_t encoding,
    char **str,
    size_t *pcchStr)
{
    char *s, *p;
    const char *chars;
    size_t i;
    int c;
    const unsigned char *q;
    int urlEncode = 0;

    if (encoding == BID_ENCODING_BASE64_URL)
        urlEncode = 1;
    else if (encoding != BID_ENCODING_BASE64)
        return BID_S_INVALID_PARAMETER;

    if (size > UINT_MAX/4) {
	*str = NULL;
	return BID_S_BUFFER_TOO_LONG;
    }

    p = s = (char *)BIDMalloc(BASE64_EXPAND(size));
    if (p == NULL) {
        *str = NULL;
	return BID_S_NO_MEMORY;
    }
    q = data;
    chars = urlEncode ? base64url_chars : base64_chars;

    for (i = 0; i < size;) {
	c = q[i++];
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	c *= 256;
	if (i < size)
	    c += q[i];
	i++;
	p[0] = chars[(c & 0x00fc0000) >> 18];
	p[1] = chars[(c & 0x0003f000) >> 12];
	p[2] = chars[(c & 0x00000fc0) >> 6];
	p[3] = chars[(c & 0x0000003f) >> 0];
	if (i > size + 1)
	    p[2] = urlEncode ? '\0' : '=';
	else if (i > size)
	    p[3] = urlEncode ? '\0' : '=';
	p += 4;
    }
    *p = '\0';
    *str = s;
    *pcchStr = strlen(s);
    return BID_S_OK;
}

/*
 * This attempts to deal with both URL and non-URL encoded base64.
 */
static ssize_t
_BIDBase64UrlTokenDecode(const char *token)
{
    size_t i, toklen;
    unsigned int val = 0;
    unsigned int marker = 0;

    toklen = strlen(token);
    if (toklen < 2)
        return DECODE_ERROR;
    else if (toklen > 4)
        toklen = 4;

    for (i = 0; i < 4; i++) {
	val *= 64;
        if (i < toklen) {
            int tmp = 0;

            if (token[i] == '=') {
                marker++;
            } else if (marker != 0) {
                return DECODE_ERROR;
            } else {
                tmp = pos(token[i]);
                if (tmp < 0) {
                    return DECODE_ERROR;
                }
            }
	    val += tmp;
        }
    }

    if (marker == 0)
        marker = 4 - toklen;
    if (marker > 2)
        return DECODE_ERROR;

    return (marker << 24) | val;
}

BIDError
_BIDBase64UrlDecode(const char *str, unsigned char **pData, size_t *pcbData)
{
    const char *p;
    unsigned char *data, *q;
    size_t maxLength;
    BIDError err;

    if (*pData == NULL) {
        maxLength = strlen(str) + 1;
        data = BIDMalloc(maxLength);
        if (data == NULL)
            return BID_S_NO_MEMORY;
    } else {
        maxLength = *pcbData;
        data = *pData;
    }

    q = data;
    p = str;

    while (*p != '\0' && *p != '=') {
	ssize_t val;
	uint8_t marker;

        BID_ASSERT(p < str + maxLength);
        BID_ASSERT(*pData != NULL || q - data <= maxLength);

        if (q - data > maxLength) {
	    err = BID_S_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        val = _BIDBase64UrlTokenDecode(p);
	if (val == DECODE_ERROR) {
	    err = BID_S_INVALID_BASE64;
            goto cleanup;
        }

        marker = (val >> 24) & 0xff;
        BID_ASSERT(marker < 3);
	*q++ = (val >> 16) & 0xff;
	if (marker < 2)
	    *q++ = (val >> 8) & 0xff;
	if (marker < 1)
	    *q++ = val & 0xff;
        p += 4 - marker;
    }

    if (*pData == NULL)
        *pData = data;

    *pcbData = q - data;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && *pData == NULL)
        BIDFree(data);

    return err;
}
