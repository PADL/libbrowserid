/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */
/*
 * Base32 implementation
 * Copyright 2010 Google Inc.
 * Author: Markus Gutschke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bid_private.h"

#include <ctype.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#define BASE32_EXPAND(n)        (n * 8 / 5 + 4)

BIDError
_BIDBase32UrlEncode(const unsigned char *data, size_t size, char **str, size_t *pcchStr)
{
    char *s;
    size_t count = 0, bufSize;

    *str = NULL;

    if (size > UINT_MAX/2)
	return BID_S_BUFFER_TOO_LONG;

    bufSize = BASE32_EXPAND(size);
    s = (char *)BIDMalloc(bufSize);
    if (s == NULL)
	return BID_S_NO_MEMORY;

    if (size > 0) {
        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;

        while (count < bufSize && (bitsLeft > 0 || next < size)) {
            int index;

            if (bitsLeft < 5) {
                if (next < size) {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                } else {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            index = 0x1F & (buffer >> (bitsLeft - 5));
            bitsLeft -= 5;
            s[count++] = base32_chars[index];
        }
    }
    if (count < bufSize)
        s[count] = '\000';

    *str = s;
    *pcchStr = strlen(s);
    return BID_S_OK;
}

BIDError
_BIDBase32UrlDecode(const char *str, unsigned char **pData, size_t *pcbData)
{
    const char *p;
    unsigned char *data;
    size_t maxLength;
    BIDError err;
    int buffer = 0;
    int bitsLeft = 0;
    size_t count = 0;

    if (*pData == NULL) {
        maxLength = strlen(str) + 1;
        data = BIDMalloc(maxLength);
        if (data == NULL)
            return BID_S_NO_MEMORY;
    } else {
        maxLength = *pcbData;
        data = *pData;
    }

    p = str;

    for (p = str; count < maxLength && *p != '\0'; ++p) {
        unsigned char ch = *p;
        buffer <<= 5;

        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
            ch = (ch & 0x1F) - 1;
        else if (ch >= '2' && ch <= '7')
            ch -= '2' - 26;
        else {
            err = BID_S_INVALID_BASE64;
            goto cleanup;
        }

        buffer |= ch;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            data[count++] = buffer >> (bitsLeft - 8);
            bitsLeft -= 8;
        }
    }

    if (count < maxLength)
        data[count] = '\0';

    if (*pData == NULL)
        *pData = data;

    *pcbData = count;
    err = BID_S_OK;

cleanup:
    if (err != BID_S_OK && *pData == NULL)
        BIDFree(data);

    return err;
}
