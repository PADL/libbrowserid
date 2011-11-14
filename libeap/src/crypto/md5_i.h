/*
 * MD5 internal definitions
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef MD5_I_H
#define MD5_I_H

#ifdef WIN32
/*
 * Use native Windows implementation from CryptDLL.
 */
struct MD5Context {
        u32 i[2];
        u32 buf[4];
        u8 in[64];
        u8 digest[16];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
/* digest must be copied out directly */
void MD5Final(struct MD5Context *context);
#else
struct MD5Context {
	u32 buf[4];
	u32 bits[2];
	u8 in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
#endif /* WIN32 */

#endif /* MD5_I_H */
