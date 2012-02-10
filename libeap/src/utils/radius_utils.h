/*
 * RADIUS tlv construction and parsing utilites
 * Copyright (c) 2012, Painless Security, LLC
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

#ifndef RADIUS_UTILS_H
#define RADIUS_UTILS_H

struct wpabuf;
struct radius_parser_struct;
typedef struct radius_parser_struct *radius_parser;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Simple utility to add a single type-length-value attribute to a buffer.
 * Currently, there is no dictionary support: 'type' and 'len' are always
 * assumed to be octets, and data is placed directly into buf untranslated
 * for byte order.  If vendor is zero, len should be no greater than 253
 * otherwise, no greater than 247.
 * returns 0 on success, -1 on failure (allocation failure or len too large)
 */
int radius_add_tlv(struct wpabuf **buf, u32 type, u32 vendor, u8 *data,
		   size_t len);

/*
 * simple radius parser
 * Could be made considerably simpler by dropping support for parsing multiple
 * sub-attributes from a vsa.
 */

/*
 * create parser object
 */
radius_parser radius_parser_start(void *tlvdata, size_t len);

/*
 * parse a single tlv;
 * There is no dictionary support; if the tlv is a vsa (attribute 26),
 * sub-attributes are not immediately parsed: instead, the raw data is returned
 * in 'value'.
 * returns 0 on success, -1 on failure (malformed buffer or end of buffer)
 */
int radius_parser_parse_tlv(radius_parser parser, u8 *type, u32 *vendor_id,
			    void **value, size_t *len);

/*
 * parse a single sub-attribute of a vsa: assumes octets for
 * vendor_type and len
 * returns 0 on success, -1 on failure (malformed buffer or end of buffer)
 */
int radius_parser_parse_vendor_specific(radius_parser parser, u8 *vendor_type,
					void **value, size_t *len);

/*
 * destroy parser object
 */
void radius_parser_finish(radius_parser parser);

#ifdef __cplusplus
}
#endif

#endif /* RADIUS_UTILS_H */