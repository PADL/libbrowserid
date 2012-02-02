/*
 * RADIUS tlv construction utilites
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

struct radius_vendor_attr_struct;
typedef struct radius_vendor_attr_struct *radius_vendor_attr;
#define VENDOR_ATTR_INVALID NULL
radius_vendor_attr radius_vendor_attr_start(struct wpabuf *buf, u32 vendor);
radius_vendor_attr radius_vendor_attr_add_subtype(radius_vendor_attr attr,
						  u8 type,
						  u8 *data, size_t len);
radius_vendor_attr radius_vendor_attr_finish(radius_vendor_attr attr);

struct radius_parser_struct;
typedef struct radius_parser_struct *radius_parser;
radius_parser radius_parser_start(void *tlvdata, size_t len);
int radius_parser_parse_tlv(radius_parser parser, u8 *type, u32 *vendor_id,
			    void **value, size_t *len);
int radius_parser_parse_vendor_specific(radius_parser parser, u8 *vendor_type,
				        void **value, size_t *len);
void radius_parser_finish(radius_parser parser);


#endif /* RADIUS_UTILS_H */