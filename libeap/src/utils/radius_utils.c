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

#include "includes.h"

#include "common.h"

#include "radius/radius.h"
#include "radius_utils.h"
#include "wpabuf.h"

int radius_add_tlv(struct wpabuf **buf, u32 type, u32 vendor, u8 *data,
		   size_t len)
{
	u8 base_type;
	u8 total;
	if (vendor) {
		if (len + 6 > RADIUS_MAX_ATTR_LEN)
			return -1;
		total = len + 2 + 6;
		base_type = RADIUS_ATTR_VENDOR_SPECIFIC;
	} else {
		if (len > RADIUS_MAX_ATTR_LEN)
			return -1;
		total = len + 2;
		base_type = type;
	}

	/* ensure buffer has enough space */
	if (wpabuf_resize(buf, total))
		return -1;

	/* write into buffer */
	wpabuf_put_u8(*buf, base_type);
	wpabuf_put_u8(*buf, total);
	if (vendor) {
		wpabuf_put_be32(*buf, vendor);
		wpabuf_put_u8(*buf, (u8 )type);
		wpabuf_put_u8(*buf, (u8 )len+2);
	}
	wpabuf_put_data(*buf, data, len);
	return 0;
}

struct radius_parser_struct
{
	u8 *data;
	size_t len;
	size_t pos;
};

radius_parser radius_parser_start(void *tlvdata, size_t len)
{
	radius_parser parser = malloc(sizeof(struct radius_parser_struct));
	if (parser) {
		parser->data = (u8 *)tlvdata;
		parser->len = len;
		parser->pos = 0;
	}
	return parser;
}

void radius_parser_finish(radius_parser parser)
{
	free(parser);
}

int radius_parser_parse_tlv(radius_parser parser, u8 *type, u32 *vendor_id,
			    void **value, size_t *len)
{
	u8 rawtype, rawlen;
	if (!parser)
		return -1;
	if (parser->len < parser->pos + 3)
		return -1;
	rawtype = parser->data[parser->pos];
	rawlen = parser->data[parser->pos+1];
	if (parser->len < parser->pos + rawlen)
		return -1;

	if (rawtype == RADIUS_ATTR_VENDOR_SPECIFIC) {
		if (rawlen < 7)
			return -1;
		*vendor_id = WPA_GET_BE24(&parser->data[parser->pos + 3]);
		*value = &parser->data[parser->pos + 6];
		*len = rawlen - 6;
	} else {
		if (rawlen < 3)
			return -1;

		*value = &parser->data[parser->pos + 2];
		*len = rawlen - 2;
	}
	*type = rawtype;

	parser->pos += rawlen;
	return 0;
}

int radius_parser_parse_vendor_specific(radius_parser parser, u8 *vendor_type,
					void **value, size_t *len)
{
	u8 rawtype, rawlen;
	if (!parser)
		return -1;
	if (parser->len < parser->pos + 3)
		return -1;
	rawtype = parser->data[parser->pos];
	rawlen = parser->data[parser->pos+1];
	if (parser->len < parser->pos + rawlen)
		return -1;

	if (rawlen < 3)
		return -1;

	*value = &parser->data[parser->pos + 2];
	*len = rawlen - 2;
	*vendor_type = rawtype;

	parser->pos += rawlen;
	return 0;
}
