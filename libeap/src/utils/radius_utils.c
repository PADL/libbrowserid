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

struct radius_vendor_attr_struct
{
    struct wpabuf *buf;
    u8 *len_pos;
    size_t start;
};

radius_vendor_attr radius_vendor_attr_start(struct wpabuf *buf, u32 vendor)
{
    radius_vendor_attr attr = (radius_vendor_attr )os_zalloc(sizeof(*attr));
    if (!attr)
        return attr;
    attr->buf = buf;
    attr->start = wpabuf_len(buf);
    wpabuf_put_u8(buf, 26);
    attr->len_pos = (u8*)wpabuf_put(buf, 1);
    /* @TODO: Verify high 8 bits of vendor are 0? */
    wpabuf_put_be32(buf, vendor);
    return attr;
}

radius_vendor_attr radius_vendor_attr_add_subtype(radius_vendor_attr attr,
                                                  u8 type,
                                                  u8 *data,
                                                  size_t len)
{
    if (attr == VENDOR_ATTR_INVALID)
        return attr;
    if (len + 2 + (wpabuf_len(attr->buf) - attr->start) > 255) {
        os_free(attr);
        return VENDOR_ATTR_INVALID;
    }
    wpabuf_put_u8(attr->buf, type);
    wpabuf_put_u8(attr->buf, len + 2);
    wpabuf_put_data(attr->buf, data, len);
    return attr;
}

radius_vendor_attr radius_vendor_attr_finish(radius_vendor_attr attr)
{
    /* poke size into correct place and free attr */
    size_t len;
    radius_vendor_attr ret = VENDOR_ATTR_INVALID;
    if (attr == ret)
        return ret;

    len = wpabuf_len(attr->buf) - attr->start;
    if (len < 255) {
        ret = attr;
        *(attr->len_pos) = (u8 )len;
    }
    os_free(attr);
    return ret;
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
	}
	else {
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
