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
 * Portions Copyright (c) 2009-2011 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _BID_CFJSON_H_
#define _BID_CFJSON_H_ 1

#ifdef JANSSON_H
#error <jansson.h> cannot be included at the same time as <cfjson.h>
#endif

#define JANSSON_H 1

#include <CoreFoundation/CoreFoundation.h>

/* because we export these, rename them */
#define json_integer_value  _BID_json_integer_value
#define json_string_value   _BID_json_string_value
#define json_object_get     _BID_json_object_get


typedef void json_t;

#if __LP64__
typedef long long json_int_t;
#define JSON_INTEGER_TYPE kCFNumberLongLongType
#else
typedef long json_int_t;
#define JSON_INTEGER_TYPE kCFNumberLongType
#endif

json_t *json_object(void);
json_t *json_array(void);
json_t *json_string(const char *value);
json_t *json_string_nocheck(const char *value);
json_t *json_integer(json_int_t value);
json_t *json_real(double value);
json_t *json_true(void);
json_t *json_false(void);
json_t *json_null(void);

#define json_is_object(json)   (json && CFGetTypeID(json) == CFDictionaryGetTypeID())
#define json_is_array(json)    (json && CFGetTypeID(json) == CFArrayGetTypeID())
#define json_is_string(json)   (json && CFGetTypeID(json) == CFStringGetTypeID())
#define json_is_integer(json)  (json && CFGetTypeID(json) == CFNumberGetTypeID() && CFNumberGetType(json) == JSON_INTEGER_TYPE)
#define json_is_real(json)     (json && CFGetTypeID(json) == CFNumberGEtTypeID() && CFNumberGetType(json) == kCFNumberDoubleType)
#define json_is_number(json)   (json && CFGEtTypeID(json) == CFNumberGetTypeID())
#define json_is_true(json)     (json && CFGetTypeID(json) == CFBooleanGetTypeID() && CFBooleanGetValue(json))
#define json_is_false(json)    (json && CFGetTypeID(json) == CFBooleanGetTypeID() && !CFBooleanGetValue(json))
#define json_is_boolean(json)  (json && CFGetTypeID(json) == CFBooleanGetTypeID())
#define json_is_null(json)     (json && CFGetTypeID(json) == CFNullGetTypeID())

static inline
json_t *json_incref(json_t *json)
{
    if (json)
        return (json_t *)CFRetain(json);
    return NULL;
}

static inline
void json_decref(json_t *json)
{
    if (json)
        CFRelease(json);
}

#define JSON_ERROR_TEXT_LENGTH    160
#define JSON_ERROR_SOURCE_LENGTH   80

typedef struct {
    int line;
    int column;
    int position;
    char source[JSON_ERROR_SOURCE_LENGTH];
    char text[JSON_ERROR_TEXT_LENGTH];
} json_error_t;

size_t json_object_size(const json_t *object);
json_t *json_object_get(const json_t *object, const char *key);
int json_object_set_new(json_t *object, const char *key, json_t *value);
int json_object_set_new_nocheck(json_t *object, const char *key, json_t *value);
int json_object_del(json_t *object, const char *key);
int json_object_clear(json_t *object);
int json_object_update(json_t *object, json_t *other);
void *json_object_iter(json_t *object);
void *json_object_iter_at(json_t *object, const char *key);
void *json_object_iter_next(json_t *object, void *iter);
const char *json_object_iter_key(void *iter);
json_t *json_object_iter_value(void *iter);
int json_object_iter_set_new(json_t *object, void *iter, json_t *value);


int json_object_set(json_t *object, const char *key, json_t *value);
int json_object_set_nocheck(json_t *object, const char *key, json_t *value);
int json_object_iter_set(json_t *object, void *iter, json_t *value);

size_t json_array_size(const json_t *array);
json_t *json_array_get(const json_t *array, size_t index);
int json_array_set_new(json_t *array, size_t index, json_t *value);
int json_array_append_new(json_t *array, json_t *value);
int json_array_insert_new(json_t *array, size_t index, json_t *value);
int json_array_remove(json_t *array, size_t index);
int json_array_clear(json_t *array);
int json_array_extend(json_t *array, json_t *other);

int json_array_set(json_t *array, size_t index, json_t *value);
int json_array_append(json_t *array, json_t *value);
int json_array_insert(json_t *array, size_t index, json_t *value);

const char *json_string_value(const json_t *string);
json_int_t json_integer_value(const json_t *integer);
double json_real_value(const json_t *real);
double json_number_value(const json_t *json);

int json_string_set(json_t *string, const char *value);
int json_string_set_nocheck(json_t *string, const char *value);
int json_integer_set(json_t *integer, json_int_t value);
int json_real_set(json_t *real, double value);


/* pack, unpack */

json_t *json_pack(const char *fmt, ...);
json_t *json_pack_ex(json_error_t *error, size_t flags, const char *fmt, ...);
json_t *json_vpack_ex(json_error_t *error, size_t flags, const char *fmt, va_list ap);

#define JSON_VALIDATE_ONLY  0x1
#define JSON_STRICT         0x2

int json_unpack(json_t *root, const char *fmt, ...);
int json_unpack_ex(json_t *root, json_error_t *error, size_t flags, const char *fmt, ...);
int json_vunpack_ex(json_t *root, json_error_t *error, size_t flags, const char *fmt, va_list ap);


/* equality */

int json_equal(json_t *value1, json_t *value2);


/* copying */

json_t *json_copy(json_t *value);
json_t *json_deep_copy(json_t *value);


/* loading, printing */

json_t *json_loads(const char *input, size_t flags, json_error_t *error);
json_t *json_loadf(FILE *input, size_t flags, json_error_t *error);
json_t *json_load_file(const char *path, size_t flags, json_error_t *error);

#define JSON_INDENT(n)      (n & 0x1F)
#define JSON_COMPACT        0x20
#define JSON_ENSURE_ASCII   0x40
#define JSON_SORT_KEYS      0x80
#define JSON_PRESERVE_ORDER 0x100

char *json_dumps(const json_t *json, size_t flags);
int json_dumpf(const json_t *json, FILE *output, size_t flags);
int json_dump_file(const json_t *json, const char *path, size_t flags);

/* custom memory allocation */

typedef void *(*json_malloc_t)(size_t);
typedef void (*json_free_t)(void *);

void json_set_alloc_funcs(json_malloc_t malloc_fn, json_free_t free_fn);

char *
_BIDCFCopyUTF8String(CFStringRef string);

#endif /* _BID_CFJSON_H_ */
