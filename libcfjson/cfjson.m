/*
 * Copyright (c) 2013 PADL Software Pty Ltd
 * Portions Copyright (c) 2009-2011 Petri Lehtinen <petri@digip.org>
 *
 * cfjson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <bid_private.h>

#include "cfjson.h"

/*
 * jansson API-compatible wrapper around CoreFoundation. CoreFoundation and JSON
 * objects can be used interchangeably.
 */

char *
json_string_copy(json_t *string)
{
    const char *ptr;
    char *s = NULL;

    ptr = [(__bridge NSString *)string UTF8String];
    if (ptr != NULL) {
        size_t cbPtr = strlen(ptr) + 1;
        s = BIDMalloc(cbPtr);
        if (s != NULL)
            memcpy(s, ptr, cbPtr);
    } else {
        CFIndex len = CFStringGetLength(string);
        len = 1 + CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
        s = BIDMalloc(len);
        if (s == NULL)
            return NULL;

        if (!CFStringGetCString(string, s, len, kCFStringEncodingUTF8)) {
            BIDFree(s);
            s = NULL;
        }
    }

    return s;
}

json_t *
json_object(void)
{
    return CFDictionaryCreateMutable(kCFAllocatorDefault,
                                     0,
                                     &kCFTypeDictionaryKeyCallBacks,
                                     &kCFTypeDictionaryValueCallBacks);
}

json_t *
json_array(void)
{
    return CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
}

json_t *
json_string(const char *value)
{
    return json_string_nocheck(value);
}

json_t *
json_string_nocheck(const char *value)
{
    return (json_t *)CFStringCreateWithCString(kCFAllocatorDefault, value,
                                               kCFStringEncodingUTF8);
}

json_t *
json_integer(json_int_t value)
{
    return (json_t *)CFNumberCreate(kCFAllocatorDefault, JSON_INTEGER_TYPE, &value);
}

json_t *
json_real(double value)
{
    return (json_t *)CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &value);
}

json_t *
json_true(void)
{
    return (json_t *)kCFBooleanTrue;
}

json_t *
json_false(void)
{
    return (json_t *)kCFBooleanFalse;
}

json_t *
json_null(void)
{
    return (json_t *)kCFNull;
}

size_t
json_object_size(const json_t *object)
{
    return CFDictionaryGetCount(object);
}

json_t *
json_object_get(const json_t *object, const char *szKey)
{
    json_t *key, *value;

    if (object == NULL)
        return NULL;

    key = json_string(szKey);
    if (key == NULL)
        return NULL;

    value = (json_t *)CFDictionaryGetValue(object, key);

    CFRelease(key);

    return value;
}

int
json_object_set_new(json_t *object, const char *szKey, json_t *value)
{
    return json_object_set_new_nocheck(object, szKey, value);
}

int
json_object_set(json_t *object, const char *szKey, json_t *value)
{
    return json_object_set_nocheck(object, szKey, value);
}

int
json_object_set_new_nocheck(json_t *object, const char *szKey, json_t *value)
{
    int ret;

    ret = json_object_set_nocheck(object, szKey, value);
    if (value)
        CFRelease(value);

    return ret;
}

int
json_object_set_nocheck(json_t *object, const char *szKey, json_t *value)
{
    json_t *key;

    if (szKey == NULL || value == NULL) {
        return -1;
    }

    if (object == NULL ||
        CFGetTypeID(object) != CFDictionaryGetTypeID() ||
        object == value) {
        return -1;
    }

    key = json_string_nocheck(szKey);
    if (key == NULL)
        return -1;

    CFDictionarySetValue((CFMutableDictionaryRef)object, key, value);
    CFRelease(key);

    return 0;
}

int
json_object_del(json_t *object, const char *szKey)
{
    json_t *key;

    if (object == NULL ||
        CFGetTypeID(object) != CFDictionaryGetTypeID())
        return -1;

    key = json_string_nocheck(szKey);
    if (key == NULL)
        return -1;

    CFDictionaryRemoveValue((CFMutableDictionaryRef)object, key);
    CFRelease(key);

    return 0;
}

int
json_object_clear(json_t *object)
{
    if (object == NULL ||
        CFGetTypeID(object) != CFDictionaryGetTypeID())
        return -1;

    CFDictionaryRemoveAllValues((CFMutableDictionaryRef)object);
    return 0;
}

static void
_json_object_copy_callback(
    const void *key,
    const void *value,
    void *context)
{
    CFDictionarySetValue((CFMutableDictionaryRef)context, key, value);
}

int
json_object_update(json_t *object, json_t *other)
{
    if (object == NULL || CFGetTypeID(object) != CFDictionaryGetTypeID() ||
        other == NULL || CFGetTypeID(other) != CFDictionaryGetTypeID())
        return -1;

    CFDictionaryApplyFunction((CFMutableDictionaryRef)other,
                              _json_object_copy_callback,
                              (CFMutableDictionaryRef)object);
    return 0;
}

typedef struct json_object_iterator {
    CFTypeRef enumerator;
    CFStringRef key;
    CFTypeRef value;
} json_object_iterator_t;

CF_RETURNS_NOT_RETAINED
static CFStringRef
_json_object_iter_next_object(
    json_t *object,
    json_object_iterator_t *iter)
{
    if (iter == NULL)
        return NULL;

    if ((iter->key = (__bridge CFStringRef)[(__bridge NSEnumerator *)iter->enumerator nextObject]) != NULL)
        iter->value = CFDictionaryGetValue(object, iter->key);
    else
        iter->value = NULL;

    return iter->key;
}

static void
_json_object_iter_release(json_object_iterator_t *iter CF_CONSUMED)
{
    if (iter != NULL) {
        if (iter->enumerator)
            CFRelease(iter->enumerator);
        BIDFree(iter);
    }
}

static json_object_iterator_t *
_json_object_iter_create(json_t *object)
{
    json_object_iterator_t *iter;

    if (object == NULL || CFGetTypeID(object) != CFDictionaryGetTypeID())
        return NULL;

    iter = BIDCalloc(1, sizeof(*iter));
    if (iter == NULL)
        return NULL;

    @autoreleasepool {
        iter->enumerator = CFBridgingRetain([(__bridge NSDictionary *)object keyEnumerator]);
        iter->key = NULL;
        iter->value = NULL;
    }

    if (_json_object_iter_next_object(object, iter) == NULL) {
        _json_object_iter_release(iter);
        return NULL;
    }

    return iter;
}

void *
json_object_iter(json_t *object)
{
    return _json_object_iter_create(object);
}

void *
json_object_iter_at(json_t *object, const char *szKey)
{
    NSString *key = [NSString stringWithUTF8String:szKey];
    json_object_iterator_t *iterator = json_object_iter(object);
    CFStringRef iteratorKey;

    if (iterator == NULL)
        return NULL;

    while ((iteratorKey = _json_object_iter_next_object(object, iterator))) {
        if ([(__bridge NSString *)iteratorKey isEqualToString:key])
            return iterator;
    }

    _json_object_iter_release(iterator);
    return NULL;
}

void *
json_object_iter_next(json_t *object, void *iter)
{
    json_object_iterator_t *iterator = iter;

    if (!_json_object_iter_next_object(object, iterator)) {
        _json_object_iter_release(iterator);
        return NULL;
    }

    return iterator;
}

const char *
json_object_iter_key(void *iter)
{
    json_object_iterator_t *iterator = iter;
    const char *s = NULL;

    if (iterator != NULL && iterator->key != NULL) {
        s = [(__bridge NSString *)iterator->key UTF8String];
        BID_ASSERT(s != NULL);
    }

    return s;
}

json_t *
json_object_iter_value(void *iter)
{
    json_object_iterator_t *iterator = iter;

    return (iterator != NULL) ? (json_t *)iterator->value : NULL;
}

int
json_object_iter_set(json_t *object, void *iter, json_t *value)
{
    json_object_iterator_t *iterator = iter;

    CFDictionarySetValue((CFMutableDictionaryRef)object, iterator->key, value);

    return 0;
}

int
json_object_iter_set_new(json_t *object, void *iter, json_t *value)
{
    int ret;

    ret = json_object_iter_set(object, iter, value);

    if (value)
        CFRelease(value);

    return ret;
}

size_t
json_array_size(const json_t *array)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return 0;

    return CFArrayGetCount(array);
}

json_t *
json_array_get(const json_t *array, size_t index)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return NULL;

    return (json_t *)CFArrayGetValueAtIndex(array, index);
}

int
json_array_set(json_t *array, size_t index, json_t *value)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArraySetValueAtIndex((CFMutableArrayRef)array, index, value);

    return 0;
}

int
json_array_set_new(json_t *array, size_t index, json_t *value)
{
    int ret = json_array_set(array, index, value);

    if (value)
        CFRelease(value);

    return ret;
}

int
json_array_append(json_t *array, json_t *value)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArrayAppendValue((CFMutableArrayRef)array, value);
    return 0;
}

int
json_array_append_new(json_t *array, json_t *value)
{
    int ret = json_array_append(array, value);

    if (value)
        CFRelease(value);

    return ret;
}

int
json_array_insert(json_t *array, size_t index, json_t *value)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArrayInsertValueAtIndex((CFMutableArrayRef)array, index, value);
    return 0;
}

int
json_array_insert_new(json_t *array, size_t index, json_t *value)
{
    int ret = json_array_insert(array, index, value);

    if (value)
        CFRelease(value);

    return ret;
}

int
json_array_remove(json_t *array, size_t index)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArrayRemoveValueAtIndex((CFMutableArrayRef)array, index);
    return 0;
}

int
json_array_clear(json_t *array)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArrayRemoveAllValues((CFMutableArrayRef)array);
    return 0;
}

int
json_array_extend(json_t *array, json_t *other)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID() ||
        other == NULL ||
        CFGetTypeID(other) != CFArrayGetTypeID())
        return -1;

    CFArrayAppendArray((CFMutableArrayRef)array, other,
                       CFRangeMake(0, CFArrayGetCount(other)));
    return 0;
}

const char *
json_string_value(const json_t *string)
{
    return [(__bridge NSString *)string UTF8String];
}

json_int_t
json_integer_value(const json_t *integer)
{
    json_int_t value = 0;

    if (integer != NULL && CFGetTypeID(integer) == CFNumberGetTypeID())
        CFNumberGetValue(integer, JSON_INTEGER_TYPE, &value);

    return value;
}

double
json_real_value(const json_t *real)
{
    double value = 0.0;

    if (real != NULL && CFGetTypeID(real) == CFNumberGetTypeID())
        CFNumberGetValue(real, kCFNumberDoubleType, &value);

    return value;
}

double
json_number_value(const json_t *json)
{
    double dValue;
    json_int_t iValue;

    if (json == NULL || CFGetTypeID(json) != CFNumberGetTypeID())
        return 0.0;

    if (CFNumberGetValue(json, kCFNumberDoubleType, &dValue))
        return dValue;
    else if (CFNumberGetValue(json, JSON_INTEGER_TYPE, &iValue))
        return iValue;
    else
        return 0.0;
}

#if 0
int
json_string_set(json_t *string, const char *value)
{
    return json_string_set_nocheck(string, value);
}

int
json_string_set_nocheck(json_t *string, const char *szValue)
{
    CFStringRef replacement = json_string(szValue);

    if (replacement == NULL)
        return -1;

    CFStringReplaceAll(string, replacement);
    CFRelease(replacement);

    return 0;
}
#endif

#if 0
int
json_integer_set(json_t *integer, json_int_t value)
{
}

int json_real_set(json_t *real, double value)
{
}
#endif

int
json_equal(json_t *value1, json_t *value2)
{
    if (value1 == NULL && value2 == NULL)
        return 1;
    else if (value1 == NULL || value2 == NULL)
        return 0;
    return CFEqual(value1, value2);
}

json_t *
json_copy(json_t *value)
{
    CFTypeRef newObj = NULL;

    if (value != NULL) {
        if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
            newObj = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, value);
        } else if (CFGetTypeID(value) == CFArrayGetTypeID()) {
            newObj = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, value);
        } else if (CFGetTypeID(value) == CFStringGetTypeID()) {
            newObj = CFStringCreateCopy(kCFAllocatorDefault, value);
        }
    }

    return (json_t *)newObj;
}

#if 0
json_t *
json_deep_copy(json_t *value)
{
}
#endif

/* loading, printing */

static json_t *
_json_loadd(NSData *data, size_t flags BID_UNUSED, json_error_t *error)
{
    id object;
    NSError *nsError = NULL;

    if (data == NULL)
        return NULL;

    if (error != NULL)
        memset(error, 0, sizeof(*error));

    object = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&nsError];
    if (nsError != NULL)
        strlcpy(error->text, [nsError.description UTF8String], sizeof(error->text));

    return (json_t *)CFBridgingRetain(object);
}

json_t *
json_loads(const char *input, size_t flags, json_error_t *error)
{
    NSData *data;
    json_t *object;

    if (input == NULL)
        return NULL;

    @autoreleasepool {
        data = [NSData dataWithBytes:input length:strlen(input)];
        object = _json_loadd(data, flags, error);
    }

    return object;
}

json_t *
json_loadcf(CFTypeRef input, size_t flags, json_error_t *error)
{
    json_t *object = NULL;

    if (input == NULL)
        return NULL;

    @autoreleasepool {
        if (CFGetTypeID(input) == CFDataGetTypeID()) {
            object = _json_loadd((__bridge NSData *)input, flags, error);
        } else if (CFGetTypeID(input) == CFStringGetTypeID()) {
            NSData *data = [(__bridge NSString *)input dataUsingEncoding:NSUTF8StringEncoding];
            object = _json_loadd(data, flags, error);
        }
    }

    return object;
}

json_t *
json_loadf(FILE *input, size_t flags, json_error_t *error)
{
    NSMutableData *data;
    char buf[BUFSIZ];
    size_t nread;
    json_t *object;

    @autoreleasepool {
        data = [NSMutableData data];

        while ((nread = fread(buf, 1, sizeof(buf), input)) != 0) {
            [data appendBytes:buf length:nread];
        }

        if ([data length] == 0 || ferror(input))
            return NULL;

        object = _json_loadd(data, flags, error);
    }

    return object;
}

json_t *
json_load_file(const char *path, size_t flags, json_error_t *error)
{
    NSData *data;
    json_t *object;

    if (path == NULL)
        return NULL;

    @autoreleasepool {
        data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
        object = _json_loadd(data, flags, error);
    }

    return object;
}

static NSData *
_json_dumpd(const json_t *json, size_t flags)
{
    NSJSONWritingOptions opt = 0;

    if (json == NULL)
        return NULL;
    if ((flags & JSON_COMPACT) == 0)
        opt |= NSJSONWritingPrettyPrinted;

    return [NSJSONSerialization dataWithJSONObject:(__bridge id)json options:opt error:NULL];
}

char *
json_dumps(const json_t *json, size_t flags)
{
    NSData *data;
    NSString *string;
    NSStringEncoding encoding;
    char *s;

    @autoreleasepool {
        data = _json_dumpd(json, flags);
        if (data == NULL)
            return NULL;

        if (flags & JSON_ENSURE_ASCII)
            encoding = NSASCIIStringEncoding;
        else
            encoding = NSUTF8StringEncoding;

        string = [[NSString alloc] initWithData:data encoding:encoding];
        s = json_string_copy((__bridge CFStringRef)string);

#if !__has_feature(objc_arc)
        [string release];
#endif
    }

    return s;
}

int
json_dumpf(const json_t *json, FILE *output, size_t flags)
{
    NSData *data;

    @autoreleasepool {
        data = _json_dumpd(json, flags);
        if (data == NULL)
            return -1;

        if (fwrite([data bytes], [data length], 1, output) != 1)
            return -1;
    }

    return 0;
}

int
json_dump_file(const json_t *json, const char *path, size_t flags)
{
    FILE *fp;
    int ret;

    @autoreleasepool {
        fp = fopen(path, "w");
        if (fp == NULL)
            return -1;

        ret = json_dumpf(json, fp, flags);

        fclose(fp);
    }

    return ret;
}

void
json_set_alloc_funcs(json_malloc_t malloc_fn BID_UNUSED, json_free_t free_fn BID_UNUSED)
{
}
