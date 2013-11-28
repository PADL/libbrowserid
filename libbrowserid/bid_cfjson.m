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

#include "bid_private.h"
#include "bid_cfjson.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

char *
_BIDCFCopyUTF8String(CFStringRef string)
{
    const char *ptr;
    char *s = NULL;

    ptr = CFStringGetCStringPtr(string, kCFStringEncodingUTF8);
    if (ptr != NULL) {
        _BIDDuplicateString(BID_C_NO_CONTEXT, ptr, &s);
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
    json_t *key = json_string_nocheck(szKey);
    json_t *value = NULL;

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

    CFDictionarySetValue(object, key, value);
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

    CFDictionaryRemoveValue(object, key);
    CFRelease(key);

    return 0;
}

int
json_object_clear(json_t *object)
{
    if (object == NULL ||
        CFGetTypeID(object) != CFDictionaryGetTypeID())
        return -1;

    CFDictionaryRemoveAllValues(object);
    return 0;
}

static void
_json_object_copy_callback(
    const void *key,
    const void *value,
    void *context)
{
    CFDictionarySetValue(context, key, value);
}

int
json_object_update(json_t *object, json_t *other)
{
    if (object == NULL || CFGetTypeID(object) != CFDictionaryGetTypeID() ||
        other == NULL || CFGetTypeID(other) != CFDictionaryGetTypeID())
        return -1;

    CFDictionaryApplyFunction(other, _json_object_copy_callback, object);
    return 0;
}

@interface _BIDJsonObjectIterator : NSObject
@property(nonatomic, retain) NSDictionary *object;
@property(nonatomic, retain) NSEnumerator *enumerator;
@property(nonatomic, assign) NSString *key;
@property(nonatomic, assign) NSObject *value;

+ (instancetype)iteratorWithObject:(json_t *)object;
@end

@implementation _BIDJsonObjectIterator
+ (instancetype)iteratorWithObject:(json_t *)object
{
    _BIDJsonObjectIterator *iterator = [[_BIDJsonObjectIterator alloc] init];

    if (object == NULL || CFGetTypeID(object) != CFDictionaryGetTypeID())
        return nil;

    iterator.object = (__bridge NSDictionary *)object;
    iterator.enumerator = [iterator.object keyEnumerator];
    iterator.key = nil;
    iterator.value = nil;

    if ([iterator nextObject] == nil)
        return nil;

    return iterator;
}

- (BOOL)validate:(const void *)obj
{
    return (__bridge const void *)self.object == obj;
}

- (id)nextObject
{
    if ((self.key = [self.enumerator nextObject]) != nil)
        self.value = self.object[self.key];
    else
        self.value = nil;

    return self.key;
}

- (const char *)keyString
{
    return [self.key UTF8String];
}
@end

void *
json_object_iter(json_t *object)
{
    return (void *)CFBridgingRetain([_BIDJsonObjectIterator iteratorWithObject:object]);
}

#if 0
void *
json_object_iter_at(json_t *object, const char *szKey)
{
}
#endif

void *
json_object_iter_next(json_t *object, void *iter)
{
    _BIDJsonObjectIterator *iterator = (__bridge _BIDJsonObjectIterator *)iter;

    if (![iterator validate:object] ||
        [iterator nextObject] == nil) {
        CFRelease(iter);
        return NULL;
    }

    return iter;
}

const char *
json_object_iter_key(void *iter)
{
    _BIDJsonObjectIterator *iterator = (__bridge _BIDJsonObjectIterator *)iter;

    return [iterator keyString];
}

json_t *
json_object_iter_value(void *iter)
{
    _BIDJsonObjectIterator *iterator = (__bridge _BIDJsonObjectIterator *)iter;

    return (__bridge json_t *)[iterator value];
}

int
json_object_iter_set(json_t *object, void *iter, json_t *value)
{
    _BIDJsonObjectIterator *iterator = (__bridge _BIDJsonObjectIterator *)iter;

    if (![iterator validate:object] || !iterator.key || value == NULL)
        return -1;

    [iterator.object setValue:(__bridge NSObject *)value forKey:iterator.key];

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

    CFArraySetValueAtIndex(array, index, value);

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

    CFArrayAppendValue(array, value);
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

    CFArrayInsertValueAtIndex(array, index, value);
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

    CFArrayRemoveValueAtIndex(array, index);
    return 0;
}

int
json_array_clear(json_t *array)
{
    if (array == NULL ||
        CFGetTypeID(array) != CFArrayGetTypeID())
        return -1;

    CFArrayRemoveAllValues(array);
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

    CFArrayAppendArray(array, other, CFRangeMake(0, CFArrayGetCount(other)));
    return 0;
}

const char *
json_string_value(const json_t *string)
{
    return CFStringGetCStringPtr(string, kCFStringEncodingUTF8);
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
    json_t *newObj;

    if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
        newObj = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, value);
    } else if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        newObj = CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, value);
    } else {
        newObj = NULL;
    }

    return newObj;
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
    NSError *nsError;

    if (data == NULL)
        return NULL;

    object = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&nsError];
    if (error != NULL)
        error->error = nsError ? (CFErrorRef)CFBridgingRetain(nsError) : NULL;

    return (json_t *)CFBridgingRetain(object);
}

json_t *
json_loads(const char *input, size_t flags, json_error_t *error)
{
    NSData *data;

    if (input == NULL)
        return NULL;

    data = [NSData dataWithBytes:input length:strlen(input)];
    return _json_loadd(data, flags, error);
}

json_t *
json_loadf(FILE *input, size_t flags, json_error_t *error)
{
    NSMutableData *data = [[NSMutableData alloc] init];
    char buf[BUFSIZ];
    size_t nread;

    while ((nread = fread(buf, 1, sizeof(buf), input)) != 0) {
        [data appendBytes:buf length:nread];
    }

    if ([data length] == 0 || ferror(input))
        return NULL;

    return _json_loadd(data, flags, error);
}

json_t *
json_load_file(const char *path, size_t flags, json_error_t *error)
{
    NSData *data;

    if (path == NULL)
        return NULL;

    data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    return _json_loadd(data, flags, error);

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

    data = _json_dumpd(json, flags);
    if (data == NULL)
        return NULL;

    string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return _BIDCFCopyUTF8String((__bridge CFStringRef)string);
}

int
json_dumpf(const json_t *json, FILE *output, size_t flags)
{
    NSData *data;

    data = _json_dumpd(json, flags);
    if (data == NULL)
        return -1;

    if (fwrite([data bytes], [data length], 1, output) != 1)
        return -1;

    return 0;
}

int
json_dump_file(const json_t *json, const char *path, size_t flags)
{
    FILE *fp;
    int ret;

    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;

    ret = json_dumpf(json, fp, flags);

    fclose(fp);

    return ret;
}

void
json_set_alloc_funcs(json_malloc_t malloc_fn BID_UNUSED, json_free_t free_fn BID_UNUSED)
{
}
