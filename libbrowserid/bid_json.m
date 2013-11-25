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
#include "bid_json.h"

#if TARGET_OS_IPHONE
#include <Foundation/Foundation.h>
#else
#include <WebKit/WebKit.h>
#endif

/*
 * This is fairly useless right now as dictionaries can't cross the
 * Objective-C to JavaScript bridge (and as a result we just send the
 * JSON string encoding). However, it's good to do things the right
 * way, and this may be useful in a future iteration.
 */
@interface BIDJsonDictionaryEnumerator : NSEnumerator <BIDJsonInit>
@end

@interface BIDJsonArrayEnumerator : NSEnumerator <BIDJsonInit>
@end

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

static NSObject *
_BIDNSObjectFromJsonObject(json_t *jsonObject)
{
    NSObject *ret;

    if (jsonObject == NULL)
        return nil;

    switch (json_typeof(jsonObject)) {
    case JSON_OBJECT:
        ret = [[BIDJsonDictionary alloc] initWithJsonObject:jsonObject];
        break;
    case JSON_ARRAY:
        ret = [[BIDJsonArray alloc] initWithJsonObject:jsonObject];
        break;
    case JSON_STRING:
        ret = [NSString stringWithUTF8String:json_string_value(jsonObject)];
        break;
    case JSON_INTEGER:
        ret = [NSNumber numberWithInteger:json_integer_value(jsonObject)];
        break;
    case JSON_REAL:
        ret = [NSNumber numberWithDouble:json_real_value(jsonObject)];
        break;
    case JSON_TRUE:
    case JSON_FALSE:
        ret = [NSNumber numberWithBool:json_is_true(jsonObject)];
        break;
    case JSON_NULL:
        ret = [NSNull null];
        break;
    }

    return ret;
}

@implementation BIDJsonDictionaryEnumerator
{
    json_t *_jsonObject;
    void *_jsonIterator;
}

- (id)initWithJsonObject:(json_t *)value
{
    self = [super init];

    if (self != nil) {
        _jsonObject = json_incref(value);
        _jsonIterator = json_object_iter(_jsonObject);
    }

    return self;
}

- (void)dealloc
{
    json_decref(_jsonObject);
}

- (id)nextObject
{
    NSString *key;

    if (_jsonIterator == NULL)
        return nil;

    key = [NSString stringWithUTF8String:json_object_iter_key(_jsonIterator)];

    _jsonIterator = json_object_iter_next(_jsonObject, _jsonIterator);

    return key;
}
@end

@implementation BIDJsonArrayEnumerator
{
    json_t *_jsonObject;
    size_t _jsonIterator;
}

- (id)initWithJsonObject:(json_t *)value
{
    self = [super init];

    if (self != nil) {
        _jsonObject = json_incref(value);
        _jsonIterator = 0;
    }

    return self;
}

- (void)dealloc
{
    json_decref(_jsonObject);
}

- (id)nextObject
{
    if (_jsonIterator >= json_array_size(_jsonObject))
        return nil;

    return _BIDNSObjectFromJsonObject(json_array_get(_jsonObject, _jsonIterator++));
}
@end

@implementation BIDJsonDictionary
{
    json_t *_jsonObject;
}

#if !TARGET_OS_IPHONE
+ (BOOL)isKeyExcludedFromWebScript:(const char *)BID_UNUSED property
{
    return NO;
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)selector
{
    if (selector == @selector(keys) ||
        selector == @selector(jsonRepresentation))
        return NO;
    return YES;
}
#endif

- (id)initWithJsonObject:(json_t *)value
{
    if (!json_is_object(value))
        return nil;

    self = [super init];
    if (self != nil)
        _jsonObject = json_incref(value);

    return self;
}

- (void)dealloc
{
    json_decref(_jsonObject);
}

- (NSUInteger)count
{
    return json_object_size(_jsonObject);
}

- (id)objectForKey:(id)aKey
{
    char *szKey;
    id ret;

    if (aKey == nil)
        return nil;

    szKey = _BIDCFCopyUTF8String((__bridge CFStringRef)[aKey description]);
    if (szKey == NULL)
        return nil;

    ret = _BIDNSObjectFromJsonObject(json_object_get(_jsonObject, szKey));

    BIDFree(szKey);

    return ret;
}

- (id)valueForKey:(NSString *)key
{
    return [self objectForKey:key];
}

- (NSEnumerator *)keyEnumerator
{
    return [[BIDJsonDictionaryEnumerator alloc] initWithJsonObject:_jsonObject];
}

- (NSArray *)keys
{
    NSMutableArray *keys = [NSMutableArray arrayWithCapacity:json_object_size(_jsonObject)];
    NSEnumerator *enumerator = [self keyEnumerator];
    NSString *key;

    while ((key = [enumerator nextObject]) != nil)
        [keys addObject:key];

    return keys;
}

- (NSArray *)attributeKeys
{
    return self.keys;
}

- (NSString *)jsonRepresentation
{
    NSString *jsonRep;
    char *szJson = json_dumps(_jsonObject, JSON_COMPACT);

    if (szJson == NULL)
        return nil;

    jsonRep = [NSString stringWithUTF8String:szJson];

    BIDFree(szJson);

    return jsonRep;
}

@end

@implementation BIDJsonArray
{
    json_t *_jsonObject;
}

- (id)initWithJsonObject:(json_t *)value
{
    if (!json_is_array(value))
        return nil;

    self = [super init];
    if (self != nil)
        _jsonObject = json_incref(value);

    return self;
}

- (void)dealloc
{
    json_decref(_jsonObject);
}

- (NSUInteger)count
{
    return json_array_size(_jsonObject);
}

- (id)objectAtIndex:(NSUInteger)index
{
    if (index >= json_array_size(_jsonObject))
        [[NSException exceptionWithName:NSRangeException reason:nil userInfo:nil] raise];

    return _BIDNSObjectFromJsonObject(json_array_get(_jsonObject, index));
}

- (id)webScriptValueAtIndex:(unsigned)index
{
    return [self objectAtIndex:index];
}

- (NSString *)jsonRepresentation
{
    NSString *jsonRep;
    char *szJson = json_dumps(_jsonObject, JSON_COMPACT);

    if (szJson == NULL)
        return nil;

    jsonRep = [NSString stringWithUTF8String:szJson];

    BIDFree(szJson);

    return jsonRep;
}
@end

#ifdef HAVE_COREFOUNDATION_CFRUNTIME_H
CFDictionaryRef
_BIDCreateDictionaryFromJsonObject(
    json_t *jsonObject)
{
    NSDictionary *dict = [[BIDJsonDictionary alloc] initWithJsonObject:jsonObject];

    return CFBridgingRetain(dict);
}
#endif /* HAVE_COREFOUNDATION_CFRUNTIME_H */
