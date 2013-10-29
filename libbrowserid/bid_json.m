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

#ifdef __APPLE__

#include "bid_private.h"
#include "bid_json.h"

#include <WebKit/WebKit.h>

/*
 * This is fairly useless right now as dictionaries can't cross the
 * Objective-C to JavaScript bridge (and as a result we just send the
 * JSON string encoding). However, it's good to do things the right
 * way, and this may be useful in a future iteration.
 */
@interface BIDJsonDictionaryEnumerator : NSEnumerator <BIDJsonInit>
{
@private
    json_t *jsonObject;
    void *jsonIterator;
}
@end

@interface BIDJsonArrayEnumerator : NSEnumerator <BIDJsonInit>
{
@private
    json_t *jsonObject;
    size_t i;
}
@end

static id _BIDNSObjectFromJsonObject(json_t *jsonObject)
{
    id ret;

    if (jsonObject == NULL)
        return nil;

    switch (json_typeof(jsonObject)) {
    case JSON_OBJECT:
        ret = [[[BIDJsonDictionary alloc] initWithJsonObject:jsonObject] autorelease];
        break;
    case JSON_ARRAY:
        ret = [[[BIDJsonArray alloc] initWithJsonObject:jsonObject] autorelease];
        break;
    case JSON_STRING:
        ret = [NSString stringWithCString:json_string_value(jsonObject)];
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
- (id)initWithJsonObject:(json_t *)value
{
    self = [super init];

    jsonObject = json_incref(value);
    jsonIterator = json_object_iter(jsonObject);

    return self;
}

- (void)dealloc
{
    [super dealloc];
    json_decref(jsonObject);
}

- (id)nextObject
{
    NSString *key;

    if (jsonIterator == NULL)
        return nil;

    key = [NSString stringWithCString:json_object_iter_key(jsonIterator)];

    jsonIterator = json_object_iter_next(jsonObject, jsonIterator);

    return key;
}
@end

@implementation BIDJsonArrayEnumerator
- (id)initWithJsonObject:(json_t *)value
{
    self = [super init];

    jsonObject = json_incref(value);
    i = 0;

    return self;
}

- (void)dealloc
{
    [super dealloc];
    json_decref(jsonObject);
}

- (id)nextObject
{
    if (i >= json_array_size(jsonObject))
        return nil;

    return _BIDNSObjectFromJsonObject(json_array_get(jsonObject, i++));
}
@end

@implementation BIDJsonDictionary
+ (BOOL)isKeyExcludedFromWebScript:(const char *)property
{
    return NO;
}

+ (BOOL)isSelectorExcludedFromWebScript:(SEL)selector
{
    if (selector == @selector(keys) ||
        selector == @selector(stringRepresentation))
        return NO;
    return YES;
}

- (id)initWithJsonObject:(json_t *)value
{
    if (!json_is_object(value))
        return nil;

    self = [super init];
    jsonObject = json_incref(value);

    return self;
}

- (void)dealloc
{
    [super dealloc];
    json_decref(jsonObject);
}

- (NSUInteger)count
{
    return json_object_size(jsonObject);
}

- (id)objectForKey:(id)aKey
{
    if (aKey == nil)
        return nil;

    return _BIDNSObjectFromJsonObject(json_object_get(jsonObject, [aKey cString]));
}

- (id)valueForKey:(NSString *)key
{
    return [self objectForKey:key];
}

- (NSEnumerator *)keyEnumerator
{
    return [[[BIDJsonDictionaryEnumerator alloc] initWithJsonObject:jsonObject] autorelease];
}

- (NSArray *)keys
{
    NSMutableArray *keys = [NSMutableArray arrayWithCapacity:json_object_size(jsonObject)];
    NSEnumerator *enumerator = [self keyEnumerator];
    NSString *key;

    while ((key = [enumerator nextObject]) != nil)
        [keys addObject:key];

    return keys;
}

- (NSArray *)attributeKeys
{
    return [self keys];
}

- (NSString *)stringRepresentation
{
    NSString *stringRep;
    char *szJson = json_dumps(jsonObject, JSON_COMPACT);

    if (szJson == NULL)
        return nil;

    stringRep = [NSString stringWithCString:szJson];

    BIDFree(szJson);

    return stringRep;
}

@end

@implementation BIDJsonArray
- (id)initWithJsonObject:(json_t *)value
{
    if (!json_is_array(value))
        return nil;

    self = [super init];
    jsonObject = json_incref(value);

    return self;
}

- (void)dealloc
{
    [super dealloc];
    json_decref(jsonObject);
}

- (NSUInteger)count
{
    return json_array_size(jsonObject);
}

- (id)objectAtIndex:(NSUInteger)index
{
    if (index >= json_array_size(jsonObject))
        [[NSException exceptionWithName:NSRangeException reason:nil userInfo:nil] raise];

    return _BIDNSObjectFromJsonObject(json_array_get(jsonObject, index));
}

- (id)webScriptValueAtIndex:(unsigned)index
{
    return [self objectAtIndex:index];
}

- (NSString *)stringRepresentation
{
    NSString *stringRep;
    char *szJson = json_dumps(jsonObject, JSON_COMPACT);

    if (szJson == NULL)
        return nil;

    stringRep = [NSString stringWithCString:szJson];

    BIDFree(szJson);

    return stringRep;
}
@end

#endif /* __APPLE__ */
