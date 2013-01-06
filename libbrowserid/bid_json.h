/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <Foundation/NSDictionary.h>
#include <Foundation/NSArray.h>

#include <jansson.h>

@protocol BIDJsonInit
- (id)initWithJsonObject:(json_t *)value;
@end

@interface BIDJsonDictionary : NSDictionary <BIDJsonInit>
{
@private
    json_t *jsonObject;
}
@end

@interface BIDJsonArray : NSArray <BIDJsonInit>
{
@private
    json_t *jsonObject;
}
@end
