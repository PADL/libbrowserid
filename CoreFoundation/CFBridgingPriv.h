//
//  CFBridgeHelper.h
//  CredUI
//
//  Created by Luke Howard on 1/01/2014.
//  Copyright (c) 2014 PADL Software Pty Ltd. All rights reserved.
//

#ifndef CFBridgeHelper_h
#define CFBridgeHelper_h

#include <objc/message.h>
#include <objc/objc-sync.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif
OBJC_EXPORT id objc_msgSend(id self, SEL op, ...) __attribute__((weak_import));

CF_EXPORT Boolean _CFIsObjC(CFTypeID typeID, CFTypeRef obj);
CF_EXPORT void _CFRuntimeBridgeClasses(CFTypeID cf_typeID, const char *objc_classname);
CF_EXPORT CFTypeRef _CFTryRetain(CFTypeRef cf);
CF_EXPORT Boolean _CFIsDeallocating(CFTypeRef cf);
#ifdef __cplusplus
}
#endif

#ifdef __OBJC__

@interface NSObject (CFBridgeHelper)
- (CFTypeID)_cfTypeID;
@end

#define CF_CLASSIMPLEMENTATION(ClassName)                                       \
- (id)retain                                                                    \
{                                                                               \
    return CFRetain((CFTypeRef)self);                                           \
}                                                                               \
                                                                                \
- (oneway void)release                                                          \
{                                                                               \
    CFRelease((CFTypeRef)self);                                                 \
}                                                                               \
                                                                                \
- (NSUInteger)retainCount                                                       \
{                                                                               \
    return CFGetRetainCount((CFTypeRef)self);                                   \
}                                                                               \
                                                                                \
- (BOOL)isEqual:(id)anObject                                                    \
{                                                                               \
    if (anObject == nil)                                                        \
        return NO;                                                              \
    return CFEqual((CFTypeRef)self, (CFTypeRef)anObject);                       \
}                                                                               \
                                                                                \
- (NSUInteger)hash                                                              \
{                                                                               \
    return CFHash((CFTypeRef)self);                                             \
}                                                                               \
                                                                                \
- (BOOL)allowsWeakReference                                                     \
{                                                                               \
    return ![self _isDeallocating];                                             \
}                                                                               \
                                                                                \
- (BOOL)retainWeakReference                                                     \
{                                                                               \
    return [self _tryRetain];                                                   \
}                                                                               \
                                                                                \
- (BOOL)_isDeallocating                                                         \
{                                                                               \
    return _CFIsDeallocating((CFTypeRef)self);                                  \
}                                                                               \
                                                                                \
- (BOOL)_tryRetain                                                              \
{                                                                               \
    return _CFTryRetain((CFTypeRef)self) != NULL;                               \
}                                                                               \
                                                                                \
- (NSString *)description                                                       \
{                                                                               \
    return [NSMakeCollectable(CFCopyDescription((CFTypeRef)self)) autorelease]; \
}                                                                               \

#endif /* __OBJC__ */

/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/*	CFInternal.h
 Copyright (c) 1998-2003, Apple, Inc. All rights reserved.
 */

#ifdef __cplusplus
extern "C" {
#endif
    
#define CF_IS_OBJC(typeID, obj) (objc_msgSend != NULL && _CFIsObjC(typeID, (CFTypeRef)obj))

#define CF_OBJC_CALLV(rettype, var, obj, sel, ...) \
{rettype (*func)(const void *, SEL, ...) = (rettype (*)(const void *, SEL, ...))objc_msgSend; \
static SEL s = NULL; if (!s) s = sel_registerName(sel); \
var = func((const void *)obj, s, ##__VA_ARGS__ );}

#define CF_OBJC_VOIDCALLV(obj, sel, ...) \
{void (*func)(const void *, SEL, ...) = (void (*)(const void *, SEL, ...))objc_msgSend; \
static SEL s = NULL; if (!s) s = sel_registerName(sel); \
func((const void *)obj, s, ##__VA_ARGS__ );}

#define CF_OBJC_FUNCDISPATCHV(typeID, rettype, obj, sel, ...) \
if (CF_IS_OBJC(typeID, obj)) \
{rettype (*func)(const void *, SEL, ...) = (rettype (*)(const void *, SEL, ...))objc_msgSend; \
static SEL s = NULL; if (!s) s = sel_registerName(sel); \
return func((const void *)obj, s, ##__VA_ARGS__ );}
    
#define CF_OBJC_KVO_WILLCHANGE(obj, key) \
if (objc_msgSend != NULL) \
{void (*func)(const void *, SEL, CFStringRef) = (void (*)(const void *, SEL, CFStringRef))objc_msgSend; \
static SEL s = NULL; if (!s) s = sel_registerName("willChangeValueForKey:"); \
func((const void *)obj, s, (key));}

#define CF_OBJC_KVO_DIDCHANGE(obj, key) \
if (objc_msgSend != NULL) \
{void (*func)(const void *, SEL, CFStringRef) = (void (*)(const void *, SEL, CFStringRef))objc_msgSend; \
static SEL s = NULL; if (!s) s = sel_registerName("didChangeValueForKey:"); \
func((const void *)obj, s, (key));}
    
#ifdef __cplusplus
}
#endif

#endif
