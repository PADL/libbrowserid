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
 *    how to obtain complete source code for the libbrowserid software
 *    and any accompanying software that uses the libbrowserid software.
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

#ifdef HAVE_CFNETWORK_CFNETWORK_H

#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>

static BIDError
_BIDCreateHttpDateFormatter(CFDateFormatterRef *pDateFormatter)
{
    CFLocaleRef locale = NULL;

    locale = CFLocaleCreate(NULL, CFSTR("en_US"));
    if (locale == NULL)
        return BID_S_NO_MEMORY;

    *pDateFormatter = CFDateFormatterCreate(kCFAllocatorDefault, locale,
                                            kCFDateFormatterNoStyle, kCFDateFormatterNoStyle);

    if (*pDateFormatter == NULL) {
        CFRelease(locale);
        return BID_S_NO_MEMORY;
    }

    CFDateFormatterSetFormat(*pDateFormatter, CFSTR("EEE',' dd MMM yyyy HH':'mm':'ss 'GMT'"));

    CFRelease(locale);

    return BID_S_OK;
}

static BIDError
_BIDHttpMessageSetHeaderDate(
    BIDContext context BID_UNUSED,
    CFHTTPMessageRef request,
    CFStringRef header,
    time_t time)
{
    BIDError err;
    CFDateFormatterRef dateFormatter = NULL;
    CFDateRef dateRef = NULL;
    CFStringRef dateAsString = NULL;

    dateRef = CFDateCreate(kCFAllocatorDefault, time - kCFAbsoluteTimeIntervalSince1970);
    if (dateRef == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDCreateHttpDateFormatter(&dateFormatter);
    BID_BAIL_ON_ERROR(err);

    dateAsString = CFDateFormatterCreateStringWithDate(kCFAllocatorDefault,
                                                       dateFormatter, dateRef);
    if (dateAsString == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    CFHTTPMessageSetHeaderFieldValue(request, header, dateAsString);

    err = BID_S_OK;

cleanup:
    if (dateFormatter != NULL)
        CFRelease(dateFormatter);
    if (dateRef != NULL)
        CFRelease(dateRef);
    if (dateAsString != NULL)
        CFRelease(dateAsString);

    return err;
}

static BIDError
_BIDHttpMessageGetHeaderDate(
    BIDContext context BID_UNUSED,
    CFHTTPMessageRef response,
    CFStringRef header,
    time_t *pTime)
{
    BIDError err;
    CFDateFormatterRef dateFormatter = NULL;
    CFStringRef dateAsString = NULL;
    CFAbsoluteTime date = 0;

    *pTime = 0;

    dateAsString = CFHTTPMessageCopyHeaderFieldValue(response, header);
    if (dateAsString == NULL) {
        err = BID_S_UNKNOWN_JSON_KEY;
        goto cleanup;
    }

    err = _BIDCreateHttpDateFormatter(&dateFormatter);
    BID_BAIL_ON_ERROR(err);

    if (!CFDateFormatterGetAbsoluteTimeFromString(dateFormatter, dateAsString, NULL, &date)) {
        err = BID_S_HTTP_ERROR;
        goto cleanup;
    }

    *pTime = date + kCFAbsoluteTimeIntervalSince1970;
    err = BID_S_OK;

cleanup:
    if (dateFormatter != NULL)
        CFRelease(dateFormatter);
    if (dateAsString != NULL)
        CFRelease(dateAsString);

    return err;
}

static BIDError
_BIDAllocHttpMessage(
    BIDContext context BID_UNUSED,
    CFStringRef method,
    CFURLRef url,
    CFHTTPMessageRef *pRequest)
{
    BIDError err;
    CFHTTPMessageRef request = NULL;
    CFStringRef host = NULL;

    *pRequest = NULL;

    request = CFHTTPMessageCreateRequest(kCFAllocatorDefault, method, url, kCFHTTPVersion1_1);
    if (request == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    host = CFURLCopyHostName(url);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Host"), host);

    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Accept"), CFSTR("application/json"));

    err = BID_S_OK;

    *pRequest = request;
    request = NULL;

cleanup:
    if (host != NULL)
        CFRelease(host);
    if (request != NULL)
        CFRelease(request);

    return err;
}

static BIDError
_BIDMakeHttpRequest(
    BIDContext context,
    CFHTTPMessageRef request,
    json_t **pJsonDoc,
    time_t *pExpiryTime)
{
    BIDError err;
    CFStringRef userAgent = NULL;
    CFDataRef serializedRequest = NULL;
    CFReadStreamRef readStream = NULL;
    CFHTTPMessageRef response = NULL;
    CFMutableDataRef responseData = NULL;
    CFIndex n = 0;
    CFDataRef responseBody = NULL;
    CFStringRef responseString = NULL;

    userAgent = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
                                         CFSTR("libbrowserid/%s"), VERS_NUM);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("User-Agent"), userAgent);

    serializedRequest = CFHTTPMessageCopySerializedMessage(request);

    readStream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, request);
    if (readStream == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    CFReadStreamSetProperty(readStream, kCFStreamPropertyHTTPShouldAutoredirect,
                            kCFBooleanTrue);

    if (!CFReadStreamOpen(readStream)) {
        err = BID_S_HTTP_ERROR;
        goto cleanup;
    }

    responseData = CFDataCreateMutable(kCFAllocatorDefault, 0);
    if (responseData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    do {
        unsigned char buf[BUFSIZ];

        n = CFReadStreamRead(readStream, buf, sizeof(buf));
        if (n > 0)
            CFDataAppendBytes(responseData, buf, n);
    } while (n > 0);

    if (n < 0) {
        err = BID_S_HTTP_ERROR;
        goto cleanup;
    }

    response = (CFHTTPMessageRef)
        CFReadStreamCopyProperty(readStream, kCFStreamPropertyHTTPResponseHeader);
    CFHTTPMessageSetBody(response, responseData);

    switch (CFHTTPMessageGetResponseStatusCode(response)) {
    case 304:
        err = BID_S_DOCUMENT_NOT_MODIFIED;
        break;
    case 200:
        err = BID_S_OK;
        break;
    default:
        err = BID_S_HTTP_ERROR;
        break;
    }
    BID_BAIL_ON_ERROR(err);

    responseBody = CFHTTPMessageCopyBody(response);
    responseString = CFStringCreateFromExternalRepresentation(kCFAllocatorDefault,
                                                              responseBody, kCFStringEncodingUTF8);
    *pJsonDoc = json_loadcf(responseString, 0, &context->JsonError);
    if (*pJsonDoc == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    if (pExpiryTime != NULL) {
        err = _BIDHttpMessageGetHeaderDate(context, response, CFSTR("Expires"), pExpiryTime);
        if (err != BID_S_OK) {
            err = _BIDHttpMessageGetHeaderDate(context, response, CFSTR("Date"), pExpiryTime);
            if (err == BID_S_OK)
                *pExpiryTime += 60 * 60 * 24;
            else
                *pExpiryTime = 0;
        }
    }

    err = BID_S_OK;

cleanup:
    if (userAgent != NULL)
        CFRelease(userAgent);
    if (serializedRequest != NULL)
        CFRelease(serializedRequest);
    if (readStream != NULL) {
        if (CFReadStreamGetStatus(readStream) != kCFStreamStatusNotOpen)
            CFReadStreamClose(readStream);
        CFRelease(readStream);
    }
    if (responseData != NULL)
        CFRelease(responseData);
    if (response != NULL)
        CFRelease(response);
    if (responseBody != NULL)
        CFRelease(responseBody);
    if (responseString != NULL)
        CFRelease(responseString);

    return err;
}

BIDError
_BIDRetrieveDocument(
    BIDContext context,
    const char *szHostname,
    const char *szRelativeUrl,
    time_t tIfModifiedSince,
    json_t **pJsonDoc,
    time_t *pExpiryTime)
{
    BIDError err;
    CFStringRef urlString = NULL;
    CFURLRef url = NULL;
    CFHTTPMessageRef request = NULL;

    *pJsonDoc = NULL;
    if (pExpiryTime != NULL)
        *pExpiryTime = 0;

    BID_CONTEXT_VALIDATE(context);

    urlString = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
                                         CFSTR("https://%s%s"),
                                         szHostname, szRelativeUrl);
    if (urlString == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    url = CFURLCreateWithString(kCFAllocatorDefault, urlString, NULL);
    if (url == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDAllocHttpMessage(context, CFSTR("GET"), url, &request);
    BID_BAIL_ON_ERROR(err);

    _BIDHttpMessageSetHeaderDate(context, request, CFSTR("If-Modified-Since"), tIfModifiedSince);

    err = _BIDMakeHttpRequest(context, request, pJsonDoc, pExpiryTime);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (urlString != NULL)
        CFRelease(urlString);
    if (url != NULL)
        CFRelease(url);
    if (request != NULL)
        CFRelease(request);

    return err;
}

BIDError
_BIDPostDocument(
    BIDContext context,
    const char *szUrl,
    const char *szPostFields,
    json_t **pJsonDoc)
{
    BIDError err;
    CFURLRef url = NULL;
    CFHTTPMessageRef request = NULL;
    CFDataRef bodyData = NULL;
    CFStringRef contentLength = NULL;

    *pJsonDoc = NULL;

    BID_CONTEXT_VALIDATE(context);

    url = CFURLCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)szUrl,
                               strlen(szUrl), kCFStringEncodingUTF8, NULL);
    if (url == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDAllocHttpMessage(context, CFSTR("POST"), url, &request);
    BID_BAIL_ON_ERROR(err);

    bodyData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const UInt8 *)szPostFields,
                                           strlen(szPostFields), kCFAllocatorNull);
    if (bodyData == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    CFHTTPMessageSetBody(request, bodyData);
    contentLength = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%ld"), CFDataGetLength(bodyData));
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Content-Length"), contentLength);
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Content-Type"), CFSTR("application/x-www-form-urlencoded"));

    err = _BIDMakeHttpRequest(context, request, pJsonDoc, NULL);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (url != NULL)
        CFRelease(url);
    if (request != NULL)
        CFRelease(request);
    if (bodyData != NULL)
        CFRelease(bodyData);
    if (contentLength != NULL)
        CFRelease(contentLength);

    return err;
}
#endif /* HAVE_CFNETWORK_CFNETWORK_H */
