/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browserid.h"
#include "bid_private.h"

/*
 * Test Base32 encoders.
 */
static void dump(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        printf("%02x", data[i] & 0xff);
    }
    printf("\n");
}

static const unsigned char testData[] = "\x01\x02\x03\x99\x55\xaa\x08";

int main(int argc, char *argv[])
{
    BIDError err;
    unsigned char *data = NULL;
    size_t len;
    char *s = NULL;

    dump(testData, sizeof(testData) - 1);

    err = _BIDBase32UrlEncode(testData, sizeof(testData) - 1, &s, &len);
    if (err == BID_S_OK)
        printf("%s\n", s);
    else
        fprintf(stderr, "Error %d\n", err);

    err = _BIDBase32UrlDecode(s, &data, &len);
    if (err == BID_S_OK) {
        dump(data, len);
    } else
        fprintf(stderr, "Error %d\n", err);

    BIDFree(data);
    data = NULL;

#if 0
    /* should fail */
    err = _BIDBase32UrlDecode("asdfasdfakjsdhfkladsf", &data, &len);
    if (err == BID_S_OK)
        dump(data, len);
    else 
        fprintf(stderr, "(should fail) Error %d\n", err);
#endif

    BIDFree(data);
    BIDFree(s);
    exit(err);
}
