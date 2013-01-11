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
 * Test DSA/RSA.
 */

static char
DsaPublicKey[] =
"{\"algorithm\":\"DS\",\"version\":\"2012.08.15\",\"y\":\"EgxmUUA4YD/wNDJH3mX+QTIiIwDtn2cAaCkXr0HGKFN3eTuoOqt6iCvTXEkFZCSIog9ml6wKIasJO8mcT+ZVD+40oD+CXKeRJ7LXPnpSuB5rSvgUxEtVY4/8wWra5RnhoHn8BOgb6tq/zOn9EEV6nE6h/t4rVb/dLW1QTono1Q8=\",\"p\":\"/2AEg9tqv8W0Xqt4WUs1M9VQ2fG/Kpkqeo2qbcNPgEWtTm4MQp0zTu6q79fiPUgQvgDkzBSSy6MluoH/LVpbMFqNF+s79KBqNJ05LgDTKXRKUXk4A0ToKhjEeTNDj4keIq7vgS1pyPdeMmy3DqAAw/d239vWBGOMLvcX/CbQLhc=\",\"q\":\"4h4E+RHR7XmRAI7Kqzv3dZhDCcM=\",\"g\":\"xSpKD/O35h/fGGfOhBODaaYVT0r6kpZuPIJ+Jc+mz1CLkOXeQZ4TN+B6Lp4qPNXepwTRdfjr9q85fWnhELlq+xfHoDJZMp5IKbDQO7x4lrFbSt5T4TCFjMNNliaaqJBB9AkTbHJCo4iVydW8ytTzia8dekvROYvQct/6iWIzOXo=\"}";

static char
DsaSecretKey[] = "{\"algorithm\":\"DS\",\"version\":\"2012.08.15\",\"x\":\"rwzgsSIrU6h+BleE/2wDM7sZZtk=\",\"p\":\"/2AEg9tqv8W0Xqt4WUs1M9VQ2fG/Kpkqeo2qbcNPgEWtTm4MQp0zTu6q79fiPUgQvgDkzBSSy6MluoH/LVpbMFqNF+s79KBqNJ05LgDTKXRKUXk4A0ToKhjEeTNDj4keIq7vgS1pyPdeMmy3DqAAw/d239vWBGOMLvcX/CbQLhc=\",\"q\":\"4h4E+RHR7XmRAI7Kqzv3dZhDCcM=\",\"g\":\"xSpKD/O35h/fGGfOhBODaaYVT0r6kpZuPIJ+Jc+mz1CLkOXeQZ4TN+B6Lp4qPNXepwTRdfjr9q85fWnhELlq+xfHoDJZMp5IKbDQO7x4lrFbSt5T4TCFjMNNliaaqJBB9AkTbHJCo4iVydW8ytTzia8dekvROYvQct/6iWIzOXo=\"}";

static unsigned char
RsaModulus[] =
{ 161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141, 
  45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240,
  36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139,    
  217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230,   
  124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154,    
  220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25, 
  184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119,   
  105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98,  
  148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189,    
  210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1,  
  179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109,   
  39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185,    
  207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94,  
  248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100,   
  193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235,    
  156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131,     
  102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31,   
  100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182, 
  134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154,     
  139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154,  
  24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207,    
  117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158,    
  33, 224, 84, 86, 202, 229, 233, 161 };

static unsigned char
RsaExponent[] = { 1, 0, 1 };

static unsigned char
RsaPrivateExponent[] =
{ 18, 174, 113, 164, 105, 205, 10, 43, 195, 126, 82,   
  108, 69, 0, 87, 31, 29, 97, 117, 29, 100, 233, 73,    
  112, 123, 98, 89, 15, 157, 11, 165, 124, 150, 60, 64, 
  30, 63, 207, 47, 44, 211, 189, 236, 136, 229, 3, 191, 
  198, 67, 155, 11, 40, 200, 47, 125, 55, 151, 103, 31, 
  82, 19, 238, 216, 193, 90, 37, 216, 213, 206, 160, 2, 
  94, 227, 171, 46, 139, 127, 121, 33, 111, 198, 59,    
  234, 86, 39, 83, 180, 6, 68, 198, 161, 81, 39, 217,   
  178, 149, 69, 64, 160, 187, 225, 163, 5, 86, 152, 45, 
  78, 159, 222, 95, 100, 37, 241, 77, 75, 113, 52, 65,  
  181, 93, 199, 59, 155, 74, 237, 204, 146, 172, 227,   
  146, 126, 55, 245, 125, 12, 253, 94, 117, 129, 250,   
  81, 44, 143, 73, 97, 169, 235, 11, 128, 248, 168, 7,  
  70, 114, 138, 85, 255, 70, 71, 31, 52, 37, 6, 59,     
  157, 83, 100, 47, 94, 222, 30, 132, 214, 19, 8, 26,   
  250, 92, 34, 208, 81, 40, 91, 214, 59, 148, 59, 86,   
  93, 137, 138, 5, 104, 84, 19, 229, 60, 60, 108, 101,  
  37, 255, 31, 227, 78, 61, 220, 112, 240, 213, 100,    
  80, 253, 164, 139, 161, 46, 16, 78, 157, 235, 159,    
  184, 24, 129, 225, 196, 189, 242, 93, 146, 71, 244,   
  80, 200, 101, 146, 121, 104, 231, 115, 52, 244, 65,   
  79, 117, 167, 80, 225, 57, 84, 110, 58, 138, 115,     
  157 };

static unsigned char
RsaSignatureTestVector[] = {
   112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69,
   243, 65, 6, 174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125,
   131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115, 162, 102, 62, 81,
   102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
   229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
   61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
   16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
   190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244,
   74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
   48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25, 129,
   253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
   177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
   173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157,
   105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
   34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202,
   234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
   193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238,
   251, 71
};

static char
SamplePlaintext[] = {
123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
   32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
   48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
   109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
   111, 116, 34, 58, 116, 114, 117, 101, 125, 0 };

//SamplePlaintext[] = "{\"iss\":\"joe\",\n \"exp\":1300819380,\n \"http://example.com/is_root\":true}";

static void
SetHexJsonStr(json_t *obj, const char *key, unsigned char *data, size_t len)
{
    char hex[BUFSIZ];
    int i;

    BID_ASSERT(len <= sizeof(hex) / 2);

    for (i = 0; i < len; i++)
        snprintf(&hex[i * 2], 3, "%02x", data[i] & 0xff);

    json_object_set_new(obj, key, json_string(hex));
}

static BIDError
TestRsaSignVerify(BIDContext context)
{
    BIDError err = BID_S_OK;
    json_t *public = NULL;
    json_t *secret = NULL;
    json_t *plaintext = NULL;
    json_error_t error;
    BIDJWT jwt = NULL;
    BIDJWT verify = NULL;
    char *encodedData = NULL;
    size_t encodedDataLen;

    public = json_object();
    secret = json_incref(public);

    SetHexJsonStr(public, "n", RsaModulus, sizeof(RsaModulus));
    SetHexJsonStr(public, "e", RsaExponent, sizeof(RsaExponent));
    SetHexJsonStr(secret, "d", RsaPrivateExponent, sizeof(RsaPrivateExponent));
    _BIDJsonObjectSet(context, secret, "algorithm", json_string("RS"), BID_JSON_FLAG_CONSUME_REF);

    plaintext = json_loads(SamplePlaintext, 0, &error);
    if (plaintext == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    jwt = BIDCalloc(1, sizeof(*jwt));
    jwt->Payload = json_incref(plaintext);

    err = _BIDMakeSignature(context, jwt, secret, NULL, &encodedData, &encodedDataLen);
    BID_BAIL_ON_ERROR(err);

    printf("Signed JWT:\n%s\n", encodedData);

    err = _BIDParseJWT(context, encodedData, &verify);
    BID_BAIL_ON_ERROR(err);

    printf("JWT signature length: %ld Test vector length: %ld Alg %s\n",
           verify->SignatureLength, sizeof(RsaSignatureTestVector), json_string_value(json_object_get(verify->Header, "alg")));

    err = _BIDVerifySignature(context, jwt, public);
    BID_BAIL_ON_ERROR(err);

    printf("Verification status %d\n", err);

cleanup:
    json_decref(public);
    json_decref(secret);
    json_decref(plaintext);
    _BIDReleaseJWT(context, jwt);
    _BIDReleaseJWT(context, verify);
    BIDFree(encodedData);

    return err;
}

static BIDError
TestDsaSignVerify(BIDContext context, const char *PublicKey, const char *SecretKey)
{
    BIDError err = BID_S_OK;
    json_t *public = NULL;
    json_t *secret = NULL;
    json_t *plaintext = NULL;
    json_error_t error;
    BIDJWT jwt = NULL;
    BIDJWT verify = NULL;
    char *encodedData = NULL;
    size_t encodedDataLen;

    public = json_loads(PublicKey, 0, &error);
    if (public == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    secret = json_loads(SecretKey, 0, &error);
    if (secret == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    plaintext = json_loads(SamplePlaintext, 0, &error);
    if (plaintext == NULL) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    jwt = BIDCalloc(1, sizeof(*jwt));
    jwt->Payload = json_incref(plaintext);

    err = _BIDMakeSignature(context, jwt, secret, NULL, &encodedData, &encodedDataLen);
    BID_BAIL_ON_ERROR(err);

    printf("Signed JWT:\n%s\n", encodedData);

    err = _BIDParseJWT(context, encodedData, &verify);
    BID_BAIL_ON_ERROR(err);

    err = _BIDVerifySignature(context, jwt, public);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(public);
    json_decref(secret);
    json_decref(plaintext);
    _BIDReleaseJWT(context, jwt);
    _BIDReleaseJWT(context, verify);
    BIDFree(encodedData);

    return err;
}

int main(int argc, char *argv[])
{
    BIDError err;
    BIDContext context = NULL;

    err = BIDAcquireContext(BID_CONTEXT_RP, &context);
    BID_BAIL_ON_ERROR(err);

    printf("Test DSA sign = ERROR %d\n", TestDsaSignVerify(context, DsaPublicKey, DsaSecretKey));
#if 0
    printf("Test RSA sign = ERROR %d\n", TestRsaSignVerify(context));
#endif

cleanup:
    BIDReleaseContext(context);
    if (err != BID_S_OK) {
        const char *s;
        BIDErrorToString(err, &s);
        fprintf(stderr, "libbrowserid error %s[%d]\n", s, err);
    }
    exit(err);
}
