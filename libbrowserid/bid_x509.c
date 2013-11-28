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

static BIDError
_BIDLoadX509CertificateChain(
    BIDContext context,
    const char **rPaths,
    size_t nPaths,
    json_t **pCertChain)
{
    BIDError err;
    json_t *certChain = NULL;
    size_t i;

    certChain = json_array();
    if (certChain == NULL)
        return BID_S_NO_MEMORY;

    for (i = 0; i < nPaths; i++) {
        json_t *cert;

        if (rPaths[i] == NULL) {
            json_decref(certChain);
            return BID_S_INVALID_PARAMETER;
        }

        err = _BIDLoadX509Certificate(context, rPaths[i], &cert);
        if (err != BID_S_OK) {
            json_decref(certChain);
            return err;
        }

        json_array_append_new(certChain, cert);
    }

    *pCertChain = certChain;

    return BID_S_OK;
}

BIDError
_BIDGetRPPrivateKey(
    BIDContext context,
    BIDJWK *pKey,
    json_t **pCertChain)
{
    BIDError err;
    json_t *privateKeyPath = NULL;
    json_t *certificatePath = NULL;
    const char *rPaths[1] = { 0 };
    size_t cPaths = 0;

    if (pKey != NULL)
        *pKey = NULL;
    if (pCertChain != NULL)
        *pCertChain = NULL;

    if (context->Config == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    err = _BIDGetCacheObject(context, context->Config,
                            "certificate", &certificatePath);
    BID_BAIL_ON_ERROR(err);

    if (!json_is_string(certificatePath)) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    /*
     * We allow these to fail; the crypto provider may be able to
     * determine the private key from the certificate.
     */
    _BIDGetCacheObject(context, context->Config,
                       "private-key", &privateKeyPath);

    if (pKey != NULL) {
        err = _BIDLoadX509PrivateKey(context,
                                     json_string_value(privateKeyPath),
                                     json_string_value(certificatePath),
                                     pKey);
        BID_BAIL_ON_ERROR(err);

        BID_ASSERT(*pKey != NULL);
    }

    rPaths[cPaths++] = json_string_value(certificatePath);

    if (pCertChain != NULL) {
        err = _BIDLoadX509CertificateChain(context, rPaths, cPaths, pCertChain);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    json_decref(privateKeyPath);
    json_decref(certificatePath);

    return err;
}

int
_BIDCanMutualAuthP(BIDContext context)
{
    return (_BIDGetRPPrivateKey(context, NULL, NULL) == BID_S_OK);
}

BIDError
_BIDValidateX509(
    BIDContext context,
    json_t *certChain,
    json_t *certAnchors,
    time_t verificationTime)
{
    BIDError err;
    json_t *certParams = NULL;
    json_t *caCertificateFile = NULL;
    json_t *caCertificateDir = NULL;

    if (!json_is_array(certChain)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    /*
     * We make a copy of the relevant parameters as in a future iteration
     * we may also add the user's trust anchors, which will be context-
     * specific rather than being stored in the global RP configuration.
     */
    certParams = (certAnchors != NULL) ? json_copy(certAnchors) : json_object();
    if (certParams == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (_BIDGetCacheObject(context, context->Config,
                           "ca-certificate", &caCertificateFile) == BID_S_OK) {
        err = _BIDJsonObjectSet(context, certParams, "ca-certificate",
                                caCertificateFile, 0);
        BID_BAIL_ON_ERROR(err);
    }

    if (_BIDGetCacheObject(context, context->Config,
                           "ca-directory", &caCertificateDir) == BID_S_OK) {
        err = _BIDJsonObjectSet(context, certParams, "ca-directory",
                                caCertificateDir, 0);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDValidateX509CertChain(context, certChain, certParams,
                                    verificationTime);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(certParams);

    return err;
}
