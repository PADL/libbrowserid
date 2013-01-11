/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
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

    *pKey = NULL;
    *pCertChain = NULL;

    if (context->RPCertConfig == NULL) {
        err = BID_S_NO_KEY;
        goto cleanup;
    }

    err = _BIDGetCacheObject(context, context->RPCertConfig, "private-key", &privateKeyPath);
    BID_BAIL_ON_ERROR(err);

    err = _BIDGetCacheObject(context, context->RPCertConfig, "certificate", &certificatePath);
    BID_BAIL_ON_ERROR(err);

    if (!json_is_string(privateKeyPath)) {
        err = BID_S_INVALID_JSON;
        goto cleanup;
    }

    err = _BIDLoadX509PrivateKey(context, json_string_value(privateKeyPath), pKey);
    BID_BAIL_ON_ERROR(err);

    rPaths[cPaths++] = json_string_value(certificatePath);

    err = _BIDLoadX509CertificateChain(context, rPaths, cPaths, pCertChain);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(privateKeyPath);
    json_decref(certificatePath);

    return err;
}

BIDError
_BIDValidateX509(
    BIDContext context,
    json_t *certChain)
{
    BIDError err;
    json_t *caCertificateFile = NULL;
    json_t *caCertificateDir = NULL;

    if (!json_is_array(certChain)) {
        err = BID_S_INVALID_PARAMETER;
        goto cleanup;
    }

    _BIDGetCacheObject(context, context->RPCertConfig, "ca-certificate", &caCertificateFile);
    _BIDGetCacheObject(context, context->RPCertConfig, "ca-directory", &caCertificateDir);

    err = _BIDValidateX509CertChain(context, json_string_value(caCertificateFile),
                                    json_string_value(caCertificateDir), certChain);
    BID_BAIL_ON_ERROR(err);

cleanup:
    return err;
}
