/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#include <MsHtml.h>
#include <MsHtmlc.h>
#include <MsHtmHst.h>

/*
 * Internet Explorer implementation of the browser shim.
 */

static const char *_BIDHTMLOnLoadScript = "                                                         \
    var controller = JSON.parse(window.dialogArguments);                                            \
    var jwcrypto = require('./lib/jwcrypto');                                                       \
    var assertionSign = jwcrypto.assertion.sign;                                                    \
                                                                                                    \
    jwcrypto.assertion.sign = function(payload, assertionParams, secretKey, cb) {                   \
        var gssPayload = controller.claims;                                                         \
        for (var k in payload) {                                                                    \
            if (payload.hasOwnProperty(k)) gssPayload[k] = payload[k];                              \
        }                                                                                           \
        assertionSign(gssPayload, assertionParams, secretKey, cb);                                  \
    };                                                                                              \
                                                                                                    \
    var options = { siteName: controller.siteName, silent: controller.silent,                       \
                    requiredEmail: controller.requiredEmail };                                      \
                                                                                                    \
    if (controller.servicePrincipalName) {                                                          \
        BrowserID.User.getHostname = function() { return controller.servicePrincipalName; };        \
    }                                                                                               \
                                                                                                    \
    BrowserID.internal.setPersistent(                                                               \
        controller.audience,                                                                        \
        function() {                                                                                \
            BrowserID.internal.get(                                                                 \
                controller.audience,                                                                \
                function(assertion, params) {                                                       \
                    window.returnValue = assertion;                                                 \
                    window.close();                                                                 \
                },                                                                                  \
                options);                                                                           \
    });                                                                                             \
";

static BIDError
_BIDSpnToSiteName(
    BIDContext context,
    const char *spn,
    char **pszSiteName)
{
    const char *pStart, *pEnd;
    size_t cchSiteName = 0;
    char *szSiteName = NULL;

    *pszSiteName = NULL;

    pStart = strchr(spn, '/');
    if (pStart != NULL)
        pStart++;
    else
        pStart = spn;

    if (pStart != spn && pStart != NULL) {
        pEnd = strchr(pStart, '/');
        if (pEnd != NULL)
            cchSiteName = pEnd - pStart;
    }

    if (cchSiteName == 0)
        cchSiteName = strlen(pStart);

    szSiteName = (char *)BIDMalloc(cchSiteName + 1);
    if (szSiteName == NULL)
        return BID_S_NO_MEMORY;

    BID_ASSERT(pStart != NULL);

    CopyMemory(szSiteName, pStart, cchSiteName);
    szSiteName[cchSiteName] = '\0';

    *pszSiteName = szSiteName;

    return BID_S_OK;
}

static BIDError
_BIDJsonToVariant(
    BIDContext context,
    json_t *jsonObject,
    VARIANT *pVar)
{
    BIDError err;
    char *szJson = NULL;
    PWSTR wszJson = NULL;

    szJson = json_dumps(jsonObject, JSON_COMPACT);
    if (szJson == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDUtf8ToUcs2(context, szJson, &wszJson);
    BID_BAIL_ON_ERROR(err);

    VariantInit(pVar);

    pVar->vt = VT_BSTR;
    pVar->bstrVal = SysAllocString(wszJson);
    if (pVar->bstrVal == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    BIDFree(szJson);
    BIDFree(wszJson);

    return err;
}

static BIDError
_BIDPackBrowserArgs(
    BIDContext context,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    BOOLEAN bSilent,
    VARIANT *pVar)
{
    BIDError err;
    json_t *args = NULL;
    char *szSiteName = NULL;

    args = json_object();
    if (args == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(context, args, "claims", claims, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(context, args, "audience",
                            json_string(szPackedAudience),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_GSS) {
        err = _BIDJsonObjectSet(context, args, "servicePrincipalName",
                                json_string(szAudienceOrSpn),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSpnToSiteName(context, szAudienceOrSpn, &szSiteName);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, args, "siteName",
                                json_string(szSiteName),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
    }

    if (szIdentityName != NULL) {
        err = _BIDJsonObjectSet(context, args, "requiredEmail",
                                json_string(szIdentityName),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        err = _BIDJsonObjectSet(context, args, "silent",
                                bSilent ? json_true() : json_false(),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDJsonToVariant(context, args, pVar);
    BID_BAIL_ON_ERROR(err);

cleanup:
    json_decref(args);
    BIDFree(szSiteName);

    return err;
}

static WCHAR _BIDHTMLDialogOptions[] =
    L"dialogHeight:375px;dialogWidth:700px;center:yes;resizable:no;scroll:no;status:no;unadorned:no";

#define BID_BAIL_ON_HERROR(status)       do {       \
        if (FAILED((status))) {                     \
            err = BID_S_INTERACT_FAILURE;           \
            goto cleanup;                           \
        }                                           \
    } while (0)


static BIDError
_BIDHTMLWindowGetAssertion(
    BIDContext context,
    SHOWHTMLDIALOGEXFN *pfnShowHTMLDialogEx,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    BOOLEAN bSilent,
    char **pAssertion)
{
    BIDError err;
    HRESULT hr;
    VARIANT varArgIn;
    VARIANT varArgOut;
    IMoniker *pURLMoniker = NULL;
    BSTR bstrURL = NULL;
    DWORD dwFlags;

    VariantInit(&varArgIn);
    VariantInit(&varArgOut);

    err = _BIDPackBrowserArgs(context, szPackedAudience, szAudienceOrSpn,
                              claims, szIdentityName, ulReqFlags, bSilent,
                              &varArgIn);
    BID_BAIL_ON_ERROR(err);

    bstrURL = SysAllocString(L"https://login.persona.org/sign_in#NATIVE");
    CreateURLMoniker(NULL, bstrURL, &pURLMoniker);

    if (pURLMoniker == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    dwFlags = HTMLDLG_MODAL | HTMLDLG_VERIFY | HTMLDLG_ALLOW_UNKNOWN_THREAD;

    if (bSilent)
        dwFlags |= HTMLDLG_NOUI;

    hr = (*pfnShowHTMLDialogEx)((HWND)context->ParentWindow,
                                pURLMoniker,
                                dwFlags,
                                &varArgIn,
                                _BIDHTMLDialogOptions,
                                &varArgOut);
    err = SUCCEEDED(hr) ? BID_S_OK : BID_S_INTERACT_FAILURE;

cleanup:
    if (pURLMoniker != NULL)
        pURLMoniker->Release();
    SysFreeString(bstrURL);
    VariantClear(&varArgIn);
    VariantClear(&varArgOut);

    return err;
}

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    char **pAssertion)
{
    BIDError err;
    HRESULT hr;
    HINSTANCE hinstMSHTML = NULL;
    SHOWHTMLDIALOGEXFN *pfnShowHTMLDialogEx = NULL;

    hinstMSHTML = LoadLibrary("mshtml.dll");
    if (hinstMSHTML == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    pfnShowHTMLDialogEx =
        (SHOWHTMLDIALOGEXFN *)GetProcAddress(hinstMSHTML, "ShowHTMLDialogEx");
    if (pfnShowHTMLDialogEx == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BID_BAIL_ON_HERROR(hr);

    err = _BIDHTMLWindowGetAssertion(context,
                                     pfnShowHTMLDialogEx,
                                     szPackedAudience,
                                     szAudienceOrSpn,
                                     claims,
                                     szIdentityName,
                                     ulReqFlags,
                                     !!(context->ContextOptions & BID_CONTEXT_BROWSER_SILENT),
                                     pAssertion);
    if (err == BID_S_INTERACT_REQUIRED && _BIDCanInteractP(context, ulReqFlags)) {
        err = _BIDHTMLWindowGetAssertion(context,
                                         pfnShowHTMLDialogEx,
                                         szPackedAudience,
                                         szAudienceOrSpn,
                                         claims,
                                         szIdentityName,
                                         ulReqFlags,
                                         FALSE,
                                         pAssertion);
    }
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (hinstMSHTML != NULL)
        FreeLibrary(hinstMSHTML);

    return err;
}
