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
_BIDHTMLEventSetAttributeBStr(
    BIDContext context,
    IHTMLEventObj2 *pEvObj2,
    LPCWSTR wszAttribute,
    const char *szValue)
{
    BIDError err;
    LPWSTR wszValue = NULL;
    BSTR bstrAttribute = NULL;
    VARIANT cv;
    HRESULT hr;

    VariantInit(&cv);

    err = _BIDUtf8ToUcs2(context, szValue, &wszValue);
    BID_BAIL_ON_ERROR(err);

    V_VT(&cv)   = VT_BSTR;
    V_BSTR(&cv) = SysAllocString(wszValue);

    if (V_BSTR(&cv) == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    bstrAttribute = SysAllocString(wszAttribute);
    if (bstrAttribute == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    hr = pEvObj2->setAttribute(bstrAttribute, cv, 0);
    err = SUCCEEDED(hr) ? BID_S_OK : BID_S_NO_MEMORY;

cleanup:
    BIDFree(wszValue);
    SysFreeString(bstrAttribute);
    SysFreeString(V_BSTR(&cv));

    return err;
}

static BIDError
_BIDHTMLEventSetAttributeBool(
    BIDContext context,
    IHTMLEventObj2 *pEvObj2,
    LPCWSTR wszAttribute,
    BOOLEAN bValue)
{
    BIDError err;
    BSTR bstrAttribute = NULL;
    VARIANT cv;
    HRESULT hr;

    VariantInit(&cv);

    V_VT(&cv)   = VT_BOOL;
    V_BOOL(&cv) = bValue;

    bstrAttribute = SysAllocString(wszAttribute);
    if (bstrAttribute == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    hr = pEvObj2->setAttribute(bstrAttribute, cv, 0);
    err = SUCCEEDED(hr) ? BID_S_OK : BID_S_NO_MEMORY;

cleanup:
    SysFreeString(bstrAttribute);

    return err;
}

static BIDError
_BIDPackBrowserArgs(
    BIDContext context,
    IHTMLEventObj2 *pEvObj2,
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    BOOLEAN bSilent)
{
    BIDError err;
    char *szSiteName = NULL;
    char *szJsonClaims = NULL;

    if (claims != NULL) {
        szJsonClaims = json_dumps(claims, JSON_COMPACT);
        if (szJsonClaims == NULL) {
            err = BID_S_NO_MEMORY;
            goto cleanup;
        }

        err = _BIDHTMLEventSetAttributeBStr(context, pEvObj2, L"claims", szJsonClaims);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDHTMLEventSetAttributeBStr(context, pEvObj2, L"audience", szPackedAudience);
    BID_BAIL_ON_ERROR(err);

    if (context->ContextOptions & BID_CONTEXT_GSS) {
        err = _BIDHTMLEventSetAttributeBStr(context, pEvObj2, L"servicePrincipalName", szAudienceOrSpn);
        BID_BAIL_ON_ERROR(err);

        err = _BIDSpnToSiteName(context, szAudienceOrSpn, &szSiteName);
        BID_BAIL_ON_ERROR(err);

        err = _BIDHTMLEventSetAttributeBStr(context, pEvObj2, L"siteName", szSiteName);
        BID_BAIL_ON_ERROR(err);
    }

    if (szIdentityName != NULL) {
        err = _BIDHTMLEventSetAttributeBStr(context, pEvObj2, L"requiredEmail", szIdentityName);
        BID_BAIL_ON_ERROR(err);

        err = _BIDHTMLEventSetAttributeBool(context, pEvObj2, L"silent", bSilent);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    BIDFree(szSiteName);
    BIDFree(szJsonClaims);

    return err;
}

static WCHAR _BIDHTMLDialogOptions[] =
    L"dialogHeight:700;dialogWidth:375;center:yes;resizable:no;scroll:no;status:no;unadorned:yes";

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
    IHTMLEventObj *pEventObj = NULL;
    IHTMLEventObj2 *pEvObj2 = NULL;
    VARIANT varArgIn = { 0 };
    VARIANT varArgOut = { 0 };
    IMoniker *pURLMoniker = NULL;
    BSTR bstrURL = NULL;
    HWND hwndParent = NULL;
    DWORD dwFlags;

    VariantInit(&varArgIn);
    VariantInit(&varArgOut);

    err = BIDGetContextParam(context, BID_PARAM_PARENT_WINDOW,
                             (PVOID *)&hwndParent);
    BID_BAIL_ON_ERROR(err);

    hr = CoCreateInstance(CLSID_CEventObj,
                          NULL,
                          CLSCTX_ALL,
                          IID_PPV_ARGS(&pEventObj));
    if (FAILED(hr)) {
        err = BID_S_INTERACT_FAILURE;
        goto cleanup;
    }

    hr = pEventObj->QueryInterface(IID_IHTMLEventObj2, (void **)&pEvObj2);
    if (FAILED(hr)) {
        err = BID_S_INTERACT_FAILURE;
        goto cleanup;
    }

    err = _BIDPackBrowserArgs(context, pEvObj2,
                              szPackedAudience, szAudienceOrSpn,
                              claims, szIdentityName, ulReqFlags, bSilent);
    BID_BAIL_ON_ERROR(err);

    bstrURL = SysAllocString(L"https://login.persona.org/sign_in#NATIVE");
    CreateURLMoniker(NULL, bstrURL, &pURLMoniker);

    if (pURLMoniker == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    dwFlags = HTMLDLG_MODAL | HTMLDLG_VERIFY;

    if (bSilent)
        dwFlags |= HTMLDLG_NOUI;

    V_UNKNOWN(&varArgIn) = pEvObj2;

    hr = (*pfnShowHTMLDialogEx)(hwndParent,
                                pURLMoniker,
                                dwFlags,
                                &varArgIn,
                                _BIDHTMLDialogOptions,
                                &varArgOut);
    err = SUCCEEDED(hr) ? BID_S_OK : BID_S_INTERACT_FAILURE;

cleanup:
    if (pURLMoniker != NULL)
        pURLMoniker->Release();
    if (pEventObj != NULL)
        pEventObj->Release();
    if (pEvObj2 != NULL)
        pEvObj2->Release();
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
