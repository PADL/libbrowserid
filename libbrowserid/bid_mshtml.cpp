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

#include <MsHtml.h>
#include <MsHtmlc.h>
#include <MsHtmHst.h>
#include <Shlwapi.h>
#include <DHtmldid.h>
#include <MsHtmdid.h>

#define DISPID_BIDIDENTITYCONTROLLER_CALLBACK       0x40000001

/*
 * Internet Explorer implementation of the browser shim.
 */

static WCHAR _BIDHTMLAcquireAssertionScript[] = L"                                                  \
    var args = JSON.parse(window.dialogArguments);                                                  \
    var options = { siteName: args.siteName,                                                        \
                    experimental_emailHint: args.emailHint,                                         \
                    experimental_userAssertedClaims: args.claims                                    \
    };                                                                                              \
                                                                                                    \
    BrowserID.internal.get(                                                                         \
        args.audience,                                                                              \
        function(assertion, params) {                                                               \
           window.controller.identityCallback(assertion, params);                                   \
        },                                                                                          \
        options);                                                                                   \
";

static WCHAR _BIDHTMLDialogOptions[] =
    L"dialogHeight:375px;dialogWidth:700px;center:yes;resizable:no;scroll:no;status:no;unadorned:no";

#define BID_BAIL_ON_HERROR(status)       do {       \
        if (FAILED((status))) {                     \
            goto cleanup;                           \
        }                                           \
    } while (0)

class CBIDIdentityController : public IDispatch
{
public:
    CBIDIdentityController::CBIDIdentityController();
    CBIDIdentityController::~CBIDIdentityController();

    DWORD __stdcall AddRef();
    DWORD __stdcall Release();
    HRESULT __stdcall QueryInterface(__in REFIID riid,
                                     __deref_out void **ppv);

    STDMETHOD(GetTypeInfoCount)(unsigned int FAR *pctInfo);
    STDMETHOD(GetTypeInfo)(unsigned int iTInfo,
                           LCID lcid,
                           ITypeInfo FAR *FAR *ppTInfo);
    STDMETHOD(GetIDsOfNames)(REFIID riid,
                             OLECHAR FAR *FAR *rgszNames,
                             unsigned int cNames,
                             LCID lcid,
                             DISPID FAR *rgDispId);
    STDMETHOD(Invoke)(DISPID dispIdMember,
                      REFIID riid,
                      LCID lcid,
                      WORD wFlags,
                      DISPPARAMS *pDispParams,
                      VARIANT *pVarResult,
                      EXCEPINFO *pExcepInfo,
                      UINT *puArgErr);

    BIDError Initialize(BIDContext context,
                        const char *szAudienceOrSpn,
                        json_t *claims,
                        const char *szIdentityName,
                        uint32_t ulReqFlags);

    BIDError GetAssertion(char **pAssertion);

private:
    HRESULT _LoadLibrary(void);
    HRESULT _PackDialogArgs(const char *szAudienceOrSpn,
                            json_t *claims,
                            const char *szIdentityName,
                            uint32_t ulReqFlags);
    HRESULT _SpnToSiteName(const char *spn,
                           char **pszSiteName);

    HRESULT _JsonToVariant(json_t *jsonObject,
                           VARIANT *pVar);

    HRESULT _AcquireAssertion(void);
    HRESULT _IdentityCallback(DISPPARAMS *pDispParams);
    HRESULT _GetArguments(VARIANT *vArgs);

    HRESULT _ShowDialog(void);
    HRESULT _RunModal(void);
    HRESULT _GetBrowserWindow(void);
    HRESULT _FindConnectionPoint(IConnectionPoint **ppConnectionPoint);
    HRESULT _PublishController(void);
    HRESULT _CloseIdentityDialog(void);
    HRESULT _SetAssertion(BSTR bstrAssertion);

    BIDError _MapError(HRESULT hr);

private:
    LONG _cRef;

    BIDContext _context;
    BIDError _bidError;
    uint32_t _ulReqFlags;

    HINSTANCE _hinstMSHTML;
    SHOWHTMLDIALOGEXFN *_pfnShowHTMLDialogEx;

    json_t *_args;
    char *_szAssertion;

    IMoniker *_pURLMoniker;
    IHTMLWindow2 *_pHTMLWindow2;
    IHTMLDocument2 *_pHTMLDocument2;
    HWND _hBrowserWindow;
    DWORD _dwCookie;
};

CBIDIdentityController::CBIDIdentityController()
{
    _cRef = 1;

    _context = NULL;
    _bidError = BID_S_INTERACT_REQUIRED;
    _ulReqFlags = 0;

    _hinstMSHTML = NULL;
    _pfnShowHTMLDialogEx = NULL;

    _args = NULL;
    _szAssertion = NULL;

    _pURLMoniker = NULL;
    _pHTMLWindow2 = NULL;
    _pHTMLDocument2 = NULL;
    _hBrowserWindow = 0;
    _dwCookie = 0;
}

CBIDIdentityController::~CBIDIdentityController()
{
    if (_hinstMSHTML != NULL)
        FreeLibrary(_hinstMSHTML);

    json_decref(_args);
    BIDFree(_szAssertion);

    if (_pURLMoniker != NULL)
        _pURLMoniker->Release();
    if (_pHTMLWindow2 != NULL)
        _pHTMLWindow2->Release();
    if (_pHTMLDocument2 != NULL)
        _pHTMLDocument2->Release();

    OleUninitialize();
}

DWORD __stdcall
CBIDIdentityController::AddRef(void)
{
    return InterlockedIncrement(&_cRef);
}

DWORD __stdcall
CBIDIdentityController::Release(void)
{
    if (InterlockedDecrement(&_cRef) == 0) {
        delete this;
        return 0;
    }

    return _cRef;
}

HRESULT __stdcall
CBIDIdentityController::QueryInterface(
    __in REFIID riid,
    __deref_out void **ppv)
{
    static const QITAB qit[] = {
        QITABENT(CBIDIdentityController, IUnknown),
        QITABENT(CBIDIdentityController, IDispatch),
        {0},
    };

    return QISearch(this, qit, riid, ppv);
}

HRESULT
CBIDIdentityController::GetTypeInfoCount(
    unsigned int FAR *pctInfo)
{
    OutputDebugString("CBIDIdentityController::GetTypeInfoCount\r\n");
    return E_NOTIMPL;
}

HRESULT
CBIDIdentityController::GetTypeInfo(
    unsigned int iTInfo,
    LCID lcid,
    ITypeInfo FAR *FAR *ppTInfo)
{
    OutputDebugString("CBIDIdentityController::GetTypeInfo\r\n");
    return E_NOTIMPL;
}

HRESULT
CBIDIdentityController::GetIDsOfNames(
    REFIID riid,
    OLECHAR FAR *FAR *rgszNames,
    unsigned int cNames,
    LCID lcid,
    DISPID FAR *rgDispId)
{
    unsigned int i;
    BOOLEAN bUnknown = FALSE;

    for (i = 0; i < cNames; i++) {
        if (wcscmp(rgszNames[i], L"identityCallback") == 0) {
            rgDispId[i] = DISPID_BIDIDENTITYCONTROLLER_CALLBACK;
        } else {
            rgDispId[i] = DISPID_UNKNOWN;
            bUnknown = TRUE;
        }
    }

    return bUnknown ? DISP_E_UNKNOWNNAME : S_OK;
}

BIDError
CBIDIdentityController::_MapError(
    HRESULT hr)
{
    BIDError err;

    switch (hr) {
    case S_OK:
        err = BID_S_OK;
        break;
    case E_OUTOFMEMORY:
        err = BID_S_NO_MEMORY;
        break;
    default:
        err = BID_S_INTERACT_FAILURE;
        break;
    }

    return err;
}

HRESULT
CBIDIdentityController::_FindConnectionPoint(
    IConnectionPoint **ppConnectionPoint)
{
    HRESULT hr;
    IConnectionPointContainer *pCPContainer = NULL;

    BID_ASSERT(_pHTMLWindow2 != NULL);

    *ppConnectionPoint = NULL;

    hr = _pHTMLWindow2->QueryInterface(IID_PPV_ARGS(&pCPContainer));
    BID_BAIL_ON_HERROR(hr);

    hr = pCPContainer->FindConnectionPoint(DIID_HTMLWindowEvents2,
                                           ppConnectionPoint);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    if (pCPContainer != NULL)
        pCPContainer->Release();

    return hr;
}

HRESULT
CBIDIdentityController::Invoke(
    DISPID dispIdMember,
    REFIID riid,
    LCID lcid,
    WORD wFlags,
    DISPPARAMS *pDispParams,
    VARIANT *pVarResult,
    EXCEPINFO *pExcepInfo,
    UINT *puArgErr)
{
    IConnectionPoint *pConnectionPoint = NULL;
    HRESULT hr = S_OK;

    if (pDispParams == NULL) {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    switch (dispIdMember) {
    case DISPID_BIDIDENTITYCONTROLLER_CALLBACK:
        OutputDebugString("CBIDIdentityController::Invoke CALLBACK\r\n");

        if ((wFlags & DISPATCH_METHOD) == 0) {
            hr = DISP_E_MEMBERNOTFOUND;
            goto cleanup;
        }

        hr = _IdentityCallback(pDispParams);
        BID_BAIL_ON_HERROR(hr);

        break;

    case DISPID_HTMLWINDOWEVENTS2_ONERROR:
        OutputDebugString("CBIDIdentityController::Invoke ONERROR\r\n");

        break;

    case DISPID_HTMLWINDOWEVENTS2_ONLOAD:
        OutputDebugString("CBIDIdentityController::Invoke ONLOAD\r\n");

        hr = _GetBrowserWindow();
        BID_BAIL_ON_HERROR(hr);

        hr = _PublishController();
        BID_BAIL_ON_HERROR(hr);

        hr = _AcquireAssertion();
        BID_BAIL_ON_HERROR(hr);

        break;
    case DISPID_HTMLWINDOWEVENTS2_ONUNLOAD:
        OutputDebugString("CBIDIdentityController::Invoke ONUNLOAD\r\n");

        hr = _FindConnectionPoint(&pConnectionPoint);
        BID_BAIL_ON_HERROR(hr);

        pConnectionPoint->Unadvise(_dwCookie);
        pConnectionPoint->Release();

        if (_bidError == BID_S_INTERACT_REQUIRED)
            _bidError = BID_S_INTERACT_FAILURE;

       break;
    default:
        hr = DISP_E_MEMBERNOTFOUND;
        break;
    }

cleanup:
    return hr;
}

HRESULT
CBIDIdentityController::_LoadLibrary(void)
{
    HRESULT hr;

    hr = OleInitialize(NULL);
    BID_BAIL_ON_HERROR(hr);

    _hinstMSHTML = LoadLibrary("mshtml.dll");
    if (_hinstMSHTML == NULL) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    _pfnShowHTMLDialogEx =
        (SHOWHTMLDIALOGEXFN *)GetProcAddress(_hinstMSHTML, "ShowHTMLDialogEx");
    if (_pfnShowHTMLDialogEx == NULL) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    hr = S_OK;

cleanup:
    return hr;
}

HRESULT
CBIDIdentityController::_JsonToVariant(
    json_t *jsonObject,
    VARIANT *pVar)
{
    HRESULT hr;
    char *szJson = NULL;
    PWSTR wszJson = NULL;

    szJson = json_dumps(jsonObject, JSON_COMPACT);
    if (szJson == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    if (_BIDUtf8ToUcs2(_context, szJson, &wszJson) != BID_S_OK) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    VariantInit(pVar);

    V_VT(pVar)   = VT_BSTR;
    V_BSTR(pVar) = SysAllocString(wszJson);

    if (V_BSTR(pVar) == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = S_OK;

cleanup:
    BIDFree(szJson);
    BIDFree(wszJson);

    return hr;
}

HRESULT
CBIDIdentityController::_GetArguments(VARIANT *varArgs)
{
    return _JsonToVariant(_args, varArgs);
}

HRESULT
CBIDIdentityController::_PackDialogArgs(
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags)
{
    HRESULT hr;
    BIDError err;
    char *szSiteName = NULL;

    _ulReqFlags = ulReqFlags;

    _args = json_object();
    if (_args == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    if (claims != NULL && json_object_size(claims)) {
        err = _BIDJsonObjectSet(_context, _args, "claims", claims, 0);
        BID_BAIL_ON_ERROR(err);
    }

    err = _BIDJsonObjectSet(_context, _args, "audience",
                            json_string(szAudienceOrSpn),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (_context->ContextOptions & BID_CONTEXT_GSS) {
        hr = _SpnToSiteName(szAudienceOrSpn, &szSiteName);
        if (FAILED(hr)) {
            err = _MapError(hr);
            goto cleanup;
        }

        err = _BIDJsonObjectSet(_context, _args, "siteName",
                                json_string(szSiteName),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
    }

    if (szIdentityName != NULL) {
        err = _BIDJsonObjectSet(_context, _args, "emailHint",
                                json_string(szIdentityName),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    BIDFree(szSiteName);

    return (err == BID_S_OK) ? S_OK : E_OUTOFMEMORY;
}

BIDError
CBIDIdentityController::Initialize(
    BIDContext context,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags)
{
    HRESULT hr;
    BSTR bstrURL = NULL;

    _context = context;

    hr = _LoadLibrary();
    BID_BAIL_ON_HERROR(hr);

    hr = _PackDialogArgs(szAudienceOrSpn, claims, szIdentityName, ulReqFlags);
    BID_BAIL_ON_HERROR(hr);

    bstrURL = SysAllocString(L"https://login.persona.org/sign_in#NATIVE");
    if (bstrURL == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = CreateURLMoniker(NULL, bstrURL, &_pURLMoniker);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    SysFreeString(bstrURL);

    return _MapError(hr);
}

HRESULT
CBIDIdentityController::_ShowDialog(void)
{
    HRESULT hr;
    VARIANT varArgIn;
    VARIANT varArgOut;
    IUnknown *pUnknown = NULL;
    IConnectionPoint *pConnectionPoint = NULL;
    DWORD dwFlags;

    VariantInit(&varArgIn);
    VariantInit(&varArgOut);

    hr = _GetArguments(&varArgIn);
    BID_BAIL_ON_HERROR(hr);

    dwFlags = HTMLDLG_MODELESS | HTMLDLG_VERIFY |
              HTMLDLG_ALLOW_UNKNOWN_THREAD;

    hr = (*_pfnShowHTMLDialogEx)((HWND)_context->ParentWindow,
                                 _pURLMoniker,
                                 dwFlags,
                                 &varArgIn,
                                 _BIDHTMLDialogOptions,
                                 &varArgOut);
    BID_BAIL_ON_HERROR(hr);

    if (V_VT(&varArgOut) != VT_UNKNOWN || V_UNKNOWN(&varArgOut) == NULL) {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    pUnknown = V_UNKNOWN(&varArgOut);
    V_UNKNOWN(&varArgOut) = NULL;

    hr = pUnknown->QueryInterface(IID_PPV_ARGS(&_pHTMLWindow2));
    BID_BAIL_ON_HERROR(hr);

    hr = _FindConnectionPoint(&pConnectionPoint);
    BID_BAIL_ON_HERROR(hr);

    hr = pConnectionPoint->Advise(this, &_dwCookie);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    if (pUnknown != NULL)
        pUnknown->Release();
    if (pConnectionPoint != NULL)
        pConnectionPoint->Release();
    VariantClear(&varArgIn);
    VariantClear(&varArgOut);

    return hr;
}

HRESULT
CBIDIdentityController::_GetBrowserWindow(void)
{
    HRESULT hr;
    IOleWindow *pOleWindow = NULL;
    HWND hwnd;

    BID_ASSERT(_pHTMLWindow2 != NULL);

    hr = _pHTMLWindow2->get_document(&_pHTMLDocument2);
    BID_BAIL_ON_HERROR(hr);

    hr = _pHTMLDocument2->QueryInterface(IID_PPV_ARGS(&pOleWindow));
    BID_BAIL_ON_HERROR(hr);

    hr = pOleWindow->GetWindow(&hwnd);
    BID_BAIL_ON_HERROR(hr);

    do {
        _hBrowserWindow = hwnd;
        hwnd = GetParent(hwnd);
    } while (hwnd != (HWND)_context->ParentWindow);

cleanup:
    if (pOleWindow != NULL)
        pOleWindow->Release();

    return hr;
}

HRESULT
CBIDIdentityController::_AcquireAssertion(void)
{
    HRESULT hr;
    VARIANT varArgOut;
    BSTR bstrScript = NULL;

    VariantInit(&varArgOut);

    BID_ASSERT(_pHTMLWindow2 != NULL);

    bstrScript = SysAllocString(_BIDHTMLAcquireAssertionScript);
    if (bstrScript == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = _pHTMLWindow2->execScript(bstrScript, L"JavaScript", &varArgOut);
    BID_BAIL_ON_HERROR(hr);

    EnableWindow(_hBrowserWindow, TRUE);
    ShowWindow(_hBrowserWindow, SW_SHOW);

cleanup:
    VariantClear(&varArgOut);
    SysFreeString(bstrScript);

    return hr;
}

HRESULT
CBIDIdentityController::_CloseIdentityDialog(void)
{
    HRESULT hr = E_INVALIDARG;

    if (_pHTMLWindow2 != NULL)
        hr = _pHTMLWindow2->close();

    return hr;
}

HRESULT
CBIDIdentityController::_SetAssertion(BSTR bstrAssertion)
{
    char *szAssertion = NULL;

    if (bstrAssertion != NULL &&
       _BIDUcs2ToUtf8(_context, bstrAssertion, &szAssertion) != BID_S_OK) {
        return E_OUTOFMEMORY;
    }

    if (_szAssertion != NULL)
        BIDFree(_szAssertion);
    _szAssertion = szAssertion;

    return S_OK;
}

HRESULT
CBIDIdentityController::_IdentityCallback(DISPPARAMS *pDispParams)
{
    HRESULT hr;
    VARIANT *vAssertion;
    BSTR bstrAssertion = NULL;

    if (pDispParams->cArgs < 2 || pDispParams->cNamedArgs != 0) {
        hr = DISP_E_BADPARAMCOUNT;
        goto cleanup;
    }

    vAssertion = &pDispParams->rgvarg[1];
    switch (V_VT(vAssertion)) {
    case VT_BSTR:
        bstrAssertion = V_BSTR(vAssertion);
        break;
    case VT_NULL:
        bstrAssertion = NULL;
        break;
    default:
        hr = DISP_E_BADVARTYPE;
        goto cleanup;
        break;
    }

    if (SysStringLen(bstrAssertion) != 0)
        _bidError = BID_S_OK;
    else
        _bidError = BID_S_INTERACT_FAILURE;

    hr = _SetAssertion(bstrAssertion);
    BID_BAIL_ON_ERROR(hr);

    hr = _CloseIdentityDialog();
    BID_BAIL_ON_ERROR(hr);

    hr = S_OK;

cleanup:
    return hr;
}

HRESULT
CBIDIdentityController::_RunModal(void)
{
    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if (_bidError != BID_S_INTERACT_REQUIRED)
            break;
    }

    return S_OK;
}

HRESULT
CBIDIdentityController::_PublishController(void)
{
    HRESULT hr;
    IDispatchEx *pDispatchEx = NULL;
    DISPID dispId;
    DISPPARAMS params;
    VARIANT varThis;
    BSTR bstrController = NULL;

    hr = _pHTMLWindow2->QueryInterface(IID_PPV_ARGS(&pDispatchEx));
    BID_BAIL_ON_HERROR(hr);

    bstrController = SysAllocString(L"controller");

    hr = pDispatchEx->GetDispID(bstrController, fdexNameEnsure, &dispId);
    BID_BAIL_ON_HERROR(hr);

    VariantInit(&varThis);
    V_VT(&varThis)       = VT_DISPATCH;
    V_DISPATCH(&varThis) = (IDispatch *)this;

    ZeroMemory(&params, sizeof(params));
    params.cArgs = 1;
    params.cNamedArgs = 0;
    params.rgvarg = &varThis;
    params.rgdispidNamedArgs = NULL;

    hr = pDispatchEx->Invoke(dispId, IID_NULL, LOCALE_SYSTEM_DEFAULT,
                             DISPATCH_PROPERTYPUT, &params,
                             NULL, NULL, NULL);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    if (pDispatchEx != NULL)
        pDispatchEx->Release();
    SysFreeString(bstrController);

    return hr;
}

BIDError
CBIDIdentityController::GetAssertion(char **pAssertion)
{
    HRESULT hr = S_OK;

    *pAssertion = NULL;

    if (_context->ParentWindow)
        EnableWindow((HWND)_context->ParentWindow, FALSE);

    hr = _ShowDialog();
    BID_BAIL_ON_HERROR(hr);

    hr = _RunModal();
    BID_BAIL_ON_HERROR(hr);

    if (_bidError == BID_S_OK) {
        *pAssertion = _szAssertion;
        _szAssertion = NULL;
    }

cleanup:
    if (_context->ParentWindow)
        EnableWindow((HWND)_context->ParentWindow, TRUE);

    return FAILED(hr) ? _MapError(hr) : _bidError;
}

HRESULT
CBIDIdentityController::_SpnToSiteName(
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
        return E_OUTOFMEMORY;

    BID_ASSERT(pStart != NULL);

    CopyMemory(szSiteName, pStart, cchSiteName);
    szSiteName[cchSiteName] = '\0';

    *pszSiteName = szSiteName;

    return S_OK;
}

BIDError
_BIDBrowserGetAssertion(
    BIDContext context,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    char **pAssertion)
{
    BIDError err;
    CBIDIdentityController *pController = NULL;

    *pAssertion = NULL;

    pController = new CBIDIdentityController();
    if (pController == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = pController->Initialize(context, szAudienceOrSpn,
                                  claims, szIdentityName, ulReqFlags);
    BID_BAIL_ON_ERROR(err);

    err = pController->GetAssertion(pAssertion);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (pController != NULL)
        pController->Release();

    return err;
}

