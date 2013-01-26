/*
 * Copyright (C) 2013 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 */

#include "bid_private.h"

#include <MsHtml.h>
#include <MsHtmlc.h>
#include <MsHtmHst.h>
#include <ExDisp.h>
#include <Shlwapi.h>
#include <DHtmldid.h>
#include <ExDispid.h>
#include <MsHtmdid.h>

/*
 * Internet Explorer implementation of the browser shim.
 */

#if 0
static WCHAR _BIDHTMLInterposeAssertionSignScript[] = L"                                            \
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
";
#else
static WCHAR _BIDHTMLInterposeAssertionSignScript[] = L"                                            \
    var controller = JSON.parse(window.dialogArguments);                                            \
";
#endif

#if 0
static WCHAR _BIDHTMLAcquireAssertionScript[] = L"                                                  \
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
                    alert(assertion);                                                 \
                    window.returnValue = assertion;                                                 \
                    window.close();                                                                 \
                },                                                                                  \
                options);                                                                           \
    });                                                                                             \
";
#else
static WCHAR _BIDHTMLAcquireAssertionScript[] = L"                                                  \
    var options = { siteName: controller.siteName, silent: controller.silent,                       \
                    requiredEmail: controller.requiredEmail };                                      \
                                                                                                    \
    BrowserID.internal.get(                                                                         \
        controller.audience,                                                                        \
        function(assertion, params) {                                                               \
            alert(assertion);                                                 \
        },                                                                                          \
            options);                                                                               \
";

#endif

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
                      EXCEPINFO *pExecepInfo,
                      UINT *puArgErr);

    BIDError Initialize(BIDContext context,
                        const char *szPackedAudience,
                        const char *szAudienceOrSpn,
                        json_t *claims,
                        const char *szIdentityName,
                        uint32_t ulReqFlags);

    BIDError GetAssertion(char **pAssertion);

private:
    HRESULT _LoadLibrary(void);
    HRESULT _PackDialogArgs(const char *szPackedAudience,
                            const char *szAudienceOrSpn,
                            json_t *claims,
                            const char *szIdentityName,
                            uint32_t ulReqFlags);
    HRESULT _SpnToSiteName(const char *spn,
                           char **pszSiteName);

    HRESULT _JsonToVariant(json_t *jsonObject,
                           VARIANT *pVar);

    HRESULT _InterposeAssertionSign(void);
    HRESULT _AcquireAssertion(void);
    HRESULT _IdentityCallback(VARIANT *vt);

    HRESULT _ShowDialog(void);
    HRESULT _RunModal(void);
    HRESULT _GetBrowserWindow(void);
    HRESULT _FindConnectionPoint(IConnectionPoint **ppConnectionPoint);

    BIDError _MapError(HRESULT hr);

private:
    LONG _cRef;

    BIDContext _context;
    BIDError _beAcquire;
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
    _beAcquire = BID_S_INTERACT_REQUIRED;
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
    OutputDebugString("CBIDIdentityController::GetIDsOfNames\r\n");
    return S_OK;
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
    EXCEPINFO *pExecepInfo,
    UINT *puArgErr)
{
    IConnectionPoint *pConnectionPoint = NULL;
    HRESULT hr = S_OK;

    switch (dispIdMember) {
    case DISPID_HTMLWINDOWEVENTS2_ONLOAD:
        OutputDebugString("CBIDIdentityController::Invoke ONLOAD\r\n");

        hr = _InterposeAssertionSign();
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

        if (_beAcquire == BID_S_INTERACT_REQUIRED)
            _beAcquire = BID_S_INTERACT_FAILURE;

       break;
    default: {
        char szMsg[256];

        snprintf(szMsg, sizeof(szMsg), "CBIDIdentityController::Invoke unknown DISPID %08x(%u)\r\n", dispIdMember, dispIdMember);
        OutputDebugString(szMsg);
        }
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
CBIDIdentityController::_PackDialogArgs(
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags)
{
    HRESULT hr;
    BIDError err;
    char *szSiteName = NULL;
    BOOLEAN bSilent = FALSE;

    _ulReqFlags = ulReqFlags;

    _args = json_object();
    if (_args == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = _BIDJsonObjectSet(_context, _args, "claims", claims, 0);
    BID_BAIL_ON_ERROR(err);

    err = _BIDJsonObjectSet(_context, _args, "audience",
                            json_string(szPackedAudience),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

    if (_context->ContextOptions & BID_CONTEXT_GSS) {
        err = _BIDJsonObjectSet(_context, _args, "servicePrincipalName",
                                json_string(szAudienceOrSpn),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

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
        err = _BIDJsonObjectSet(_context, _args, "requiredEmail",
                                json_string(szIdentityName),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);

        bSilent = !!(_context->ContextOptions & BID_CONTEXT_BROWSER_SILENT);
    }

    err = _BIDJsonObjectSet(_context, _args, "silent",
                            bSilent ? json_true() : json_false(),
                            BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
    BID_BAIL_ON_ERROR(err);

cleanup:
    BIDFree(szSiteName);

    return (err == BID_S_OK) ? S_OK : E_OUTOFMEMORY;
}

BIDError
CBIDIdentityController::Initialize(
    BIDContext context,
    const char *szPackedAudience,
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

    hr = _PackDialogArgs(szPackedAudience, szAudienceOrSpn,
                          claims, szIdentityName, ulReqFlags);
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

    hr = _JsonToVariant(_args, &varArgIn);
    BID_BAIL_ON_HERROR(hr);

    dwFlags = HTMLDLG_MODELESS | HTMLDLG_VERIFY |
              HTMLDLG_ALLOW_UNKNOWN_THREAD;

    if (json_is_true(json_object_get(_args, "silent")))
        dwFlags |= HTMLDLG_NOUI;

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

    BID_ASSERT(_pHTMLWindow2 != NULL);

    hr = _pHTMLWindow2->get_document(&_pHTMLDocument2);
    BID_BAIL_ON_HERROR(hr);

    hr = _pHTMLDocument2->QueryInterface(IID_PPV_ARGS(&pOleWindow));
    BID_BAIL_ON_HERROR(hr);

    hr = pOleWindow->GetWindow(&_hBrowserWindow);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    if (pOleWindow != NULL)
        pOleWindow->Release();

    return hr;
}

HRESULT
CBIDIdentityController::_InterposeAssertionSign(void)
{
    HRESULT hr;
    VARIANT varArgOut;
    BSTR bstrScript = NULL;

    VariantInit(&varArgOut);

    BID_ASSERT(_pHTMLWindow2 != NULL);

    bstrScript = SysAllocString(_BIDHTMLInterposeAssertionSignScript);
    if (bstrScript == NULL) {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = _pHTMLWindow2->execScript(bstrScript, L"JavaScript", &varArgOut);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    VariantClear(&varArgOut);
    SysFreeString(bstrScript);

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

cleanup:
    VariantClear(&varArgOut);
    SysFreeString(bstrScript);

    return hr;
}

HRESULT
CBIDIdentityController::_IdentityCallback(VARIANT *vt)
{
    return E_NOTIMPL;
}

HRESULT
CBIDIdentityController::_RunModal(void)
{
    MSG msg;

    while (GetMessage(&msg, _hBrowserWindow, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if (_beAcquire != BID_S_INTERACT_REQUIRED)
            break;
    }

    return S_OK;
}

BIDError
CBIDIdentityController::GetAssertion(char **pAssertion)
{
    HRESULT hr;

    *pAssertion = NULL;

    hr = _ShowDialog();
    BID_BAIL_ON_HERROR(hr);

    hr = _RunModal();
    BID_BAIL_ON_HERROR(hr);

cleanup:
    return SUCCEEDED(hr) ? _MapError(hr) : _beAcquire;
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
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags,
    char **pAssertion)
{
    BIDError err;
    CBIDIdentityController *pController = NULL;

    *pAssertion = NULL;

    /*
     * Unlike on OS X, we're going to make setting the context option
     * for no interaction a hard error, in order to support the case
     * where a non-UI process acting on behalf of the user wishes to
     * acquire a re-auth assertion without calling into any UI code.
     *
     * If you wish to acquire an assertion silently on Windows, then
     * just set BID_ACQUIRE_FLAG_NO_INTERACT on ulReqFlags.
     */
    if (context->ContextOptions & BID_CONTEXT_INTERACTION_DISABLED) {
        err = BID_S_INTERACT_REQUIRED;
        goto cleanup;
    }

    pController = new CBIDIdentityController();
    if (pController == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = pController->Initialize(context, szPackedAudience,
                                  szAudienceOrSpn, claims,
                                  szIdentityName, ulReqFlags);
    BID_BAIL_ON_ERROR(err);

    err = pController->GetAssertion(pAssertion);
    BID_BAIL_ON_ERROR(err);

cleanup:
    if (pController != NULL)
        pController->Release();

    return err;
}

