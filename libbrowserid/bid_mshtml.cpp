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

/*
 * Internet Explorer implementation of the browser shim.
 */

static WCHAR _BIDHTMLSetupScript[] = L"                                                         \
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
    }";

static WCHAR _BIDHTMLAssertionScript[] = L"                                                         \
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

static WCHAR _BIDHTMLDialogOptions[] =
    L"dialogHeight:375px;dialogWidth:700px;center:yes;resizable:no;scroll:no;status:no;unadorned:no";

#define BID_BAIL_ON_HERROR(status)       do {       \
        if (FAILED((status))) {                     \
            err = BID_S_INTERACT_FAILURE;           \
            goto cleanup;                           \
        }                                           \
    } while (0)

class CBIDIdentityController : public IUnknown
{
public:
    IFACEMETHODIMP_(ULONG) AddRef() {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release() {
        LONG cRef = --_cRef;
        if (!cRef) {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv) {
        static const QITAB qit[] = {
            QITABENT(CBIDIdentityController, IUnknown),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

public:
    CBIDIdentityController::CBIDIdentityController();
    CBIDIdentityController::~CBIDIdentityController();

    BIDError Initialize(BIDContext context,
                        const char *szPackedAudience,
                        const char *szAudienceOrSpn,
                        json_t *claims,
                        const char *szIdentityName,
                        uint32_t ulReqFlags);

    BIDError GetAssertion(char **pAssertion);

private:
    BIDError _LoadLibrary(void);
    BIDError _PackDialogArgs(const char *szPackedAudience,
                             const char *szAudienceOrSpn,
                             json_t *claims,
                             const char *szIdentityName,
                             uint32_t ulReqFlags);
    BIDError _ShowDialog(void);
    BIDError _RunModal(void);

    BIDError _SpnToSiteName(const char *spn,
                            char **pszSiteName);

    BIDError _JsonToVariant(json_t *jsonObject,
                            VARIANT *pVar);

    BIDError _GetBrowserWindow(void);

private:
    LONG _cRef;

    BIDContext _context;
    uint32_t _ulReqFlags;

    HINSTANCE _hinstMSHTML;
    SHOWHTMLDIALOGEXFN *_pfnShowHTMLDialogEx;

    json_t *_args;

    IMoniker *_pURLMoniker;
    IHTMLWindow2 *_pHTMLWindow2;
    HWND _hBrowserWindow;
};

CBIDIdentityController::CBIDIdentityController()
{
    _cRef = 1;

    _context = NULL;
    _ulReqFlags = 0;

    _hinstMSHTML = NULL;
    _pfnShowHTMLDialogEx = NULL;

    _args = NULL;

    _pURLMoniker = NULL;
    _pHTMLWindow2 = NULL;
    _hBrowserWindow = 0;
}

CBIDIdentityController::~CBIDIdentityController()
{
    if (_hinstMSHTML != NULL)
        FreeLibrary(_hinstMSHTML);

    json_decref(_args);

    if (_pURLMoniker != NULL)
        _pURLMoniker->Release();
    if (_pHTMLWindow2 != NULL)
        _pHTMLWindow2->Release();

    CoUninitialize();
}

BIDError
CBIDIdentityController::_LoadLibrary(void)
{
    BIDError err;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BID_BAIL_ON_HERROR(hr);

    _hinstMSHTML = LoadLibrary("mshtml.dll");
    if (_hinstMSHTML == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    _pfnShowHTMLDialogEx =
        (SHOWHTMLDIALOGEXFN *)GetProcAddress(_hinstMSHTML, "ShowHTMLDialogEx");
    if (_pfnShowHTMLDialogEx == NULL) {
        err = BID_S_INTERACT_UNAVAILABLE;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    return err;
}

BIDError
CBIDIdentityController::_JsonToVariant(
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

    err = _BIDUtf8ToUcs2(_context, szJson, &wszJson);
    BID_BAIL_ON_ERROR(err);

    VariantInit(pVar);

    V_VT(pVar)   = VT_BSTR;
    V_BSTR(pVar) = SysAllocString(wszJson);

    if (V_BSTR(pVar) == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    err = BID_S_OK;

cleanup:
    BIDFree(szJson);
    BIDFree(wszJson);

    return err;
}

BIDError
CBIDIdentityController::_PackDialogArgs(
    const char *szPackedAudience,
    const char *szAudienceOrSpn,
    json_t *claims,
    const char *szIdentityName,
    uint32_t ulReqFlags)
{
    BIDError err;
    char *szSiteName = NULL;
    BOOLEAN bSilent = !!(_context->ContextOptions & BID_CONTEXT_BROWSER_SILENT);

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

        err = _SpnToSiteName(szAudienceOrSpn, &szSiteName);
        BID_BAIL_ON_ERROR(err);

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

        err = _BIDJsonObjectSet(_context, _args, "silent",
                                bSilent ? json_true() : json_false(),
                                BID_JSON_FLAG_REQUIRED | BID_JSON_FLAG_CONSUME_REF);
        BID_BAIL_ON_ERROR(err);
    }

cleanup:
    BIDFree(szSiteName);

    return err;
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
    BIDError err;
    HRESULT hr;
    BSTR bstrURL = NULL;

    _context = context;

    err = _LoadLibrary();
    BID_BAIL_ON_ERROR(err);

    err = _PackDialogArgs(szPackedAudience, szAudienceOrSpn,
                          claims, szIdentityName, ulReqFlags);
    BID_BAIL_ON_ERROR(err);

    bstrURL = SysAllocString(L"https://login.persona.org/sign_in#NATIVE");
    if (bstrURL == NULL) {
        err = BID_S_NO_MEMORY;
        goto cleanup;
    }

    hr = CreateURLMoniker(NULL, bstrURL, &_pURLMoniker);
    BID_BAIL_ON_HERROR(hr);

cleanup:
    SysFreeString(bstrURL);

    return err;
}

BIDError
CBIDIdentityController::_ShowDialog(void)
{
    BIDError err;
    HRESULT hr;
    VARIANT varArgIn;
    VARIANT varArgOut;
    IUnknown *pUnknown = NULL;
    DWORD dwFlags;

    VariantInit(&varArgIn);
    VariantInit(&varArgOut);

    err = _JsonToVariant(_args, &varArgIn);
    BID_BAIL_ON_ERROR(err);

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
        err = BID_S_INTERACT_FAILURE;
        goto cleanup;
    }

    pUnknown = V_UNKNOWN(&varArgOut);
    V_UNKNOWN(&varArgOut) = NULL;

    hr = pUnknown->QueryInterface(IID_PPV_ARGS(&_pHTMLWindow2));
    BID_BAIL_ON_HERROR(hr);

cleanup:
    if (pUnknown != NULL)
        pUnknown->Release();
    VariantClear(&varArgIn);
    VariantClear(&varArgOut);

    return err;
}

BIDError
CBIDIdentityController::_GetBrowserWindow(void)
{
    BIDError err;
    HRESULT hr;
    IHTMLDocument2 *pHTMLDocument2 = NULL;
    IOleWindow *pOleWindow = NULL;

    hr = _pHTMLWindow2->get_document(&pHTMLDocument2);
    BID_BAIL_ON_HERROR(hr);

    hr = pHTMLDocument2->QueryInterface(IID_PPV_ARGS(&pOleWindow));
    BID_BAIL_ON_HERROR(hr);

    hr = pOleWindow->GetWindow(&_hBrowserWindow);
    BID_BAIL_ON_HERROR(hr);

    err = BID_S_OK;

cleanup:
    if (pHTMLDocument2 != NULL)
        pHTMLDocument2->Release();
    if (pOleWindow != NULL)
        pOleWindow->Release();

    return err;
}

BIDError
CBIDIdentityController::_RunModal(void)
{
    BIDError err;

    err = _GetBrowserWindow();
    BID_BAIL_ON_ERROR(err);

#if 0
    hr = pHTMLWindow2->execScript(_BIDHTMLSetupScript, L"JavaScript", NULL);
    BID_BAIL_ON_HERROR(hr);

    VariantClear(&varArgOut);
    V_UNKNOWN(&varArgOut) = NULL;

    hr = pHTMLWindow2->execScript(_BIDHTMLAssertionScript, L"JavaScript", &varArgOut);
    BID_BAIL_ON_HERROR(hr);
#endif

cleanup:
    return err;
}

BIDError
CBIDIdentityController::GetAssertion(char **pAssertion)
{
    BIDError err;

    *pAssertion = NULL;

    err = _ShowDialog();
    BID_BAIL_ON_ERROR(err);

    err = _RunModal();
    BID_BAIL_ON_ERROR(err);

#if 0
    if (_BIDCanInteractP(_context, _ulReqFlags))
        ;
#endif

cleanup:
    return err;
}

BIDError
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
        return BID_S_NO_MEMORY;

    BID_ASSERT(pStart != NULL);

    CopyMemory(szSiteName, pStart, cchSiteName);
    szSiteName[cchSiteName] = '\0';

    *pszSiteName = szSiteName;

    return BID_S_OK;
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
