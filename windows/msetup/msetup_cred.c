/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * msetup credential attribute helper functions
 */

#include "msetup.h"

typedef DWORD (*MsAttrSetterFn)(
    LPWSTR TargetName,
    LPWSTR UserName,
    LPWSTR StringValue,
    PCREDENTIAL_ATTRIBUTE Attribute,
    BOOLEAN *pbFreeAttrValue);

static DWORD
MsSetCredCaCert(LPWSTR TargetName,
                LPWSTR UserName,
                LPWSTR CaCertFilename,
                PCREDENTIAL_ATTRIBUTE Attribute,
                BOOLEAN *pbFreeAttrValue)
{
    Attribute->Value = (PBYTE)CaCertFilename;
    Attribute->ValueSize = wcslen(CaCertFilename) * sizeof(WCHAR);
    *pbFreeAttrValue = FALSE;

    return ERROR_SUCCESS;
}

static DWORD
FindCertBySubject(  
    LPWSTR Store,
    LPWSTR SubjectName,
    HCERTSTORE *pCs,
    PCCERT_CONTEXT *pCc)
{
    HCERTSTORE cs = NULL;
    PCCERT_CONTEXT cc = NULL;

    cs = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                       0,
                       (HCRYPTPROV)NULL,
                       CERT_SYSTEM_STORE_CURRENT_USER |
                        CERT_STORE_OPEN_EXISTING_FLAG |
                        CERT_STORE_READONLY_FLAG,
                       Store);
    if (cs == NULL) {
        return GetLastError();
    }

    cc = CertFindCertificateInStore(cs,
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    0,
                                    CERT_FIND_SUBJECT_STR,
                                    SubjectName,
                                    NULL);
    if (cc == NULL) {
        CertCloseStore(cs, 0);
        return GetLastError();
    }

    *pCs = cs;
    *pCc = cc;

    return ERROR_SUCCESS;
}

static DWORD
MsSetCredServerCert(LPWSTR TargetName,
                    LPWSTR UserName,
                    LPWSTR CertName,
                    PCREDENTIAL_ATTRIBUTE Attribute,
                    BOOLEAN *pbFreeAttrValue)
{
    HCERTSTORE cs = NULL;
    PCCERT_CONTEXT cc = NULL;
    DWORD dwResult;

    dwResult = FindCertBySubject(L"MY", CertName, &cs, &cc);
#if 0
    if (dwResult == CRYPT_E_NOT_FOUND)
        dwResult = FindCertBySubject(L"TrustedPeople", CertName, &cs, &cc);
#endif
    if (dwResult != ERROR_SUCCESS)
        goto cleanup;

    CertGetCertificateContextProperty(cc, CERT_HASH_PROP_ID,
                                      NULL, &Attribute->ValueSize);
    if (Attribute->ValueSize == 0) {
        dwResult = GetLastError();
        goto cleanup;
    }

    Attribute->Value = LocalAlloc(LPTR, Attribute->ValueSize);
    if (Attribute->Value == NULL) {
        dwResult = GetLastError();
        goto cleanup;
    }

    *pbFreeAttrValue = TRUE;

    if (!CertGetCertificateContextProperty(cc, CERT_HASH_PROP_ID,
                                           Attribute->Value,
                                           &Attribute->ValueSize)) {
        dwResult = GetLastError();
        goto cleanup;
    }

    dwResult = ERROR_SUCCESS;

cleanup:
    if (cs != NULL)
        CertCloseStore(cs, 0);
    if (cc != NULL)
        CertFreeCertificateContext(cc);

    return dwResult;
}

static DWORD
MsSetCredSubjectName(LPWSTR TargetName,
                     LPWSTR UserName,
                     LPWSTR SubjectName,
                     PCREDENTIAL_ATTRIBUTE Attribute,
                     BOOLEAN *pbFreeAttrValue)
{
    DWORD cbSize;

    if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       SubjectName,
                       CERT_X500_NAME_STR,
                       NULL,
                       NULL,
                       &cbSize,
                       NULL))
        return GetLastError();

    Attribute->Value = LocalAlloc(LPTR, cbSize);
    if (Attribute->Value == NULL)
        return GetLastError();

    if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       SubjectName,
                       CERT_X500_NAME_STR,
                       NULL,
                       Attribute->Value,
                       &Attribute->ValueSize,
                       NULL)) {
        LocalFree(Attribute->Value);
        return GetLastError();
    }

    *pbFreeAttrValue = TRUE;
    return ERROR_SUCCESS;
}

static DWORD
MsSetCredSubjectAltName(LPWSTR TargetName,
                        LPWSTR UserName,
                        LPWSTR SubjectAltName,
                        PCREDENTIAL_ATTRIBUTE Attribute,
                        BOOLEAN *pbFreeAttrValue)
{
    Attribute->Value = (PBYTE)SubjectAltName;
    Attribute->ValueSize = wcslen(SubjectAltName) * sizeof(WCHAR);
    *pbFreeAttrValue = FALSE;

    return ERROR_SUCCESS;
}

static struct _MS_CRED_ATTR_HANDLER {
    LPWSTR Attribute;
    MsAttrSetterFn AttrSetter;
} msCredAttrSetters[] = {
    { NULL,                                 NULL                        },
    { L"Moonshot_CACertificate",            MsSetCredCaCert             },
    { L"Moonshot_ServerCertificateHash",    MsSetCredServerCert         },
    { L"Moonshot_SubjectNameConstraint",    MsSetCredSubjectName        },
    { L"Moonshot_SubjectAltNameConstraint", MsSetCredSubjectAltName     },
};

static DWORD
UpdateExistingCred(
    LPWSTR TargetName,
    LPWSTR UserName,
    DWORD dwAttrType,
    LPWSTR AttributeValue,
    PCREDENTIAL ExistingCred)
{
    DWORD dwResult;
    LONG i, iAttr = -1;
    CREDENTIAL Credential = { 0 };
    struct _MS_CRED_ATTR_HANDLER *Handler;
    BOOLEAN bFreeAttrValue = FALSE;

    Handler = &msCredAttrSetters[dwAttrType];

    assert(Handler->Attribute != NULL);
    assert(Handler->AttrSetter != NULL);

    Credential = *ExistingCred;

    Credential.AttributeCount = 0;
    Credential.Attributes = LocalAlloc(LPTR,
        (ExistingCred->AttributeCount + 1) * sizeof(CREDENTIAL_ATTRIBUTE));
    if (Credential.Attributes == NULL) {
        dwResult = GetLastError();
        goto cleanup;
    }

    for (i = 0, iAttr = -1; i < ExistingCred->AttributeCount; i++) {
        PCREDENTIAL_ATTRIBUTE Attr = &ExistingCred->Attributes[i];

        if (_wcsicmp(Attr->Keyword, Handler->Attribute) == 0)
            iAttr = i;

        if (iAttr == i && AttributeValue == NULL) {
#ifdef DEBUG
            fwprintf(stderr, L"Clearing attribute %s\n", Attr->Keyword);
#endif
            continue; /* remove this attribute */
        }

        Credential.Attributes[Credential.AttributeCount++] = *Attr;
    }

    if (AttributeValue != NULL) {
        if (iAttr == -1)
            iAttr = Credential.AttributeCount++;

        Credential.Attributes[iAttr].Keyword = Handler->Attribute;
        Credential.Attributes[iAttr].Flags = 0;

        dwResult = Handler->AttrSetter(TargetName,
                                        UserName,
                                        AttributeValue,
                                        &Credential.Attributes[iAttr],
                                        &bFreeAttrValue);
        if (dwResult != ERROR_SUCCESS)
            goto cleanup;

#ifdef DEBUG
        fwprintf(stderr, L"Set attribute %s length %u\n",
                 Credential.Attributes[iAttr].Keyword,
                 Credential.Attributes[iAttr].ValueSize);
#endif
    } else if (iAttr == -1) {
#ifdef DEBUG
        fwprintf(stderr, L"No such attribute %s; nothing to do\n",
                 Handler->Attribute);
#endif
        dwResult = ERROR_SUCCESS;
        goto cleanup;
    }

    if (!CredWrite(&Credential, CRED_PRESERVE_CREDENTIAL_BLOB)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"CredWrite failed: 0x%08x\n", dwResult);
    } else {
        dwResult = ERROR_SUCCESS;
    }

cleanup:
    if (Credential.Attributes != NULL) {
        if (iAttr != -1 &&
            bFreeAttrValue &&
            Credential.Attributes[iAttr].Value != NULL)
            LocalFree(Credential.Attributes[iAttr].Value);
        LocalFree(Credential.Attributes);
    }

    return dwResult;
}

DWORD
MsSetCredAttribute(
    LPWSTR TargetName,
    LPWSTR UserName,
    DWORD dwAttrType,
    LPWSTR AttributeValue)
{
    DWORD dwResult;
    DWORD dwCredCount = 0, i;
    BOOLEAN bFoundCred = FALSE;
    PCREDENTIAL_TARGET_INFORMATION TargetInfo = NULL;
    PCREDENTIAL *ExistingCreds = NULL;

    if (dwAttrType == 0 || dwAttrType > MS_CRED_ATTR_MAX) {
        dwResult = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if (!CredGetTargetInfo(TargetName, 0, &TargetInfo)) {
        dwResult = GetLastError();
        if (dwResult == ERROR_NOT_FOUND)
            fwprintf(stderr, L"No existing credential for %s\n", TargetName);
        else
            fwprintf(stderr, L"CredGetTargetInfo failed: 0x%08x\n", dwResult);
        goto cleanup;
    }

    if (!CredReadDomainCredentials(TargetInfo, 0,
                                   &dwCredCount, &ExistingCreds)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"CredReadDomainCredentials failed: 0x%08x\n", dwResult);
        goto cleanup;
    }

    for (i = 0, bFoundCred = FALSE; i < dwCredCount; i++) {
        if (_wcsicmp(ExistingCreds[i]->UserName, UserName) == 0) {
            dwResult = UpdateExistingCred(TargetName, UserName, dwAttrType,
                                          AttributeValue, ExistingCreds[i]);
            if (dwResult != ERROR_SUCCESS)
                goto cleanup;
            if (!bFoundCred)
                bFoundCred = TRUE;
        }
    }

    if (!bFoundCred) {
        fwprintf(stderr, L"No credentials for %s match username %s\n", TargetName, UserName);
        dwResult = ERROR_NOT_FOUND;
        goto cleanup;
    }

cleanup:
    if (ExistingCreds != NULL)
        CredFree(ExistingCreds);
    if (TargetInfo != NULL)
        CredFree(TargetInfo);
    return dwResult;
}

DWORD
MsSetDefaultCertStore(
    HKEY hSspKey,
    LPWSTR Store)
{
    DWORD dwResult;

    if (Store != NULL) {
        dwResult = RegSetValueEx(hSspKey, L"DefaultCertStore", 0,
                                 REG_SZ, (PBYTE)Store,
                                 (wcslen(Store) + 1) * sizeof(WCHAR));
    } else {
        dwResult = RegDeleteValue(hSspKey, L"DefaultCertStore");
    }

    return dwResult;
}

DWORD
MsGetDefaultCertStore(
    HKEY hSspKey,
    LPWSTR *pStore)
{
    DWORD dwResult;
    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;

    dwResult = RegQueryValueEx(hSspKey, L"DefaultCertStore", NULL, &dwType,
                               NULL, &dwSize);
    if (dwResult != ERROR_SUCCESS)
        return dwResult;
    else if (dwType != REG_SZ)
        return ERROR_INVALID_PARAMETER;

    *pStore = LocalAlloc(LPTR, dwSize + sizeof(WCHAR));

    dwResult = RegQueryValueEx(hSspKey, L"DefaultCertStore", NULL, &dwType,
                               (PBYTE)*pStore, &dwSize);
    if (dwResult == ERROR_SUCCESS)
        (*pStore)[dwSize / sizeof(WCHAR)] = 0;

    return dwResult;
}
