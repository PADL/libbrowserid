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

typedef DWORD (*MsAttrGetterFn)(
    LPWSTR TargetName,
    LPWSTR UserName,
    PCREDENTIAL_ATTRIBUTE Attribute,
    LPWSTR *pStringValue);

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
MsGetCredCaCert(LPWSTR TargetName,
                LPWSTR UserName,
                PCREDENTIAL_ATTRIBUTE Attribute,
                LPWSTR *pCredCaCert)
{
    LPWSTR CredCaCert;

    CredCaCert = LocalAlloc(LPTR, Attribute->ValueSize + sizeof(WCHAR));
    if (CredCaCert == NULL)
        return GetLastError();

    memcpy(CredCaCert, Attribute->Value, Attribute->ValueSize);
    CredCaCert[Attribute->ValueSize / sizeof(WCHAR)] = 0;

    *pCredCaCert = CredCaCert;

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
MsSetCredServerHash(LPWSTR TargetName,
                    LPWSTR UserName,
                    LPWSTR CertHash,
                    PCREDENTIAL_ATTRIBUTE Attribute,
                    BOOLEAN *pbFreeAttrValue)
{
    DWORD dwLength;
    DWORD i;
    BOOLEAN bColonSeparated;

    bColonSeparated = (wcschr(CertHash, ':') != NULL);

    if (bColonSeparated) {
        dwLength = wcslen(CertHash) + 1;
        if (dwLength % 3)
            return ERROR_BAD_LENGTH;
        Attribute->ValueSize = dwLength / 3;
    } else {
        dwLength = wcslen(CertHash);
        if (dwLength % 2)
            return ERROR_BAD_LENGTH;
        Attribute->ValueSize = dwLength / 2;
    }

    /* Fix to SHA256 length for now */
    if (Attribute->ValueSize != 32)
        return ERROR_BAD_LENGTH;

    Attribute->Value = LocalAlloc(LPTR, Attribute->ValueSize);
    if (Attribute->Value == NULL)
        return GetLastError();

    *pbFreeAttrValue = TRUE;

    for (i = 0; i < Attribute->ValueSize; i++) {
        int iByte, iChar = bColonSeparated ? 3 : 2;

        if (_snwscanf(&CertHash[i * iChar], iChar, L"%02x", &iByte) != 1)
            return ERROR_BAD_FORMAT;

        Attribute->Value[i] = iByte & 0xFF;
    }

    return ERROR_SUCCESS;
}

static DWORD
MsGetCredServerHash(LPWSTR TargetName,
                    LPWSTR UserName,
                    PCREDENTIAL_ATTRIBUTE Attribute,
                    LPWSTR *StringValue)
{
    LPWSTR szHash;
    DWORD i;

    szHash = LocalAlloc(LPTR, Attribute->ValueSize * 3 * sizeof(WCHAR));
    if (szHash == NULL)
        return GetLastError();

    for (i = 0; i < Attribute->ValueSize; i++) {
        _snwprintf(&szHash[i * 3], 4, L"%02x:", Attribute->Value[i]);
    }
    szHash[i * 3 - 1] = 0;

    *StringValue = szHash;
    return ERROR_SUCCESS;
}

static DWORD
MsSetCredSubjectName(LPWSTR TargetName,
                     LPWSTR UserName,
                     LPWSTR SubjectName,
                     PCREDENTIAL_ATTRIBUTE Attribute,
                     BOOLEAN *pbFreeAttrValue)
{
    DWORD dwResult;

    if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       SubjectName,
                       CERT_X500_NAME_STR,
                       NULL,
                       NULL,
                       &Attribute->ValueSize,
                       NULL)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"CertStrToName failed: 0x%08x\n", dwResult);
        return dwResult;
    }

    Attribute->Value = LocalAlloc(LPTR, Attribute->ValueSize);
    if (Attribute->Value == NULL)
        return GetLastError();

    if (!CertStrToName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       SubjectName,
                       CERT_X500_NAME_STR,
                       NULL,
                       Attribute->Value,
                       &Attribute->ValueSize,
                       NULL)) {
        dwResult = GetLastError();
        fwprintf(stderr, L"CertStrToName failed: 0x%08x\n", dwResult);
        LocalFree(Attribute->Value);
        return dwResult;
    }

    *pbFreeAttrValue = TRUE;
    return ERROR_SUCCESS;
}

static DWORD
MsGetCredSubjectName(LPWSTR TargetName,
                     LPWSTR UserName,
                     PCREDENTIAL_ATTRIBUTE Attribute,
                     LPWSTR *pSubjectName)
{
    LPWSTR SubjectName;
    CERT_NAME_BLOB CertNameBlob;
    DWORD cbSize;

    *pSubjectName = NULL;

    CertNameBlob.cbData = Attribute->ValueSize;
    CertNameBlob.pbData = Attribute->Value;

    cbSize = CertNameToStr(X509_ASN_ENCODING,
                           &CertNameBlob,
                           CERT_X500_NAME_STR,
                           NULL,
                           0);
    if (cbSize == 0)
        return GetLastError();
    else if (cbSize == 1)
        return ERROR_SUCCESS;

    SubjectName = LocalAlloc(LPTR, (cbSize + 1) * sizeof(WCHAR));
    if (SubjectName == NULL)
        return GetLastError();

    cbSize = CertNameToStr(X509_ASN_ENCODING,
                           &CertNameBlob,
                           CERT_X500_NAME_STR,
                           SubjectName,
                           cbSize);
    if (cbSize == 0)
        return GetLastError();

    SubjectName[cbSize] = 0;
    *pSubjectName = SubjectName;

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

static DWORD
MsGetCredSubjectAltName(LPWSTR TargetName,
                        LPWSTR UserName,
                        PCREDENTIAL_ATTRIBUTE Attribute,
                        LPWSTR *pCredSan)
{
    LPWSTR CredSan;

    CredSan = LocalAlloc(LPTR, Attribute->ValueSize + sizeof(WCHAR));
    if (CredSan == NULL)
        return GetLastError();

    memcpy(CredSan, Attribute->Value, Attribute->ValueSize);
    CredSan[Attribute->ValueSize / sizeof(WCHAR)] = 0;

    *pCredSan = CredSan;

    return ERROR_SUCCESS;
}

static struct _MS_CRED_ATTR_HANDLER {
    LPWSTR Attribute;
    LPWSTR DisplayName;
    MsAttrSetterFn AttrSetter;
    MsAttrGetterFn AttrGetter;
} msCredAttrSetters[] = {
    {
        NULL,
        NULL
    },
    {
        L"Moonshot_CACertificate",
        L"CA Certificate",
        MsSetCredCaCert,
        MsGetCredCaCert,
    },
    {
        L"Moonshot_ServerCertificateHash",
        L"Server fingerprint",
        MsSetCredServerHash,
        MsGetCredServerHash,
    },
    {
        L"Moonshot_SubjectNameConstraint",
        L"Subject name",
        MsSetCredSubjectName,
        MsGetCredSubjectName,
    },
    {
        L"Moonshot_SubjectAltNameConstraint",
        L"Subject alternative name",
        MsSetCredSubjectAltName,
        MsGetCredSubjectAltName,
    },
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

        if (Credential.Attributes[iAttr].ValueSize > CRED_MAX_VALUE_SIZE) {
            dwResult = ERROR_BAD_LENGTH;
            goto cleanup;
        }

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

static DWORD
FormatDisplayCred(
    LPWSTR TargetName,
    LPWSTR UserName,
    DWORD dwAttrType,
    PCREDENTIAL Cred,
    LPWSTR *pDisplayName,
    LPWSTR *pDisplayValue)
{
    DWORD dwResult;
    LONG i, iAttr = -1;
    struct _MS_CRED_ATTR_HANDLER *Handler;

    Handler = &msCredAttrSetters[dwAttrType];

    assert(Handler->Attribute != NULL);
    assert(Handler->AttrGetter != NULL);

    *pDisplayName = NULL;
    *pDisplayValue = NULL;

    for (i = 0, iAttr = -1; i < Cred->AttributeCount; i++) {
        PCREDENTIAL_ATTRIBUTE Attr = &Cred->Attributes[i];

        if (_wcsicmp(Attr->Keyword, Handler->Attribute) == 0) {
            iAttr = i;
            break;
        }
    }

    *pDisplayName = LocalAlloc(LPTR,
                               (wcslen(Handler->DisplayName) + 1) * sizeof(WCHAR));
    if (*pDisplayName == NULL)
        return GetLastError();

    wcscpy(*pDisplayName, Handler->DisplayName);

    if (iAttr == -1)
        return ERROR_NOT_FOUND;

    dwResult = Handler->AttrGetter(TargetName,
                                   UserName,
                                   &Cred->Attributes[iAttr],
                                   pDisplayValue);

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
    PCREDENTIAL_TARGET_INFORMATION pTargetInfo = NULL;
    CREDENTIAL_TARGET_INFORMATION TargetInfo = { 0 };
    PCREDENTIAL *ExistingCreds = NULL;

    if (dwAttrType < MS_CRED_ATTR_MIN || dwAttrType > MS_CRED_ATTR_MAX) {
        dwResult = ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if (!CredGetTargetInfo(TargetName, 0, &pTargetInfo)) {
        dwResult = GetLastError();
        if (dwResult == ERROR_NOT_FOUND) {
            /* try directly */
            TargetInfo.TargetName = TargetName;
            pTargetInfo = &TargetInfo;
        } else {
            fwprintf(stderr, L"CredGetTargetInfo failed: 0x%08x\n", dwResult);
            goto cleanup;
        }
    }

    if (!CredReadDomainCredentials(pTargetInfo, 0,
                                   &dwCredCount, &ExistingCreds)) {
        dwResult = GetLastError();
        if (dwResult == ERROR_NOT_FOUND) {
            fwprintf(stderr, L"No existing credential for %s\n", TargetName);
        } else {
            fwprintf(stderr, L"CredReadDomainCredentials failed: 0x%08x\n", dwResult);
        }
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

    dwResult = ERROR_SUCCESS;

cleanup:
    if (ExistingCreds != NULL)
        CredFree(ExistingCreds);
    if (pTargetInfo != NULL && pTargetInfo != &TargetInfo)
        CredFree(pTargetInfo);
    return dwResult;
}

DWORD
MsGetCredAttribute(
    LPWSTR TargetName,
    LPWSTR UserName,
    LPWSTR **pDisplayNames,
    LPWSTR **pDisplayValues)
{
    DWORD dwResult;
    DWORD dwCredCount = 0, i;
    LONG iCred;
    BOOLEAN bFoundAttr;
    PCREDENTIAL_TARGET_INFORMATION pTargetInfo = NULL;
    PCREDENTIAL *Creds = NULL;
    CREDENTIAL_TARGET_INFORMATION TargetInfo = { 0 };

    *pDisplayNames = NULL;
    *pDisplayValues = NULL;

    if (!CredGetTargetInfo(TargetName, 0, &pTargetInfo)) {
        dwResult = GetLastError();
        if (dwResult == ERROR_NOT_FOUND) {
            /* try directly */
            TargetInfo.TargetName = TargetName;
            pTargetInfo = &TargetInfo;
        } else {
            fwprintf(stderr, L"CredGetTargetInfo failed: 0x%08x\n", dwResult);
            goto cleanup;
        }
    }

    if (!CredReadDomainCredentials(pTargetInfo, 0,
                                   &dwCredCount, &Creds)) {
        dwResult = GetLastError();
        if (dwResult == ERROR_NOT_FOUND) {
            fwprintf(stderr, L"No existing credential for %s\n", TargetName);
        } else {
            fwprintf(stderr, L"CredReadDomainCredentials failed: 0x%08x\n", dwResult);
        }
        goto cleanup;
    }

    for (i = 0, iCred = -1; i < dwCredCount; i++) {
        if (_wcsicmp(Creds[i]->UserName, UserName) == 0) {
            iCred = i;
            break;
        }
    }

    if (iCred == -1) {
        fwprintf(stderr, L"No credentials for %s match username %s\n", TargetName, UserName);
        dwResult = ERROR_NOT_FOUND;
        goto cleanup;
    }

    *pDisplayNames = LocalAlloc(LPTR, MS_CRED_ATTR_MAX * sizeof(LPWSTR));
    if (*pDisplayNames == NULL) {
        dwResult = GetLastError();
        goto cleanup;
    }

    *pDisplayValues = LocalAlloc(LPTR, MS_CRED_ATTR_MAX * sizeof(LPWSTR));
    if (*pDisplayValues == NULL) {
        dwResult = GetLastError();
        goto cleanup;
    }

    for (i = 0, bFoundAttr = FALSE; i < MS_CRED_ATTR_MAX; i++) {
        dwResult = FormatDisplayCred(TargetName, UserName, i + MS_CRED_ATTR_MIN,
                                     Creds[iCred],
                                     &(*pDisplayNames)[i],
                                     &(*pDisplayValues)[i]);
        if (dwResult == ERROR_SUCCESS)
            bFoundAttr = TRUE;
    }

    dwResult = bFoundAttr ? ERROR_SUCCESS : ERROR_NOT_FOUND;

cleanup:
    if (Creds != NULL)
        CredFree(Creds);
    if (pTargetInfo != NULL && pTargetInfo != &TargetInfo)
        CredFree(pTargetInfo);

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
