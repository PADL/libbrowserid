/*
 * Copyright (C) 2012 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 */

#ifndef _KSECEAP_H_
#define _KSECEAP_H_ 1

#include "../eapssp/gssp.h"

#define KSECEAP_BAIL_ON_BAD_OFFSET(StructSize, Offset, Length)  \
    do { \
        if ((Offset) + (Length) > (StructSize)) { \
            KdPrint(("%s: Invalid Offset %d Length %d StructSize %d", \
                     __FUNCTION__, (Offset), (Length), (StructSize))); \
            Status = STATUS_BUFFER_TOO_SMALL; \
            goto cleanup; \
        } \
    } while (0)

#define KSECEAP_SIGNATURE                   0x00688889
#define KSECEAP_TAG                         ((ULONG)'EapS')

KspInitPackageFn                    EapInitKernelPackage;
KspDeleteContextFn                  EapDeleteKernelContext;
KspInitContextFn                    EapInitKernelContext;
KspMapHandleFn                      EapMapKernelHandle;
KspMakeSignatureFn                  EapMakeSignature;
KspVerifySignatureFn                EapVerifySignature;
KspSealMessageFn                    EapSealMessage;
KspUnsealMessageFn                  EapUnsealMessage;
KspGetTokenFn                       EapGetContextToken;
KspQueryAttributesFn                EapAes128QueryContextAttributes;
KspQueryAttributesFn                EapAes256QueryContextAttributes;
KspCompleteTokenFn                  EapCompleteToken;
SpExportSecurityContextFn           EapExportSecurityContext;
SpImportSecurityContextFn           EapImportSecurityContext;
KspSetPagingModeFn                  EapSetPagingMode;
KspSerializeAuthDataFn              EapSerializeAuthData;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, EapInitKernelPackage)
#pragma alloc_text(PAGE, EapDeleteKernelContext)
#pragma alloc_text(PAGE, EapInitKernelContext)
#pragma alloc_text(PAGE, EapMapKernelHandle)
#pragma alloc_text(PAGE, EapMakeSignature)
#pragma alloc_text(PAGE, EapVerifySignature)
#pragma alloc_text(PAGE, EapSealMessage)
#pragma alloc_text(PAGE, EapUnsealMessage)
#pragma alloc_text(PAGE, EapGetContextToken)
#pragma alloc_text(PAGE, EapAes128QueryContextAttributes)
#pragma alloc_text(PAGE, EapAes256QueryContextAttributes)
#pragma alloc_text(PAGE, EapCompleteToken)
#pragma alloc_text(PAGE, EapExportSecurityContext)
#pragma alloc_text(PAGE, EapImportSecurityContext)
#pragma alloc_text(PAGE, EapSetPagingMode)
#pragma alloc_text(PAGE, EapSerializeAuthData)
#endif

#endif /* _KSECEAP_H_ */
