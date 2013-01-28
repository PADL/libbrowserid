#pragma once

typedef struct bignum_st BIGNUM;
/* Used for temp variables (declaration hidden in bn_lcl.h) */
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;

#include <windows.h>

#include <bn/bn.h>

#include <stdlib.h>
#include <string.h>

#define BNerr(a, b)

static void OPENSSL_cleanse(void *ptr, size_t nbytes)
{
    SecureZeroMemory(ptr, nbytes);
}

static void OPENSSL_free(void *ptr)
{
    LocalFree(ptr);
}

static void *OPENSSL_malloc(size_t nbytes)
{
    return LocalAlloc(0, nbytes);
}

