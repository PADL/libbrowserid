/*
 * SSL/TLS interface functions for Microsoft Schannel
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

/*
 * FIX: Go through all SSPI functions and verify what needs to be freed
 * FIX: session resumption
 * TODO: add support for server cert chain validation
 * TODO: add support for CA cert validation
 * TODO: add support for EAP-TLS (client cert/key conf)
 */

#include "includes.h"
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#ifdef GSSEAP_SSP
#include <NTSecAPI.h>
#include <NTSecPkg.h>
#include <Sddl.h>
#endif
#include "common.h"
#include "tls.h"

struct tls_global {
	HMODULE hsecurity;
	PSecurityFunctionTable sspi;
};

struct tls_connection {
	int established, start;
	int failed, read_alerts, write_alerts;

	HCERTSTORE my_cert_store;
	SCHANNEL_CRED schannel_cred;
	ALG_ID algs[2];
	CredHandle creds;
	CtxtHandle context;
};


static int schannel_load_lib(struct tls_global *global)
{
	INIT_SECURITY_INTERFACE pInitSecurityInterface;

	global->hsecurity = LoadLibrary(TEXT("Secur32.dll"));
	if (global->hsecurity == NULL) {
		wpa_printf(MSG_ERROR, "%s: Could not load Secur32.dll - 0x%x",
			   __func__, (unsigned int) GetLastError());
		return -1;
	}

	pInitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(
		global->hsecurity, "InitSecurityInterfaceA");
	if (pInitSecurityInterface == NULL) {
		wpa_printf(MSG_ERROR, "%s: Could not find "
			   "InitSecurityInterfaceA from Secur32.dll",
			   __func__);
		FreeLibrary(global->hsecurity);
		global->hsecurity = NULL;
		return -1;
	}

	global->sspi = pInitSecurityInterface();
	if (global->sspi == NULL) {
		wpa_printf(MSG_ERROR, "%s: Could not read security "
			   "interface - 0x%x",
			   __func__, (unsigned int) GetLastError());
		FreeLibrary(global->hsecurity);
		global->hsecurity = NULL;
		return -1;
	}

	return 0;
}


void * tls_init(const struct tls_config *conf)
{
	struct tls_global *global;

	global = os_zalloc(sizeof(*global));
	if (global == NULL)
		return NULL;
	if (schannel_load_lib(global)) {
		os_free(global);
		return NULL;
	}
	return global;
}


void tls_deinit(void *ssl_ctx)
{
	struct tls_global *global = ssl_ctx;

	FreeLibrary(global->hsecurity);
	os_free(global);
}


int tls_get_errors(void *ssl_ctx)
{
	return 0;
}


struct tls_connection * tls_connection_init(void *ssl_ctx)
{
	struct tls_connection *conn;

	conn = os_zalloc(sizeof(*conn));
	if (conn == NULL)
		return NULL;
	conn->start = 1;

	return conn;
}


void tls_connection_deinit(void *ssl_ctx, struct tls_connection *conn)
{
	if (conn == NULL)
		return;
	if (conn->my_cert_store)
		CertCloseStore(conn->my_cert_store, 0);
	os_free(conn);
}


int tls_connection_established(void *ssl_ctx, struct tls_connection *conn)
{
	return conn ? conn->established : 0;
}


int tls_connection_shutdown(void *ssl_ctx, struct tls_connection *conn)
{
	struct tls_global *global = ssl_ctx;
	if (conn == NULL)
		return -1;

	conn->established = 0;
	conn->failed = 0;
	conn->read_alerts = 0;
	conn->write_alerts = 0;

	global->sspi->DeleteSecurityContext(&conn->context);
	/* FIXME: what else needs to be reset? */

	return 0;
}


int tls_global_set_params(void *tls_ctx,
			  const struct tls_connection_params *params)
{
	return -1;
}


int tls_global_set_verify(void *ssl_ctx, int check_crl)
{
	return -1;
}


int tls_connection_set_verify(void *ssl_ctx, struct tls_connection *conn,
			      int verify_peer)
{
	return -1;
}


int tls_connection_get_keys(void *tls_ctx, struct tls_connection *conn,
			    struct tls_keys *keys)
{
	return -1;
}

static const char *
tls_prf_labels[] = {
	"client EAP encryption",
	"ttls keying material",
	"ttls challenge",
	"key expansion"
};

int tls_connection_prf(void *tls_ctx, struct tls_connection *conn,
		       const char *label, int server_random_first,
		       u8 *out, size_t out_len)
{
	struct tls_global *global = tls_ctx;
	SECURITY_STATUS status;
	SecPkgContext_EapPrfInfo epi;
	SecPkgContext_EapKeyBlock ekb;
	DWORD i, dwLabel = (DWORD)-1;

	os_memset(out, 0, out_len);

	if (conn == NULL || server_random_first) {
		return -1;
	}

	for (i = 0;
	     i < sizeof(tls_prf_labels) / sizeof(tls_prf_labels[0]);
	     i++) {
		if (os_strcmp(label, tls_prf_labels[i]) == 0) {
			dwLabel = i;
			break;
		}
	}

	if (dwLabel == (DWORD)-1) {
		return -1;
	}

	epi.dwVersion = 0;
	epi.cbPrfData = sizeof(dwLabel);
	epi.pbPrfData = (PBYTE)&dwLabel;

	status = SetContextAttributesA(&conn->context,
				       SECPKG_ATTR_EAP_PRF_INFO,
				       &epi,
				       sizeof(epi));
	if (status != SEC_E_OK) {
		wpa_printf(MSG_DEBUG, "%s: SetContextAttributes("
			   "SECPKG_ATTR_EAP_PRF_INFO) failed (%d)",
			   __func__, (int) status);
		return -1;
	}

	status = global->sspi->QueryContextAttributes(&conn->context,
						      SECPKG_ATTR_EAP_KEY_BLOCK,
						      &ekb);
	if (status != SEC_E_OK) {
		wpa_printf(MSG_DEBUG, "%s: QueryContextAttributes("
			   "SECPKG_ATTR_EAP_KEY_BLOCK) failed (%d)",
			   __func__, (int) status);
		return -1;
	}

	wpa_hexdump_key(MSG_MSGDUMP, "Schannel - EapKeyBlock - rgbKeys",
			ekb.rgbKeys, sizeof(ekb.rgbKeys));
	wpa_hexdump_key(MSG_MSGDUMP, "Schannel - EapKeyBlock - rgbIVs",
			ekb.rgbIVs, sizeof(ekb.rgbIVs));

	if (out_len > sizeof(ekb.rgbKeys))
		out_len = sizeof(ekb.rgbKeys);

	os_memcpy(out, ekb.rgbKeys, out_len);

	return 0;
}


static struct wpabuf * tls_conn_hs_clienthello(struct tls_global *global,
					       struct tls_connection *conn)
{
	DWORD sspi_flags, sspi_flags_out;
	SecBufferDesc outbuf;
	SecBuffer outbufs[1];
	SECURITY_STATUS status;
	TimeStamp ts_expiry;

	sspi_flags = ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION;

	wpa_printf(MSG_DEBUG, "%s: Generating ClientHello", __func__);

	outbufs[0].pvBuffer = NULL;
	outbufs[0].BufferType = SECBUFFER_TOKEN;
	outbufs[0].cbBuffer = 0;

	outbuf.cBuffers = 1;
	outbuf.pBuffers = outbufs;
	outbuf.ulVersion = SECBUFFER_VERSION;

#ifdef UNICODE
	status = global->sspi->InitializeSecurityContextW(
		&conn->creds, NULL, NULL /* server name */, sspi_flags, 0,
		SECURITY_NATIVE_DREP, NULL, 0, &conn->context,
		&outbuf, &sspi_flags_out, &ts_expiry);
#else /* UNICODE */
	status = global->sspi->InitializeSecurityContextA(
		&conn->creds, NULL, NULL /* server name */, sspi_flags, 0,
		SECURITY_NATIVE_DREP, NULL, 0, &conn->context,
		&outbuf, &sspi_flags_out, &ts_expiry);
#endif /* UNICODE */
	if (status != SEC_I_CONTINUE_NEEDED) {
		wpa_printf(MSG_ERROR, "%s: InitializeSecurityContextA "
			   "failed - 0x%x",
			   __func__, (unsigned int) status);
		return NULL;
	}

	if (outbufs[0].cbBuffer != 0 && outbufs[0].pvBuffer) {
		struct wpabuf *buf;
		wpa_hexdump(MSG_MSGDUMP, "SChannel - ClientHello",
			    outbufs[0].pvBuffer, outbufs[0].cbBuffer);
		conn->start = 0;
		buf = wpabuf_alloc_copy(outbufs[0].pvBuffer,
					outbufs[0].cbBuffer);
		if (buf == NULL)
			return NULL;
		global->sspi->FreeContextBuffer(outbufs[0].pvBuffer);
		return buf;
	}

	wpa_printf(MSG_ERROR, "SChannel: Failed to generate ClientHello");

	return NULL;
}



struct wpabuf * tls_connection_handshake(void *tls_ctx,
					 struct tls_connection *conn,
					 const struct wpabuf *in_data,
					 struct wpabuf **appl_data)
{
	struct tls_global *global = tls_ctx;
	DWORD sspi_flags, sspi_flags_out;
	SecBufferDesc inbuf, outbuf;
	SecBuffer inbufs[2], outbufs[1];
	SECURITY_STATUS status;
	TimeStamp ts_expiry;
	struct wpabuf *out_buf = NULL;

	if (appl_data)
		*appl_data = NULL;

	if (conn->start)
		return tls_conn_hs_clienthello(global, conn);

	wpa_printf(MSG_DEBUG, "SChannel: %d bytes handshake data to process",
		   (int) wpabuf_len(in_data));

	sspi_flags = ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION;

	/* Input buffer for Schannel */
	inbufs[0].pvBuffer = (u8 *) wpabuf_head(in_data);
	inbufs[0].cbBuffer = wpabuf_len(in_data);
	inbufs[0].BufferType = SECBUFFER_TOKEN;

	/* Place for leftover data from Schannel */
	inbufs[1].pvBuffer = NULL;
	inbufs[1].cbBuffer = 0;
	inbufs[1].BufferType = SECBUFFER_EMPTY;

	inbuf.cBuffers = 2;
	inbuf.pBuffers = inbufs;
	inbuf.ulVersion = SECBUFFER_VERSION;

	/* Output buffer for Schannel */
	outbufs[0].pvBuffer = NULL;
	outbufs[0].cbBuffer = 0;
	outbufs[0].BufferType = SECBUFFER_TOKEN;

	outbuf.cBuffers = 1;
	outbuf.pBuffers = outbufs;
	outbuf.ulVersion = SECBUFFER_VERSION;

#ifdef UNICODE
	status = global->sspi->InitializeSecurityContextW(
		&conn->creds, &conn->context, NULL, sspi_flags, 0,
		SECURITY_NATIVE_DREP, &inbuf, 0, NULL,
		&outbuf, &sspi_flags_out, &ts_expiry);
#else /* UNICODE */
	status = global->sspi->InitializeSecurityContextA(
		&conn->creds, &conn->context, NULL, sspi_flags, 0,
		SECURITY_NATIVE_DREP, &inbuf, 0, NULL,
		&outbuf, &sspi_flags_out, &ts_expiry);
#endif /* UNICODE */

	wpa_printf(MSG_MSGDUMP, "Schannel: InitializeSecurityContext -> "
		   "status=%d inlen[0]=%d intype[0]=%d inlen[1]=%d "
		   "intype[1]=%d outlen[0]=%d",
		   (int) status, (int) inbufs[0].cbBuffer,
		   (int) inbufs[0].BufferType, (int) inbufs[1].cbBuffer,
		   (int) inbufs[1].BufferType,
		   (int) outbufs[0].cbBuffer);
	if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED ||
	    (FAILED(status) && (sspi_flags_out & ISC_RET_EXTENDED_ERROR))) {
		if (outbufs[0].cbBuffer != 0 && outbufs[0].pvBuffer) {
			wpa_hexdump(MSG_MSGDUMP, "SChannel - output",
				    outbufs[0].pvBuffer, outbufs[0].cbBuffer);
			out_buf = wpabuf_alloc_copy(outbufs[0].pvBuffer,
						    outbufs[0].cbBuffer);
			global->sspi->FreeContextBuffer(outbufs[0].pvBuffer);
			outbufs[0].pvBuffer = NULL;
			if (out_buf == NULL)
				return NULL;
		}
	}

	switch (status) {
	case SEC_E_INCOMPLETE_MESSAGE:
		wpa_printf(MSG_DEBUG, "Schannel: SEC_E_INCOMPLETE_MESSAGE");
		break;
	case SEC_I_CONTINUE_NEEDED:
		wpa_printf(MSG_DEBUG, "Schannel: SEC_I_CONTINUE_NEEDED");
		break;
	case SEC_E_OK:
		/* TODO: verify server certificate chain */
		wpa_printf(MSG_DEBUG, "Schannel: SEC_E_OK - Handshake "
			   "completed successfully");
		conn->established = 1;

		/* Need to return something to get final TLS ACK. */
		if (out_buf == NULL)
			out_buf = wpabuf_alloc(0);

		if (inbufs[1].BufferType == SECBUFFER_EXTRA) {
			wpa_hexdump(MSG_MSGDUMP, "SChannel - Encrypted "
				    "application data",
				    inbufs[1].pvBuffer, inbufs[1].cbBuffer);
			if (appl_data) {
				*appl_data = wpabuf_alloc_copy(
					outbufs[1].pvBuffer,
					outbufs[1].cbBuffer);
			}
			global->sspi->FreeContextBuffer(inbufs[1].pvBuffer);
			inbufs[1].pvBuffer = NULL;
		}
		break;
	case SEC_I_INCOMPLETE_CREDENTIALS:
		wpa_printf(MSG_DEBUG,
			   "Schannel: SEC_I_INCOMPLETE_CREDENTIALS");
		break;
	case SEC_E_WRONG_PRINCIPAL:
		wpa_printf(MSG_DEBUG, "Schannel: SEC_E_WRONG_PRINCIPAL");
		break;
	case SEC_E_INTERNAL_ERROR:
		wpa_printf(MSG_DEBUG, "Schannel: SEC_E_INTERNAL_ERROR");
		break;
	}

	if (FAILED(status)) {
		wpa_printf(MSG_DEBUG, "Schannel: Handshake failed "
			   "(out_buf=%p)", out_buf);
		conn->failed++;
		global->sspi->DeleteSecurityContext(&conn->context);
		return out_buf;
	}

	if (inbufs[1].BufferType == SECBUFFER_EXTRA) {
		/* TODO: Can this happen? What to do with this data? */
		wpa_hexdump(MSG_MSGDUMP, "SChannel - Leftover data",
			    inbufs[1].pvBuffer, inbufs[1].cbBuffer);
		global->sspi->FreeContextBuffer(inbufs[1].pvBuffer);
		inbufs[1].pvBuffer = NULL;
	}

	return out_buf;
}


struct wpabuf * tls_connection_server_handshake(void *tls_ctx,
						struct tls_connection *conn,
						const struct wpabuf *in_data,
						struct wpabuf **appl_data)
{
	return NULL;
}


struct wpabuf * tls_connection_encrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
	struct tls_global *global = tls_ctx;
	SECURITY_STATUS status;
	SecBufferDesc buf;
	SecBuffer bufs[4];
	SecPkgContext_StreamSizes sizes;
	int i;
	struct wpabuf *out;

	status = global->sspi->QueryContextAttributes(&conn->context,
						      SECPKG_ATTR_STREAM_SIZES,
						      &sizes);
	if (status != SEC_E_OK) {
		wpa_printf(MSG_DEBUG, "%s: QueryContextAttributes failed",
			   __func__);
		return NULL;
	}
	wpa_printf(MSG_DEBUG, "%s: Stream sizes: header=%u trailer=%u",
		   __func__,
		   (unsigned int) sizes.cbHeader,
		   (unsigned int) sizes.cbTrailer);

	out = wpabuf_alloc(sizes.cbHeader + wpabuf_len(in_data) +
			   sizes.cbTrailer);

	os_memset(&bufs, 0, sizeof(bufs));
	bufs[0].pvBuffer = wpabuf_put(out, sizes.cbHeader);
	bufs[0].cbBuffer = sizes.cbHeader;
	bufs[0].BufferType = SECBUFFER_STREAM_HEADER;

	bufs[1].pvBuffer = wpabuf_put(out, 0);
	wpabuf_put_buf(out, in_data);
	bufs[1].cbBuffer = wpabuf_len(in_data);
	bufs[1].BufferType = SECBUFFER_DATA;

	bufs[2].pvBuffer = wpabuf_put(out, 0);
	bufs[2].cbBuffer = sizes.cbTrailer;
	bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;

	bufs[3].pvBuffer = NULL;
	bufs[3].cbBuffer = 0;
	bufs[3].BufferType = SECBUFFER_EMPTY;

	buf.ulVersion = SECBUFFER_VERSION;
	buf.cBuffers = sizeof(bufs) / sizeof(bufs[0]);
	buf.pBuffers = bufs;

	status = global->sspi->EncryptMessage(&conn->context, 0, &buf, 0);

	wpabuf_put(out, bufs[2].cbBuffer);

	wpa_printf(MSG_MSGDUMP, "Schannel: EncryptMessage -> "
		   "status=%d len[0]=%d type[0]=%d len[1]=%d type[1]=%d "
		   "len[2]=%d type[2]=%d",
		   (int) status,
		   (int) bufs[0].cbBuffer, (int) bufs[0].BufferType,
		   (int) bufs[1].cbBuffer, (int) bufs[1].BufferType,
		   (int) bufs[2].cbBuffer, (int) bufs[2].BufferType);
	wpa_printf(MSG_MSGDUMP, "Schannel: EncryptMessage pointers: "
		   "out_data=%p bufs %p %p %p",
		   wpabuf_head(out), bufs[0].pvBuffer, bufs[1].pvBuffer,
		   bufs[2].pvBuffer);

	for (i = 0; i < buf.cBuffers; i++) {
		if (bufs[i].pvBuffer && bufs[i].BufferType != SECBUFFER_EMPTY)
		{
			wpa_hexdump(MSG_MSGDUMP, "SChannel: bufs",
				    bufs[i].pvBuffer, bufs[i].cbBuffer);
		}
	}

	if (status == SEC_E_OK) {
		wpa_printf(MSG_DEBUG, "%s: SEC_E_OK", __func__);
		wpa_hexdump_buf_key(MSG_MSGDUMP, "Schannel: Encrypted data "
				    "from EncryptMessage", out);
		return out;
	}

	wpa_printf(MSG_DEBUG, "%s: Failed - status=%d",
		   __func__, (int) status);
	wpabuf_free(out);
	return NULL;
}


struct wpabuf * tls_connection_decrypt(void *tls_ctx,
				       struct tls_connection *conn,
				       const struct wpabuf *in_data)
{
	struct tls_global *global = tls_ctx;
	SECURITY_STATUS status;
	SecBufferDesc buf;
	SecBuffer bufs[4];
	PSecBuffer data = NULL;
	PSecBuffer extra = NULL;
	int i;
	struct wpabuf *out, *tmp;

	wpa_hexdump_buf(MSG_MSGDUMP,
			"Schannel: Encrypted data to DecryptMessage", in_data);
	os_memset(&bufs, 0, sizeof(bufs));
	tmp = wpabuf_dup(in_data);
	if (tmp == NULL)
		return NULL;
	bufs[0].pvBuffer = wpabuf_mhead(tmp);
	bufs[0].cbBuffer = wpabuf_len(in_data);
	bufs[0].BufferType = SECBUFFER_DATA;

	bufs[1].BufferType = SECBUFFER_EMPTY;
	bufs[2].BufferType = SECBUFFER_EMPTY;
	bufs[3].BufferType = SECBUFFER_EMPTY;

	buf.ulVersion = SECBUFFER_VERSION;
	buf.cBuffers = sizeof(bufs) / sizeof(bufs[0]);
	buf.pBuffers = bufs;

	status = global->sspi->DecryptMessage(&conn->context, &buf, 0, NULL);
	wpa_printf(MSG_MSGDUMP, "Schannel: DecryptMessage -> "
		   "status=%d len[0]=%d type[0]=%d len[1]=%d type[1]=%d "
		   "len[2]=%d type[2]=%d len[3]=%d type[3]=%d",
		   (int) status,
		   (int) bufs[0].cbBuffer, (int) bufs[0].BufferType,
		   (int) bufs[1].cbBuffer, (int) bufs[1].BufferType,
		   (int) bufs[2].cbBuffer, (int) bufs[2].BufferType,
		   (int) bufs[3].cbBuffer, (int) bufs[3].BufferType);
	wpa_printf(MSG_MSGDUMP, "Schannel: DecryptMessage pointers: "
		   "out_data=%p bufs %p %p %p %p",
		   wpabuf_head(tmp), bufs[0].pvBuffer, bufs[1].pvBuffer,
		   bufs[2].pvBuffer, bufs[3].pvBuffer);

	switch (status) {
	case SEC_E_INCOMPLETE_MESSAGE:
		wpa_printf(MSG_DEBUG, "%s: SEC_E_INCOMPLETE_MESSAGE",
			   __func__);
		break;
	case SEC_E_OK:
		wpa_printf(MSG_DEBUG, "%s: SEC_E_OK", __func__);
		for (i = 0; i < buf.cBuffers; i++) {
			if (data == NULL &&
			    bufs[i].BufferType == SECBUFFER_DATA)
				data = &bufs[i];
			else if (extra == NULL &&
			    bufs[i].BufferType == SECBUFFER_EXTRA)
				extra = &bufs[i];
		}
		if (data == NULL) {
			wpa_printf(MSG_DEBUG, "%s: No output data from "
				   "DecryptMessage", __func__);
			wpabuf_free(tmp);
			return NULL;
		}
		wpa_hexdump_key(MSG_MSGDUMP, "Schannel: Decrypted data from "
				"DecryptMessage",
				data->pvBuffer, data->cbBuffer);
		out = wpabuf_alloc_copy(data->pvBuffer, data->cbBuffer);
		wpabuf_free(tmp);

		return out;
	}

	wpa_printf(MSG_DEBUG, "%s: Failed - status=%d",
		   __func__, (int) status);
	wpabuf_free(tmp);
	return NULL;
}


int tls_connection_resumed(void *ssl_ctx, struct tls_connection *conn)
{
	return 0;
}


int tls_connection_set_cipher_list(void *tls_ctx, struct tls_connection *conn,
				   u8 *ciphers)
{
	return -1;
}


int tls_get_cipher(void *ssl_ctx, struct tls_connection *conn,
		   char *buf, size_t buflen)
{
	return -1;
}


int tls_connection_enable_workaround(void *ssl_ctx,
				     struct tls_connection *conn)
{
	return 0;
}


int tls_connection_client_hello_ext(void *ssl_ctx, struct tls_connection *conn,
				    int ext_type, const u8 *data,
				    size_t data_len)
{
	return -1;
}


int tls_connection_get_failed(void *ssl_ctx, struct tls_connection *conn)
{
	if (conn == NULL)
		return -1;
	return conn->failed;
}


int tls_connection_get_read_alerts(void *ssl_ctx, struct tls_connection *conn)
{
	if (conn == NULL)
		return -1;
	return conn->read_alerts;
}


int tls_connection_get_write_alerts(void *ssl_ctx, struct tls_connection *conn)
{
	if (conn == NULL)
		return -1;
	return conn->write_alerts;
}

#ifdef GSSEAP_SSP
extern PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable;

/*
 * Get the certificate store path by the LSA calling user's SID.
 */
static HCERTSTORE cryptoapi_find_user_store(void)
{
	SECPKG_CLIENT_INFO clientInfo;
	NTSTATUS status;
	PUCHAR tokenUserBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
	DWORD cbTokenUserBuffer = sizeof(tokenUserBuffer);
	PTOKEN_USER pTokenUser;
	LPSTR szTokenUser = NULL;
	ULONG cchTokenUser;
	LPWSTR wszStorePath = NULL;
	HCERTSTORE cs;

	status = LsaSpFunctionTable->GetClientInfo(&clientInfo);
	if (status)
		return NULL;

	if (!GetTokenInformation(clientInfo.ClientToken,
				 TokenUser, tokenUserBuffer,
				 cbTokenUserBuffer, &cbTokenUserBuffer))
		return NULL;

	pTokenUser = (PTOKEN_USER)tokenUserBuffer;

	if (!ConvertSidToStringSid(pTokenUser->User.Sid, &szTokenUser))
		return NULL;

	cchTokenUser = strlen(szTokenUser);

	wszStorePath = LocalAlloc(LPTR, sizeof(WCHAR) * (cchTokenUser + 4));
	if (wszStorePath == NULL) {
		LocalFree(szTokenUser);
		return NULL;
	}

	MultiByteToWideChar(CP_ACP, 0, szTokenUser, cchTokenUser,
			    wszStorePath, cchTokenUser);

	wcscpy(wszStorePath + cchTokenUser, L"\\MY");

	cs = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
			   CERT_SYSTEM_STORE_USERS |
				CERT_STORE_OPEN_EXISTING_FLAG |
			   	CERT_STORE_READONLY_FLAG,
			   wszStorePath);

	LocalFree(szTokenUser);
	LocalFree(wszStorePath);

	return cs;
}
#else
static LPWSTR cryptoapi_find_user_store(void)
{
	HCERTSTORE cs;

	cs = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
			   CERT_SYSTEM_STORE_CURRENT_USER |
				CERT_STORE_OPEN_EXISTING_FLAG |
			   	CERT_STORE_READONLY_FLAG,
			   L"MY");

	return cs;
}
#endif /* GSSEAP_SSP */

static const CERT_CONTEXT *cryptoapi_find_cert(const char *name,
					       HCERTSTORE cs)
{
	const CERT_CONTEXT *ret = NULL;

	if (strncmp(name, "cert://", 7) == 0) {
		unsigned short wbuf[255];
		MultiByteToWideChar(CP_ACP, 0, name + 7, -1, wbuf, 255);
		ret = CertFindCertificateInStore(cs, X509_ASN_ENCODING |
						 PKCS_7_ASN_ENCODING,
						 0, CERT_FIND_SUBJECT_STR,
						 wbuf, NULL);
	} else if (strncmp(name, "hash://", 7) == 0) {
		CRYPT_HASH_BLOB blob;
		int len;
		const char *hash = name + 7;
		unsigned char *buf;

		len = os_strlen(hash) / 2;
		buf = os_malloc(len);
		if (buf && hexstr2bin(hash, buf, len) == 0) {
			blob.cbData = len;
			blob.pbData = buf;
			ret = CertFindCertificateInStore(cs,
							 X509_ASN_ENCODING |
							 PKCS_7_ASN_ENCODING,
							 0, CERT_FIND_HASH,
							 &blob, NULL);
		}
		os_free(buf);
	}

	return ret;
}

int tls_connection_set_params(void *tls_ctx, struct tls_connection *conn,
			      const struct tls_connection_params *params)
{
	struct tls_global *global = tls_ctx;
	SECURITY_STATUS status;
	PCCERT_CONTEXT certContexts[1] = { NULL };
	TimeStamp ts_expiry;

	if (conn == NULL)
		return -1;

	conn->my_cert_store = cryptoapi_find_user_store();
	if (conn->my_cert_store == NULL) {
		wpa_printf(MSG_ERROR, "%s: CertOpenSystemStore failed - 0x%x",
			   __func__, (unsigned int) GetLastError());
		return -1;
	}

	if (params->private_key != NULL) {
		certContexts[0] = cryptoapi_find_cert(params->private_key,
						      conn->my_cert_store);
		if (certContexts[0] == NULL) {
			wpa_printf(MSG_ERROR, "%s: CertFindCertificateInStore failed - 0x%x",
			   	__func__, (unsigned int) GetLastError());
			return -1;
		}
	}

	os_memset(&conn->schannel_cred, 0, sizeof(conn->schannel_cred));
	conn->schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
	conn->schannel_cred.grbitEnabledProtocols = SP_PROT_TLS1;

	if (params->private_key != NULL) {
		conn->schannel_cred.cCreds = 1;
		conn->schannel_cred.paCred = certContexts;
	}

	/* TODO set DH params */
	conn->algs[0] = CALG_RSA_KEYX;
	conn->algs[1] = CALG_DH_EPHEM;
	conn->schannel_cred.cSupportedAlgs = 2;
	conn->schannel_cred.palgSupportedAlgs = conn->algs;

	conn->schannel_cred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION |
				      SCH_CRED_NO_DEFAULT_CREDS;

#ifdef UNICODE
	status = global->sspi->AcquireCredentialsHandleW(
		NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
		&conn->schannel_cred, NULL, NULL, &conn->creds, &ts_expiry);
#else /* UNICODE */
	status = global->sspi->AcquireCredentialsHandleA(
		NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
		&conn->schannel_cred, NULL, NULL, &conn->creds, &ts_expiry);
#endif /* UNICODE */
	if (status != SEC_E_OK) {
		wpa_printf(MSG_DEBUG, "%s: AcquireCredentialsHandleA failed - "
			   "0x%x", __func__, (unsigned int) status);
		return -1;
	}

	return 0;
}


unsigned int tls_capabilities(void *tls_ctx)
{
	return 0;
}
