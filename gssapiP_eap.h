/*
 * Copyright (c) 2010, JANET(UK)
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
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _GSSAPIP_EAP_H_
#define _GSSAPIP_EAP_H_ 1

#include <gssapi/gssapi.h>
#include <krb5.h>

#include "gssapi_eap.h"

struct gss_name_struct {
    OM_uint32 flags;
    krb5_principal principal;
    void *aaa;
    void *assertion;
};

#define CRED_FLAG_INITIATOR                 0x00000001
#define CRED_FLAG_ACCEPTOR                  0x00000002
#define CRED_FLAG_DEFAULT_IDENTITY          0x00000004
#define CRED_FLAG_PASSWORD                  0x00000008

struct gss_cred_id_struct {
    OM_uint32 flags;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    gss_buffer_desc password;
};

#define CTX_FLAG_INITIATOR                  0x00000001

enum eap_gss_state {
    EAP_STATE_AUTHENTICATE = 1,
    EAP_STATE_KEY_TRANSPORT,
    EAP_STATE_SECURE_ASSOCIATION,
    EAP_STATE_GSS_CHANNEL_BINDINGS,
    EAP_STATE_ESTABLISHED
};

struct gss_ctx_id_struct {
    enum eap_gss_state state;
    OM_uint32 flags;
    OM_uint32 gssFlags;
    krb5_context kerberosCtx;
    gss_OID mechanismUsed;
    krb5_cksumtype checksumType;
    krb5_keyblock *encryptionKey;
    gss_name_t initiatorName;
    gss_name_t acceptorName;
    OM_uint32 lifetime;
};

#endif /* _GSSAPIP_EAP_H_ */

