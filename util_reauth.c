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

#include "gssapiP_eap.h"

/*
 * Fast reauthentication support for EAP GSS.
 */

#define KRB5_AUTHDATA_RADIUS_AVP        513

static krb5_error_code
getAcceptorKey(krb5_context krbContext,
               gss_ctx_id_t ctx,
               gss_cred_id_t cred,
               krb5_principal *princ,
               krb5_keyblock *key)
{
    krb5_error_code code;
    krb5_keytab keytab = NULL;
    krb5_keytab_entry ktent;
    krb5_kt_cursor cursor = NULL;

    *princ = NULL;
    memset(key, 0, sizeof(*key));
    memset(&ktent, 0, sizeof(ktent));

    code = krb5_kt_default(krbContext, &keytab);
    if (code != 0)
        goto cleanup;

    if (cred != GSS_C_NO_CREDENTIAL && cred->name != GSS_C_NO_NAME) {
        code = krb5_kt_get_entry(krbContext, keytab,
                                 cred->name->krbPrincipal, 0, 
                                 ctx->encryptionType, &ktent);
        if (code != 0)
            goto cleanup;
    } else {
        code = krb5_kt_start_seq_get(krbContext, keytab, &cursor);
        if (code != 0)
            goto cleanup;

        while ((code = krb5_kt_next_entry(krbContext, keytab,
                                          &ktent, &cursor)) == 0) {
            if (ktent.key.enctype != ctx->encryptionType) {
                krb5_free_keytab_entry_contents(krbContext, &ktent);
                continue;
            }
        }
    }

    code = krb5_copy_principal(krbContext, ktent.principal, princ);
    if (code != 0)
        goto cleanup;

    code = krb5_copy_keyblock_contents(krbContext, &ktent.key, key);
    if (code != 0)
        goto cleanup;

cleanup:
    if (cred == GSS_C_NO_CREDENTIAL || cred->name == GSS_C_NO_NAME)
        krb5_kt_end_seq_get(krbContext, keytab, &cursor);

    krb5_free_keytab_entry_contents(krbContext, &ktent);
    krb5_kt_end_seq_get(krbContext, keytab, &cursor);
    krb5_kt_close(krbContext, keytab);

    if (code != 0) {
        if (*princ != NULL) {
            krb5_free_principal(krbContext, *princ);
            *princ = NULL;
        }
        krb5_free_keyblock_contents(krbContext, key),
        memset(key, 0, sizeof(key));
    }

    return code; 
}

static OM_uint32
makeReauthCreds(OM_uint32 *minor,
                gss_ctx_id_t ctx,
                gss_cred_id_t cred,
                gss_buffer_t credBuf)
{
    OM_uint32 major = GSS_S_COMPLETE, code;
    krb5_context krbContext = NULL;
    krb5_ticket ticket = { 0 };
    krb5_keyblock session, acceptorKey = { 0 };
    krb5_enc_tkt_part enc_part = { 0 };
    gss_buffer_desc attrBuf = GSS_C_EMPTY_BUFFER;
    krb5_authdata *authData[2], authDatum = { 0 };
    krb5_data *ticketData = NULL, *credsData = NULL;
    krb5_creds creds = { 0 };
    krb5_auth_context authContext = NULL;
 
    credBuf->length = 0;
    credBuf->value = NULL;
 
    GSSEAP_KRB_INIT(&krbContext);

    code = getAcceptorKey(krbContext, ctx, cred,
                          &ticket.server, &acceptorKey);
    if (code != 0)
        goto cleanup;

    enc_part.flags = TKT_FLG_INITIAL;

    code = krb5_c_make_random_key(krbContext, ctx->encryptionType,
                                  &session);
    if (code != 0)
        goto cleanup;

    enc_part.session = &session;
    enc_part.client = ctx->initiatorName->krbPrincipal;
    enc_part.times.authtime = time(NULL);
    enc_part.times.starttime = enc_part.times.authtime;
    enc_part.times.endtime = ctx->expiryTime
                             ? ctx->expiryTime
                             : KRB5_INT32_MAX;
    enc_part.times.renew_till = 0;

    major = gssEapExportAttrContext(minor, ctx->initiatorName,
                                    &attrBuf);
    if (GSS_ERROR(major))
        goto cleanup;

    authDatum.ad_type = KRB5_AUTHDATA_RADIUS_AVP;
    authDatum.length = attrBuf.length;
    authDatum.contents = attrBuf.value;
    authData[0] = &authDatum;
    authData[1] = NULL;
    enc_part.authorization_data = authData;

    ticket.enc_part2 = &enc_part;

    code = encode_krb5_ticket(&ticket, &ticketData);
    if (code != 0)
        goto cleanup;

    creds.client = enc_part.client;
    creds.server = ticket.server;
    creds.keyblock = session;
    creds.times = enc_part.times;
    creds.ticket_flags = enc_part.flags;
    creds.ticket = *ticketData;
    creds.authdata = authData;

    code = krb5_auth_con_init(krbContext, &authContext);
    if (code != 0)
        goto cleanup;

    code = krb5_auth_con_setsendsubkey(krbContext, authContext, &ctx->rfc3961Key);
    if (code != 0)
        goto cleanup;

    code = krb5_mk_1cred(krbContext, authContext, &creds, &credsData, NULL);
    if (code != 0)
        goto cleanup;

    krbDataToGssBuffer(credsData, credBuf);

    code = krb5_encrypt_tkt_part(krbContext, acceptorKey, &ticket);
    if (code != 0)
        goto cleanup;

cleanup:
    *minor = code;

    if (ticket.enc_part.ciphertext.data != NULL)
        GSSEAP_FREE(ticket.enc_part.ciphertext.data);

    krb5_free_keyblock_contents(krbContext, &session);
    krb5_free_keyblock_contents(krbContext, &acceptorKey);
    gss_release_buffer(&code, &attrBuf);
    krb5_free_data(krbContext, ticketData);
    krb5_auth_con_free(krbContext, authContext);
    if (credsData != NULL)
        GSSEAP_FREE(credsData);

    if (major == GSS_S_COMPLETE)
        major = *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;

    return major;
}

static OM_uint32
storeReauthCreds(OM_uint32 *minor,
                 gss_ctx_id_t ctx,
                 gss_cred_id_t cred,
                 gss_buffer_t credBuf)
{
    OM_uint32 major = GSS_S_COMPLETE, code;
    krb5_context krbContext = NULL;
    krb5_auth_context authContext = NULL;
    krb5_data credData = { 0 };
    krb5_creds **creds = NULL;
    int i;

    if (credBuf->length == 0 || cred == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;

    GSSEAP_KRB_INIT(&krbContext);

    code = krb5_auth_con_init(krbContext, &authContext);
    if (code != 0)
        goto cleanup;

    code = krb5_auth_con_setrecvsubkey(krbContext, authContext,
                                       &ctx->rfc3961Key);
    if (code != 0)
        goto cleanup;

    gssBufferToKrbData(credBuf, &credData);

    code = krb5_rd_cred(krbContext, authContext, &credData, &creds, NULL);
    if (code != 0)
        goto cleanup;



/*
OM_uint32 KRB5_CALLCONV
gss_krb5_import_cred(OM_uint32 *minor_status,
                     krb5_ccache id,
                     krb5_principal keytab_principal,
                     krb5_keytab keytab,
                     gss_cred_id_t *cred);
*/

    if (creds != NULL && creds[0] != NULL) {
    }    

cleanup:
    *minor = code;

    krb5_auth_con_free(krbContext, authContext);
    if (creds != NULL) {
        for (i = 0; creds[i] != NULL; i++)
            krb5_free_creds(krbContext, creds[i]);
    }
    if (major == GSS_S_COMPLETE)
        major = *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;

    return major;
}
