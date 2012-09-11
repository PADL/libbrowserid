/*
 * Copyright (c) 2011, JANET(UK)
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

/*
 * Fast reauthentication support.
 */

#include "gssapiP_eap.h"

#include <dlfcn.h>

/*
 * Fast reauthentication support for EAP GSS.
 */

krb5_error_code
krb5_encrypt_tkt_part(krb5_context, const krb5_keyblock *, krb5_ticket *);

krb5_error_code
encode_krb5_ticket(const krb5_ticket *rep, krb5_data **code);

static OM_uint32
gssDisplayName(OM_uint32 *minor,
               gss_name_t name,
               gss_buffer_t buffer,
               gss_OID *name_type);

static OM_uint32
gssImportName(OM_uint32 *minor,
              gss_buffer_t buffer,
              gss_OID name_type,
              gss_name_t *name);

static krb5_error_code
getAcceptorKey(krb5_context krbContext,
               gss_ctx_id_t ctx,
               gss_cred_id_t cred,
               krb5_principal *princ,
               krb5_keyblock *key)
{
    krb5_error_code code;
    krb5_keytab keytab = NULL;
    krb5_keytab_entry ktent = { 0 };
    krb5_kt_cursor cursor;

    *princ = NULL;
    memset(key, 0, sizeof(*key));
    memset(&cursor, 0, sizeof(cursor));

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
        /*
         * It's not clear that looking encrypting the ticket in the
         * requested EAP enctype provides any value.
         */
        code = krb5_kt_start_seq_get(krbContext, keytab, &cursor);
        if (code != 0)
            goto cleanup;

        while ((code = krb5_kt_next_entry(krbContext, keytab,
                                          &ktent, &cursor)) == 0) {
            if (KRB_KEY_TYPE(KRB_KT_ENT_KEYBLOCK(&ktent)) == ctx->encryptionType)
                break;
            else
                KRB_KT_ENT_FREE(krbContext, &ktent);
        }
    }

    if (code == 0) {
        *princ = ktent.principal;
        *key = *KRB_KT_ENT_KEYBLOCK(&ktent);
    }

cleanup:
    if (cred == GSS_C_NO_CREDENTIAL || cred->name == GSS_C_NO_NAME)
        krb5_kt_end_seq_get(krbContext, keytab, &cursor);
    krb5_kt_close(krbContext, keytab);
    if (code != 0)
        KRB_KT_ENT_FREE(krbContext, &ktent);

    return code;
}

static OM_uint32
freezeAttrContext(OM_uint32 *minor,
                  gss_name_t initiatorName,
                  krb5_const_principal acceptorPrinc,
                  krb5_keyblock *session,
#ifdef HAVE_HEIMDAL_VERSION
                  krb5_authdata *kdcIssuedAuthData
#else
                  krb5_authdata ***kdcIssuedAuthData
#endif
                  )
{
    OM_uint32 major, tmpMinor;
    krb5_error_code code;
    krb5_context krbContext;
    gss_buffer_desc attrBuf = GSS_C_EMPTY_BUFFER;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_authdata authDataBuf, *authData = &authDataBuf;
    AuthorizationDataElement authDatum = { 0 };
#else
    krb5_authdata *authData[2], authDatum = { 0 };
#endif

    memset(kdcIssuedAuthData, 0, sizeof(*kdcIssuedAuthData));

    GSSEAP_KRB_INIT(&krbContext);

    major = gssEapExportAttrContext(minor, initiatorName, &attrBuf);
    if (GSS_ERROR(major))
        return major;

    authDatum.ad_type = KRB5_AUTHDATA_RADIUS_AVP;
#ifdef HAVE_HEIMDAL_VERSION
    authDatum.ad_data.length = attrBuf.length;
    authDatum.ad_data.data = attrBuf.value;
    authData->len = 1;
    authData->val = &authDatum;
#else
    authDatum.length = attrBuf.length;
    authDatum.contents = attrBuf.value;
    authData[0] = &authDatum;
    authData[1] = NULL;
#endif

    code = krbMakeAuthDataKdcIssued(krbContext, session, acceptorPrinc,
                                    authData, kdcIssuedAuthData);
    if (code != 0) {
        major = GSS_S_FAILURE;
        *minor = code;
    } else {
        major = GSS_S_COMPLETE;
    }

    gss_release_buffer(&tmpMinor, &attrBuf);

    return major;
}

/*
 * Fabricate a ticket to ourselves given a GSS EAP context.
 */
OM_uint32
gssEapMakeReauthCreds(OM_uint32 *minor,
                      gss_ctx_id_t ctx,
                      gss_cred_id_t cred,
                      gss_buffer_t credBuf)
{
    OM_uint32 major = GSS_S_COMPLETE;
    krb5_error_code code;
    krb5_context krbContext = NULL;
    krb5_keyblock session = { 0 }, acceptorKey = { 0 };
    krb5_principal server = NULL;
#ifdef HAVE_HEIMDAL_VERSION
    Ticket ticket;
    EncTicketPart enc_part;
    AuthorizationData authData = { 0 };
    krb5_crypto krbCrypto = NULL;
    krb5_data ticketData = { 0 };
    krb5_data encPartData = { 0 };
    size_t len;
#else
    krb5_ticket ticket;
    krb5_enc_tkt_part enc_part;
    krb5_data *ticketData = NULL;
#endif
    krb5_data credsData = { 0 };
    krb5_creds creds = { 0 };
    krb5_auth_context authContext = NULL;

    memset(&ticket, 0, sizeof(ticket));
    memset(&enc_part, 0, sizeof(enc_part));

    credBuf->length = 0;
    credBuf->value = NULL;

    GSSEAP_KRB_INIT(&krbContext);

    code = getAcceptorKey(krbContext, ctx, cred, &server, &acceptorKey);
    if (code != 0) {
        *minor = code;
        return GSS_S_UNAVAILABLE;
    }

    /*
     * Generate a random session key to place in the ticket and
     * sign the "KDC-Issued" authorization data element.
     */
#ifdef HAVE_HEIMDAL_VERSION
    ticket.realm = server->realm;
    ticket.sname = server->name;

    code = krb5_generate_random_keyblock(krbContext, ctx->encryptionType,
                                         &session);
    if (code != 0)
        goto cleanup;

    enc_part.flags.initial = 1;
    enc_part.key = session;
    enc_part.crealm = ctx->initiatorName->krbPrincipal->realm;
    enc_part.cname = ctx->initiatorName->krbPrincipal->name;
    enc_part.authtime = time(NULL);
    enc_part.starttime = &enc_part.authtime;
    enc_part.endtime = (ctx->expiryTime != 0)
                       ? ctx->expiryTime : KRB_TIME_FOREVER;
    enc_part.renew_till = NULL;
    enc_part.authorization_data = &authData;

    major = freezeAttrContext(minor, ctx->initiatorName, server,
                              &session, &authData);
    if (GSS_ERROR(major))
        goto cleanup;

    ASN1_MALLOC_ENCODE(EncTicketPart, encPartData.data, encPartData.length,
                       &enc_part, &len, code);
    if (code != 0)
        goto cleanup;

    code = krb5_crypto_init(krbContext, &acceptorKey, 0, &krbCrypto);
    if (code != 0)
        goto cleanup;

    code = krb5_encrypt_EncryptedData(krbContext,
                                      krbCrypto,
                                      KRB5_KU_TICKET,
                                      encPartData.data,
                                      encPartData.length,
                                      0,
                                      &ticket.enc_part);
    if (code != 0)
        goto cleanup;

    ASN1_MALLOC_ENCODE(Ticket, ticketData.data, ticketData.length,
                       &ticket, &len, code);
    if (code != 0)
        goto cleanup;
#else
    ticket.server = server;

    code = krb5_c_make_random_key(krbContext, ctx->encryptionType,
                                  &session);
    if (code != 0)
        goto cleanup;

    enc_part.flags = TKT_FLG_INITIAL;
    enc_part.session = &session;
    enc_part.client = ctx->initiatorName->krbPrincipal;
    enc_part.times.authtime = time(NULL);
    enc_part.times.starttime = enc_part.times.authtime;
    enc_part.times.endtime = (ctx->expiryTime != 0)
                             ? ctx->expiryTime
                             : KRB_TIME_FOREVER;
    enc_part.times.renew_till = 0;

    major = freezeAttrContext(minor, ctx->initiatorName, server,
                              &session, &enc_part.authorization_data);
    if (GSS_ERROR(major))
        goto cleanup;

    ticket.enc_part2 = &enc_part;

    code = krb5_encrypt_tkt_part(krbContext, &acceptorKey, &ticket);
    if (code != 0)
        goto cleanup;

    code = encode_krb5_ticket(&ticket, &ticketData);
    if (code != 0)
        goto cleanup;
#endif /* HAVE_HEIMDAL_VERSION */

    creds.client = ctx->initiatorName->krbPrincipal;
    creds.server = server;
#ifdef HAVE_HEIMDAL_VERSION
    creds.session = session;
    creds.times.authtime = enc_part.authtime;
    creds.times.starttime = *enc_part.starttime;
    creds.times.endtime = enc_part.endtime;
    creds.times.renew_till = 0;
    creds.flags.b = enc_part.flags;
    creds.ticket = ticketData;
    creds.authdata = authData;
#else
    creds.keyblock = session;
    creds.times = enc_part.times;
    creds.ticket_flags = enc_part.flags;
    creds.ticket = *ticketData;
    creds.authdata = enc_part.authorization_data;
#endif

    code = krb5_auth_con_init(krbContext, &authContext);
    if (code != 0)
        goto cleanup;

    code = krb5_auth_con_setflags(krbContext, authContext, 0);
    if (code != 0)
        goto cleanup;

#ifdef HAVE_HEIMDAL_VERSION
    code = krb5_auth_con_setlocalsubkey(krbContext, authContext,
                                        &ctx->rfc3961Key);
#else
    code = krb5_auth_con_setsendsubkey(krbContext, authContext,
                                       &ctx->rfc3961Key);
#endif
    if (code != 0)
        goto cleanup;

    code = krbMakeCred(krbContext, authContext, &creds, &credsData);
    if (code != 0)
        goto cleanup;

    krbDataToGssBuffer(&credsData, credBuf);

cleanup:
#ifdef HAVE_HEIMDAL_VERSION
    if (krbCrypto != NULL)
        krb5_crypto_destroy(krbContext, krbCrypto);
    free_AuthorizationData(&authData);
    free_EncryptedData(&ticket.enc_part);
    krb5_data_free(&ticketData);
    krb5_data_free(&encPartData);
#else
    krb5_free_authdata(krbContext, enc_part.authorization_data);
    if (ticket.enc_part.ciphertext.data != NULL)
        GSSEAP_FREE(ticket.enc_part.ciphertext.data);
    krb5_free_data(krbContext, ticketData);
#endif
    krb5_free_keyblock_contents(krbContext, &session);
    krb5_free_principal(krbContext, server);
    krb5_free_keyblock_contents(krbContext, &acceptorKey);
    krb5_auth_con_free(krbContext, authContext);

    if (major == GSS_S_COMPLETE) {
        *minor = code;
        major = (code != 0) ? GSS_S_FAILURE : GSS_S_COMPLETE;
    }

    return major;
}

static int
isTicketGrantingServiceP(krb5_context krbContext GSSEAP_UNUSED,
                         krb5_const_principal principal)
{
    if (KRB_PRINC_LENGTH(principal) == 2 &&
#ifdef HAVE_HEIMDAL_VERSION
        strcmp(KRB_PRINC_NAME(principal)[0], "krbtgt") == 0
#else
        krb5_princ_component(krbContext, principal, 0)->length == 6 &&
        memcmp(krb5_princ_component(krbContext,
                                    principal, 0)->data, "krbtgt", 6) == 0
#endif
        )
        return TRUE;

    return FALSE;
}

/*
 * Returns TRUE if the configuration variable reauth_use_ccache is
 * set in krb5.conf for the eap_gss application and the client realm.
 */
static int
reauthUseCredsCache(krb5_context krbContext,
                    krb5_principal principal)
{
    int reauthUseCCache;

    /* if reauth_use_ccache, use default credentials cache if ticket is for us */
    krb5_appdefault_boolean(krbContext, "eap_gss",
                            KRB_PRINC_REALM(principal),
                            "reauth_use_ccache", 0, &reauthUseCCache);

    return reauthUseCCache;
}

/*
 * Look in default credentials cache for reauthentication credentials,
 * if policy allows.
 */
static OM_uint32
getDefaultReauthCredentials(OM_uint32 *minor,
                            gss_cred_id_t cred,
                            gss_name_t target,
                            time_t now,
                            OM_uint32 timeReq)
{
    OM_uint32 major = GSS_S_CRED_UNAVAIL;
    krb5_context krbContext = NULL;
    krb5_error_code code = 0;
    krb5_ccache ccache = NULL;
    krb5_creds match = { 0 };
    krb5_creds creds = { 0 };

    GSSEAP_KRB_INIT(&krbContext);

    GSSEAP_ASSERT(cred != GSS_C_NO_CREDENTIAL);
    GSSEAP_ASSERT(target != GSS_C_NO_NAME);

    if (cred->name == GSS_C_NO_NAME ||
        !reauthUseCredsCache(krbContext, cred->name->krbPrincipal))
        goto cleanup;

    match.client = cred->name->krbPrincipal;
    match.server = target->krbPrincipal;
    if (timeReq != 0 && timeReq != GSS_C_INDEFINITE)
        match.times.endtime = now + timeReq;

    code = krb5_cc_default(krbContext, &ccache);
    if (code != 0)
        goto cleanup;

    code = krb5_cc_retrieve_cred(krbContext, ccache, 0, &match, &creds);
    if (code != 0)
        goto cleanup;

    cred->flags |= CRED_FLAG_DEFAULT_CCACHE;
    cred->krbCredCache = ccache;
    ccache = NULL;

    major = gss_krb5_import_cred(minor, cred->krbCredCache, NULL, NULL,
                                 &cred->reauthCred);

cleanup:
    if (major == GSS_S_CRED_UNAVAIL)
        *minor = code;

    if (ccache != NULL)
        krb5_cc_close(krbContext, ccache);
    krb5_free_cred_contents(krbContext, &creds);

    return major;
}

/*
 * Returns TRUE if the credential handle's reauth credentials are
 * valid or if we can use the default credentials cache. Credentials
 * handle must be locked.
 */
int
gssEapCanReauthP(gss_cred_id_t cred,
                 gss_name_t target,
                 OM_uint32 timeReq)
{
    time_t now, expiryReq;
    OM_uint32 minor;

    if (cred == GSS_C_NO_CREDENTIAL)
        return FALSE;

    now = time(NULL);
    expiryReq = now;
    if (timeReq != GSS_C_INDEFINITE)
        expiryReq += timeReq;

    if (cred->krbCredCache != NULL && cred->expiryTime > expiryReq)
        return TRUE;

    if (getDefaultReauthCredentials(&minor, cred, target,
                                    now, timeReq) == GSS_S_COMPLETE)
        return TRUE;

    return FALSE;
}

/*
 * Store re-authentication (Kerberos) credentials in a credential handle.
 * Credentials handle must be locked.
 */
OM_uint32
gssEapStoreReauthCreds(OM_uint32 *minor,
                       gss_ctx_id_t ctx,
                       gss_cred_id_t cred,
                       gss_buffer_t credBuf)
{
    OM_uint32 major = GSS_S_COMPLETE;
    krb5_error_code code;
    krb5_context krbContext = NULL;
    krb5_auth_context authContext = NULL;
    krb5_data credData = { 0 };
    krb5_creds **creds = NULL;
    krb5_principal canonPrinc;
    krb5_principal ccPrinc = NULL;
    int i;

    if (credBuf->length == 0 || cred == GSS_C_NO_CREDENTIAL)
        return GSS_S_COMPLETE;

    GSSEAP_KRB_INIT(&krbContext);

    code = krb5_auth_con_init(krbContext, &authContext);
    if (code != 0)
        goto cleanup;

    code = krb5_auth_con_setflags(krbContext, authContext, 0);
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

    if (creds == NULL || creds[0] == NULL)
        goto cleanup;

    code = krb5_copy_principal(krbContext, creds[0]->client, &canonPrinc);
    if (code != 0)
        goto cleanup;

    krb5_free_principal(krbContext, cred->name->krbPrincipal);
    cred->name->krbPrincipal = canonPrinc;

    if (creds[0]->times.endtime == KRB_TIME_FOREVER)
        cred->expiryTime = 0;
    else
        cred->expiryTime = creds[0]->times.endtime;

    if (cred->krbCredCache == NULL) {
        if (reauthUseCredsCache(krbContext, creds[0]->client) &&
            krb5_cc_default(krbContext, &cred->krbCredCache) == 0)
            cred->flags |= CRED_FLAG_DEFAULT_CCACHE;
    } else {
        /*
         * If we already have an associated credentials cache, possibly from
         * the last time we stored a reauthentication credential, then we
         * need to clear it out and release the associated GSS credential.
         */
        if (cred->flags & CRED_FLAG_DEFAULT_CCACHE) {
            krb5_cc_remove_cred(krbContext, cred->krbCredCache, 0, creds[0]);
        } else {
            krb5_cc_destroy(krbContext, cred->krbCredCache);
            cred->krbCredCache = NULL;
        }
        gssReleaseCred(minor, &cred->reauthCred);
    }

    if (cred->krbCredCache == NULL) {
        code = krb5_cc_new_unique(krbContext, "MEMORY", NULL, &cred->krbCredCache);
        if (code != 0)
            goto cleanup;
    }

    if ((cred->flags & CRED_FLAG_DEFAULT_CCACHE) == 0 ||
        krb5_cc_get_principal(krbContext, cred->krbCredCache, &ccPrinc) != 0) {
        code = krb5_cc_initialize(krbContext, cred->krbCredCache,
                                  creds[0]->client);
        if (code != 0)
            goto cleanup;
    }

    for (i = 0; creds[i] != NULL; i++) {
        krb5_creds kcred = *(creds[i]);

        /*
         * Swap in the acceptor name the client asked for so
         * get_credentials() works. We're making the assumption that
         * any service tickets returned are for us. We'll need to
         * reflect some more on whether that is a safe assumption.
         */
        if (!isTicketGrantingServiceP(krbContext, kcred.server))
            kcred.server = ctx->acceptorName->krbPrincipal;

        code = krb5_cc_store_cred(krbContext, cred->krbCredCache, &kcred);
        if (code != 0)
            goto cleanup;
    }

    major = gss_krb5_import_cred(minor, cred->krbCredCache, NULL, NULL,
                                 &cred->reauthCred);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    *minor = code;

    krb5_free_principal(krbContext, ccPrinc);
    krb5_auth_con_free(krbContext, authContext);
    if (creds != NULL) {
        for (i = 0; creds[i] != NULL; i++)
            krb5_free_creds(krbContext, creds[i]);
        GSSEAP_FREE(creds);
    }
    if (major == GSS_S_COMPLETE)
        major = *minor ? GSS_S_FAILURE : GSS_S_COMPLETE;

    return major;
}

#ifndef HAVE_HEIMDAL_VERSION
static gss_buffer_desc radiusAvpKrbAttr = {
    sizeof("urn:authdata-aaa-radius") - 1, "urn:authdata-aaa-radius"
};
#endif

/*
 * Unfortunately extracting an AD-KDCIssued authorization data element
 * is pretty implementation-dependent. It's not possible to verify the
 * signature ourselves because the ticket session key is not exposed
 * outside GSS. In an ideal world, all AD-KDCIssued elements would be
 * verified by the Kerberos library and authentication would fail if
 * verification failed. We're not quite there yet and as a result have
 * to go through some hoops to get this to work. The alternative would
 * be to sign the authorization data with our long-term key, but it
 * seems a pity to compromise the design because of current implementation
 * limitations.
 *
 * (Specifically, the hoops involve a libkrb5 authorisation data plugin
 * that exposes the verified and serialised attribute context through
 * the Kerberos GSS mechanism's naming extensions API.)
 */
static OM_uint32
defrostAttrContext(OM_uint32 *minor,
#ifdef HAVE_HEIMDAL_VERSION
                   gss_ctx_id_t glueContext,
#else
                   gss_name_t glueName,
#endif
                   gss_name_t mechName)
{
    OM_uint32 major, tmpMinor;
#ifdef HAVE_HEIMDAL_VERSION
    gss_OID_desc oid = { 0 };
    gss_buffer_set_t authData = GSS_C_NO_BUFFER_SET;
#else
    gss_buffer_desc authData = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc authDataDisplay = GSS_C_EMPTY_BUFFER;
    int more = -1;
    int authenticated, complete;
#endif

#ifdef HAVE_HEIMDAL_VERSION
    major = composeOid(minor,
                       GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_X->elements,
                       GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_X->length,
                       KRB5_AUTHDATA_RADIUS_AVP, &oid);
    if (GSS_ERROR(major))
        return major;

    /* XXX we are assuming that this verifies AD-KDCIssued signature */
    major = gssInquireSecContextByOid(minor, glueContext,
                                      &oid, &authData);
    if (major == GSS_S_COMPLETE) {
        if (authData == GSS_C_NO_BUFFER_SET || authData->count != 1)
            major = GSS_S_FAILURE;
        else
            major = gssEapImportAttrContext(minor, authData->elements, mechName);
    } else if (major == GSS_S_FAILURE && *minor == ENOENT) {
        /* This is the equivalent of GSS_S_UNAVAILABLE for MIT attr APIs */
        *minor = 0;
        major = GSS_S_COMPLETE;
    }

    gss_release_buffer_set(&tmpMinor, &authData);
    GSSEAP_FREE(oid.elements);
#else
    major = gssGetNameAttribute(minor, glueName, &radiusAvpKrbAttr,
                                &authenticated, &complete,
                                &authData, &authDataDisplay, &more);
    if (major == GSS_S_COMPLETE) {
        if (authenticated == 0)
            major = GSS_S_BAD_NAME;
        else
            major = gssEapImportAttrContext(minor, &authData, mechName);
    } else if (major == GSS_S_UNAVAILABLE) {
        major = GSS_S_COMPLETE;
    }

    gss_release_buffer(&tmpMinor, &authData);
    gss_release_buffer(&tmpMinor, &authDataDisplay);
#endif /* HAVE_HEIMDAL_VERSION */

    return major;
}

/*
 * Convert a mechanism glue to an EAP mechanism name by displaying and
 * importing it. This also handles the RADIUS attributes.
 */
OM_uint32
gssEapGlueToMechName(OM_uint32 *minor,
                     gss_ctx_id_t ctx,
                     gss_name_t glueName,
                     gss_name_t *pMechName)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;

    *pMechName = GSS_C_NO_NAME;

    major = gssDisplayName(minor, glueName, &nameBuf, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssEapImportName(minor, &nameBuf, GSS_C_NT_USER_NAME,
                             ctx->mechanismUsed, pMechName);
    if (GSS_ERROR(major))
        goto cleanup;

    major = defrostAttrContext(minor,
#ifdef HAVE_HEIMDAL_VERSION
                               ctx->reauthCtx,
#else
                               glueName,
#endif
                               *pMechName);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    if (GSS_ERROR(major)) {
        gssReleaseName(&tmpMinor, pMechName);
        *pMechName = GSS_C_NO_NAME;
    }

    gss_release_buffer(&tmpMinor, &nameBuf);

    return major;
}

/*
 * Convert an EAP mechanism name to a mechanism glue name by displaying
 * and importing it.
 */
OM_uint32
gssEapMechToGlueName(OM_uint32 *minor,
                     gss_name_t mechName,
                     gss_name_t *pGlueName)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_desc nameBuf = GSS_C_EMPTY_BUFFER;

    *pGlueName = GSS_C_NO_NAME;

    major = gssEapDisplayName(minor, mechName, &nameBuf, NULL);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gssImportName(minor, &nameBuf, GSS_C_NT_USER_NAME,
                          pGlueName);
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    gss_release_buffer(&tmpMinor, &nameBuf);

    return major;
}

/*
 * Suck out the analgous elements of a Kerberos GSS context into an EAP
 * one so that the application doesn't know the difference.
 */
OM_uint32
gssEapReauthComplete(OM_uint32 *minor,
                     gss_ctx_id_t ctx,
                     gss_cred_id_t cred GSSEAP_UNUSED,
                     const gss_OID mech,
                     OM_uint32 timeRec)
{
    OM_uint32 major, tmpMinor;
    gss_buffer_set_t keyData = GSS_C_NO_BUFFER_SET;
    krb5_context krbContext = NULL;
#ifdef HAVE_HEIMDAL_VERSION
    krb5_storage *sp = NULL;
#endif

    GSSEAP_KRB_INIT(&krbContext);

    if (!oidEqual(mech, gss_mech_krb5)) {
        major = GSS_S_BAD_MECH;
        goto cleanup;
    }

    /* Get the raw subsession key and encryption type */
#ifdef HAVE_HEIMDAL_VERSION
#define KRB_GSS_SUBKEY_COUNT    1 /* encoded session key */
    major = gssInquireSecContextByOid(minor, ctx->reauthCtx,
                                      GSS_KRB5_GET_SUBKEY_X, &keyData);
#else
#define KRB_GSS_SUBKEY_COUNT    2 /* raw session key, enctype OID */
    major = gssInquireSecContextByOid(minor, ctx->reauthCtx,
                                      GSS_C_INQ_SSPI_SESSION_KEY, &keyData);
#endif
    if (GSS_ERROR(major))
        goto cleanup;

    if (keyData == GSS_C_NO_BUFFER_SET || keyData->count < KRB_GSS_SUBKEY_COUNT) {
        *minor = GSSEAP_KEY_UNAVAILABLE;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

#ifdef HAVE_HEIMDAL_VERSION
    sp = krb5_storage_from_mem(keyData->elements[0].value,
                               keyData->elements[0].length);
    if (sp == NULL) {
        *minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto cleanup;
    }

    *minor = krb5_ret_keyblock(sp, &ctx->rfc3961Key);
    if (*minor != 0) {
        major = GSS_S_FAILURE;
        goto cleanup;
    }
#else
    {
        gss_OID_desc oid;
        int suffix;

        oid.length = keyData->elements[1].length;
        oid.elements = keyData->elements[1].value;

        /* GSS_KRB5_SESSION_KEY_ENCTYPE_OID */
        major = decomposeOid(minor,
                             "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04",
                             10, &oid, &suffix);
        if (GSS_ERROR(major))
            goto cleanup;

        ctx->encryptionType = suffix;
    }

    {
        krb5_keyblock key;

        KRB_KEY_LENGTH(&key) = keyData->elements[0].length;
        KRB_KEY_DATA(&key)   = keyData->elements[0].value;
        KRB_KEY_TYPE(&key)   = ctx->encryptionType;

        *minor = krb5_copy_keyblock_contents(krbContext,
                                             &key, &ctx->rfc3961Key);
        if (*minor != 0) {
            major = GSS_S_FAILURE;
            goto cleanup;
        }
    }
#endif /* HAVE_HEIMDAL_VERSION */

    major = rfc3961ChecksumTypeForKey(minor, &ctx->rfc3961Key,
                                      &ctx->checksumType);
    if (GSS_ERROR(major))
        goto cleanup;

    if (timeRec != GSS_C_INDEFINITE)
        ctx->expiryTime = time(NULL) + timeRec;

    /* Initialize our sequence state */
    major = sequenceInit(minor,
                         &ctx->seqState, ctx->recvSeq,
                         ((ctx->gssFlags & GSS_C_REPLAY_FLAG) != 0),
                         ((ctx->gssFlags & GSS_C_SEQUENCE_FLAG) != 0),
                         TRUE);
    if (GSS_ERROR(major))
        goto cleanup;

    major = GSS_S_COMPLETE;

cleanup:
#ifdef HAVE_HEIMDAL_VERSION
    if (sp != NULL)
        krb5_storage_free(sp);
#endif
    gss_release_buffer_set(&tmpMinor, &keyData);

    return major;
}

/*
 * The remainder of this file consists of wrappers so we can call into the
 * mechanism glue without calling ourselves.
 */
static OM_uint32
(*gssInitSecContextNext)(OM_uint32 *,
                         gss_cred_id_t,
                         gss_ctx_id_t *,
                         gss_name_t,
                         gss_OID,
                         OM_uint32,
                         OM_uint32,
                         gss_channel_bindings_t,
                         gss_buffer_t,
                         gss_OID *,
                         gss_buffer_t,
                         OM_uint32 *,
                         OM_uint32 *);

static OM_uint32
(*gssAcceptSecContextNext)(OM_uint32 *,
                           gss_ctx_id_t *,
                           gss_cred_id_t,
                           gss_buffer_t,
                           gss_channel_bindings_t,
                           gss_name_t *,
                           gss_OID *,
                           gss_buffer_t,
                           OM_uint32 *,
                           OM_uint32 *,
                           gss_cred_id_t *);

static OM_uint32
(*gssReleaseCredNext)(OM_uint32 *, gss_cred_id_t *);

static OM_uint32
(*gssReleaseNameNext)(OM_uint32 *, gss_name_t *);

static OM_uint32
(*gssInquireSecContextByOidNext)(OM_uint32 *,
                                 const gss_ctx_id_t,
                                 const gss_OID,
                                 gss_buffer_set_t *);

static OM_uint32
(*gssDeleteSecContextNext)(OM_uint32 *,
                          gss_ctx_id_t *,
                          gss_buffer_t);

static OM_uint32
(*gssDisplayNameNext)(OM_uint32 *,
                      gss_name_t,
                      gss_buffer_t,
                      gss_OID *);

static OM_uint32
(*gssImportNameNext)(OM_uint32 *,
                     gss_buffer_t,
                     gss_OID,
                     gss_name_t *);

static OM_uint32
(*gssStoreCredNext)(OM_uint32 *,
                    const gss_cred_id_t,
                    gss_cred_usage_t,
                    const gss_OID,
                    OM_uint32,
                    OM_uint32,
                    gss_OID_set *,
                    gss_cred_usage_t *);

static OM_uint32
(*gssGetNameAttributeNext)(OM_uint32 *,
                          gss_name_t,
                          gss_buffer_t,
                          int *,
                          int *,
                          gss_buffer_t,
                          gss_buffer_t,
                          int *);

#define NEXT_SYMBOL(local, global)  do {        \
        ((local) = dlsym(RTLD_NEXT, (global))); \
        if ((local) == NULL) {                  \
            *minor = GSSEAP_NO_MECHGLUE_SYMBOL; \
            major = GSS_S_UNAVAILABLE;          \
            /* but continue */                  \
        }                                       \
    } while (0)

OM_uint32
gssEapReauthInitialize(OM_uint32 *minor)
{
    OM_uint32 major = GSS_S_COMPLETE;

    NEXT_SYMBOL(gssInitSecContextNext,         "gss_init_sec_context");
    NEXT_SYMBOL(gssAcceptSecContextNext,       "gss_accept_sec_context");
    NEXT_SYMBOL(gssReleaseCredNext,            "gss_release_cred");
    NEXT_SYMBOL(gssReleaseNameNext,            "gss_release_name");
    NEXT_SYMBOL(gssInquireSecContextByOidNext, "gss_inquire_sec_context_by_oid");
    NEXT_SYMBOL(gssDeleteSecContextNext,       "gss_delete_sec_context");
    NEXT_SYMBOL(gssDisplayNameNext,            "gss_display_name");
    NEXT_SYMBOL(gssImportNameNext,             "gss_import_name");
    NEXT_SYMBOL(gssStoreCredNext,              "gss_store_cred");
#ifndef HAVE_HEIMDAL_VERSION
    NEXT_SYMBOL(gssGetNameAttributeNext,       "gss_get_name_attribute");
#endif

    return major;
}

OM_uint32
gssInitSecContext(OM_uint32 *minor,
                  gss_cred_id_t cred,
                  gss_ctx_id_t *context_handle,
                  gss_name_t target_name,
                  gss_OID mech_type,
                  OM_uint32 req_flags,
                  OM_uint32 time_req,
                  gss_channel_bindings_t input_chan_bindings,
                  gss_buffer_t input_token,
                  gss_OID *actual_mech_type,
                  gss_buffer_t output_token,
                  OM_uint32 *ret_flags,
                  OM_uint32 *time_rec)
{
    if (gssInitSecContextNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssInitSecContextNext(minor, cred, context_handle,
                                 target_name, mech_type, req_flags,
                                 time_req, input_chan_bindings,
                                 input_token, actual_mech_type,
                                 output_token, ret_flags, time_rec);
}

OM_uint32
gssAcceptSecContext(OM_uint32 *minor,
                    gss_ctx_id_t *context_handle,
                    gss_cred_id_t cred,
                    gss_buffer_t input_token,
                    gss_channel_bindings_t input_chan_bindings,
                    gss_name_t *src_name,
                    gss_OID *mech_type,
                    gss_buffer_t output_token,
                    OM_uint32 *ret_flags,
                    OM_uint32 *time_rec,
                    gss_cred_id_t *delegated_cred_handle)
{
    if (gssAcceptSecContextNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssAcceptSecContextNext(minor, context_handle, cred,
                                   input_token, input_chan_bindings,
                                   src_name, mech_type, output_token,
                                   ret_flags, time_rec, delegated_cred_handle);
}

OM_uint32
gssReleaseCred(OM_uint32 *minor,
               gss_cred_id_t *cred_handle)
{
    if (gssReleaseCredNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssReleaseCredNext(minor, cred_handle);
}

OM_uint32
gssReleaseName(OM_uint32 *minor,
               gss_name_t *name)
{
    if (gssReleaseName == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssReleaseNameNext(minor, name);
}

OM_uint32
gssDeleteSecContext(OM_uint32 *minor,
                    gss_ctx_id_t *context_handle,
                    gss_buffer_t output_token)
{
    if (gssDeleteSecContextNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssDeleteSecContextNext(minor, context_handle, output_token);
}

static OM_uint32
gssDisplayName(OM_uint32 *minor,
               gss_name_t name,
               gss_buffer_t buffer,
               gss_OID *name_type)
{
    if (gssDisplayNameNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssDisplayNameNext(minor, name, buffer, name_type);
}

static OM_uint32
gssImportName(OM_uint32 *minor,
              gss_buffer_t buffer,
              gss_OID name_type,
              gss_name_t *name)
{
    if (gssImportNameNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssImportNameNext(minor, buffer, name_type, name);
}

OM_uint32
gssInquireSecContextByOid(OM_uint32 *minor,
                          const gss_ctx_id_t context_handle,
                          const gss_OID desired_object,
                          gss_buffer_set_t *data_set)
{
    if (gssInquireSecContextByOidNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssInquireSecContextByOidNext(minor, context_handle,
                                         desired_object, data_set);
}

OM_uint32
gssStoreCred(OM_uint32 *minor,
             const gss_cred_id_t input_cred_handle,
             gss_cred_usage_t input_usage,
             const gss_OID desired_mech,
             OM_uint32 overwrite_cred,
             OM_uint32 default_cred,
             gss_OID_set *elements_stored,
             gss_cred_usage_t *cred_usage_stored)
{
    if (gssStoreCredNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssStoreCredNext(minor, input_cred_handle, input_usage,
                            desired_mech, overwrite_cred, default_cred,
                            elements_stored, cred_usage_stored);
}

OM_uint32
gssGetNameAttribute(OM_uint32 *minor,
                    gss_name_t name,
                    gss_buffer_t attr,
                    int *authenticated,
                    int *complete,
                    gss_buffer_t value,
                    gss_buffer_t display_value,
                    int *more)
{
    if (gssGetNameAttributeNext == NULL) {
        *minor = GSSEAP_NO_MECHGLUE_SYMBOL;
        return GSS_S_UNAVAILABLE;
    }

    return gssGetNameAttributeNext(minor, name, attr, authenticated, complete,
                                   value, display_value, more);
}
