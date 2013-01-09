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
 * General mechanism utility routines.
 */

#include "gssapiP_bid.h"

/*
 * OIDs are taken from 1.3.6.1.4.1.5322(padl)
 *      gssBrowserID(24)
 *       apiExtensions(3)
 *        inquireSecContextByOid(1)
 *        inquireCredByOid(2)
 *        setSecContextOption(3)
 *        setCredOption(4)
 *        mechInvoke(5)
 */

/*
 * Note: the enctype-less OID is used as the mechanism OID in non-
 * canonicalized exported names.
 */
static gss_OID_desc gssBidMechOids[] = {
    /* 1.3.6.1.4.1.5322.24.1  */
    { 9, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x01" },
    /* 1.3.6.1.4.1.5322.24.1.0 (ENCTYPE_NULL) */
    { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x01\x00" },
    /* 1.3.6.1.4.1.5322.24.1.17 */
    { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x01\x11" },
    /* 1.3.6.1.4.1.5322.24.1.18 */
    { 10, "\x2B\x06\x01\x04\x01\xA9\x4A\x18\x01\x12" }
};

gss_OID GSS_BROWSERID_MECHANISM                            = &gssBidMechOids[0];
gss_OID GSS_BROWSERID_NONE_MECHANISM                       = &gssBidMechOids[1];
gss_OID GSS_BROWSERID_AES128_CTS_HMAC_SHA1_96_MECHANISM    = &gssBidMechOids[2];
gss_OID GSS_BROWSERID_AES256_CTS_HMAC_SHA1_96_MECHANISM    = &gssBidMechOids[3];

static int
internalizeOid(const gss_OID oid,
               gss_OID *const pInternalizedOid);

/*
 * Returns TRUE is the OID is a concrete mechanism OID, that is, one
 * with a Kerberos enctype as the last element.
 */
int
gssBidIsConcreteMechanismOid(const gss_OID oid)
{
    return oid->length > GSS_BROWSERID_MECHANISM->length &&
           memcmp(oid->elements, GSS_BROWSERID_MECHANISM->elements,
                  GSS_BROWSERID_MECHANISM->length) == 0;
}

int
gssBidIsMechanismOid(const gss_OID oid)
{
    return oid == GSS_C_NO_OID ||
           oidEqual(oid, GSS_BROWSERID_MECHANISM) ||
           gssBidIsConcreteMechanismOid(oid);
}

/*
 * Validate that all elements are concrete mechanism OIDs.
 */
OM_uint32
gssBidValidateMechs(OM_uint32 *minor,
                    const gss_OID_set mechs)
{
    int i;

    *minor = 0;

    if (mechs == GSS_C_NO_OID_SET) {
        return GSS_S_COMPLETE;
    }

    for (i = 0; i < mechs->count; i++) {
        gss_OID oid = &mechs->elements[i];

        if (!gssBidIsConcreteMechanismOid(oid)) {
            *minor = GSSBID_WRONG_MECH;
            return GSS_S_BAD_MECH;
        }
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssBidOidToEnctype(OM_uint32 *minor,
                   const gss_OID oid,
                   krb5_enctype *enctype)
{
    OM_uint32 major;
    int suffix;

    major = decomposeOid(minor,
                         GSS_BROWSERID_MECHANISM->elements,
                         GSS_BROWSERID_MECHANISM->length,
                         oid,
                         &suffix);
    if (major == GSS_S_COMPLETE)
        *enctype = suffix;

    return major;
}

OM_uint32
gssBidEnctypeToOid(OM_uint32 *minor,
                   krb5_enctype enctype,
                   gss_OID *pOid)
{
    OM_uint32 major;
    gss_OID oid;

    *pOid = NULL;

    oid = (gss_OID)GSSBID_MALLOC(sizeof(*oid));
    if (oid == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    oid->length = GSS_BROWSERID_MECHANISM->length + 1;
    oid->elements = GSSBID_MALLOC(oid->length);
    if (oid->elements == NULL) {
        *minor = ENOMEM;
        GSSBID_FREE(oid);
        return GSS_S_FAILURE;
    }

    major = composeOid(minor,
                       GSS_BROWSERID_MECHANISM->elements,
                       GSS_BROWSERID_MECHANISM->length,
                       enctype,
                       oid);
    if (major == GSS_S_COMPLETE) {
        internalizeOid(oid, pOid);
        *pOid = oid;
    } else {
        GSSBID_FREE(oid->elements);
        GSSBID_FREE(oid);
    }

    return major;
}

OM_uint32
gssBidIndicateMechs(OM_uint32 *minor,
                    gss_OID_set *mechs)
{
    krb5_context krbContext;
    OM_uint32 major;
    krb5_enctype *etypes;
    int i;

    GSSBID_KRB_INIT(&krbContext);

#ifdef HAVE_HEIMDAL_VERSION
    *minor = krb5_get_default_in_tkt_etypes(krbContext, KRB5_PDU_NONE, &etypes);
#else
    *minor = krb5_get_permitted_enctypes(krbContext, &etypes);
#endif
    if (*minor != 0) {
        return GSS_S_FAILURE;
    }

    major = gss_create_empty_oid_set(minor, mechs);
    if (GSS_ERROR(major)) {
        GSSBID_FREE(etypes);
        return major;
    }

    for (i = 0; etypes[i] != ENCTYPE_NULL; i++) {
        gss_OID mechOid;
#ifndef HAVE_HEIMDAL_VERSION
        OM_uint32 tmpMinor;
#endif

        /* XXX currently we aren't equipped to encode these enctypes */
        if (etypes[i] < 0 || etypes[i] > 127)
            continue;

        major = gssBidEnctypeToOid(minor, etypes[i], &mechOid);
        if (GSS_ERROR(major))
            break;

        major = gss_add_oid_set_member(minor, mechOid, mechs);
        if (GSS_ERROR(major))
            break;

#ifndef HAVE_HEIMDAL_VERSION
        gss_release_oid(&tmpMinor, &mechOid);
#endif
    }

    GSSBID_FREE(etypes);

    *minor = 0;
    return major;
}

OM_uint32
gssBidDefaultMech(OM_uint32 *minor,
                  gss_OID *oid)
{
    gss_OID_set mechs;
    OM_uint32 major, tmpMinor;

    major = gssBidIndicateMechs(minor, &mechs);
    if (GSS_ERROR(major)) {
        return major;
    }

    if (mechs->count == 0) {
        gss_release_oid_set(&tmpMinor, &mechs);
        return GSS_S_BAD_MECH;
    }

    if (!internalizeOid(&mechs->elements[0], oid)) {
        /* don't double-free if we didn't internalize it */
        mechs->elements[0].length = 0;
        mechs->elements[0].elements = NULL;
    }

    gss_release_oid_set(&tmpMinor, &mechs);

    *minor = 0;
    return GSS_S_COMPLETE;
}

static int
internalizeOid(const gss_OID oid,
               gss_OID *const pInternalizedOid)
{
    int i;

    *pInternalizedOid = GSS_C_NO_OID;

    for (i = 0;
         i < sizeof(gssBidMechOids) / sizeof(gssBidMechOids[0]);
         i++) {
        if (oidEqual(oid, &gssBidMechOids[i])) {
            *pInternalizedOid = (const gss_OID)&gssBidMechOids[i];
            break;
        }
    }

    if (*pInternalizedOid == GSS_C_NO_OID) {
        if (oidEqual(oid, GSS_BROWSERID_NT_EMAIL_OR_SPN))
            *pInternalizedOid = (const gss_OID)GSS_BROWSERID_NT_EMAIL_OR_SPN;
    }

    if (*pInternalizedOid == GSS_C_NO_OID) {
        *pInternalizedOid = oid;
        return 0;
    }

    return 1;
}

OM_uint32
gssBidReleaseOid(OM_uint32 *minor, gss_OID *oid)
{
    gss_OID internalizedOid = GSS_C_NO_OID;

    *minor = 0;

    if (internalizeOid(*oid, &internalizedOid)) {
        /* OID was internalized, so we can mark it as "freed" */
        *oid = GSS_C_NO_OID;
        return GSS_S_COMPLETE;
    }

    /* we don't know about this OID */
    return GSS_S_CONTINUE_NEEDED;
}

OM_uint32
gssBidCanonicalizeOid(OM_uint32 *minor,
                      const gss_OID oid,
                      OM_uint32 flags,
                      gss_OID *pOid)
{
    OM_uint32 major;
    int mapToNull = 0;

    major = GSS_S_COMPLETE;
    *minor = 0;
    *pOid = GSS_C_NULL_OID;

    if (oid == GSS_C_NULL_OID) {
        if ((flags & OID_FLAG_NULL_VALID) == 0) {
            *minor = GSSBID_WRONG_MECH;
            return GSS_S_BAD_MECH;
        } else if (flags & OID_FLAG_MAP_NULL_TO_DEFAULT_MECH) {
            return gssBidDefaultMech(minor, pOid);
        } else {
            mapToNull = 1;
        }
    } else if (oidEqual(oid, GSS_BROWSERID_MECHANISM)) {
        if ((flags & OID_FLAG_FAMILY_MECH_VALID) == 0) {
            *minor = GSSBID_WRONG_MECH;
            return GSS_S_BAD_MECH;
        } else if (flags & OID_FLAG_MAP_FAMILY_MECH_TO_NULL) {
            mapToNull = 1;
        }
    } else if (!gssBidIsConcreteMechanismOid(oid)) {
        *minor = GSSBID_WRONG_MECH;
        return GSS_S_BAD_MECH;
    }

    if (!mapToNull) {
        if (!internalizeOid(oid, pOid))
            major = duplicateOid(minor, oid, pOid);
    }

    return major;
}

static gss_buffer_desc gssBidSaslMechs[] = {
    { 0,                              NULL               },
    { sizeof("BROWSERID") - 1,        "BROWSERID",       },
    { sizeof("BROWSERID-AES128") - 1, "BROWSERID-AES128" },
    { sizeof("BROWSERID-AES256") - 1, "BROWSERID-AES256" },
};

gss_buffer_t
gssBidOidToSaslName(const gss_OID oid)
{
    size_t i;

    for (i = 1; i < sizeof(gssBidMechOids)/sizeof(gssBidMechOids[0]); i++) {
        if (oidEqual(&gssBidMechOids[i], oid))
            return &gssBidSaslMechs[i];
    }

    return GSS_C_NO_BUFFER;
}

gss_OID
gssBidSaslNameToOid(const gss_buffer_t name)
{
    size_t i;

    for (i = 1; i < sizeof(gssBidSaslMechs)/sizeof(gssBidSaslMechs[0]); i++) {
        if (bufferEqual(&gssBidSaslMechs[i], name))
            return &gssBidMechOids[i];
    }

    return GSS_C_NO_OID;
}

void gssBidFinalize(void) GSSBID_DESTRUCTOR;

OM_uint32
gssBidInitiatorInit(OM_uint32 *minor)
{
    initialize_bidg_error_table();
    initialize_lbid_error_table();

    *minor = 0;
    return GSS_S_COMPLETE;
}

void
gssBidFinalize(void)
{
#ifdef GSSBID_ENABLE_ACCEPTOR
    OM_uint32 minor;

    gssBidAttrProvidersFinalize(&minor);
#endif
}

#ifdef GSSBID_CONSTRUCTOR
static void gssBidInitiatorInitAssert(void) GSSBID_CONSTRUCTOR;

static void
gssBidInitiatorInitAssert(void)
{
    OM_uint32 major, minor;

    major = gssBidInitiatorInit(&minor);

    GSSBID_ASSERT(!GSS_ERROR(major));
}
#endif

