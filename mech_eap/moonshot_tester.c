/*
 * Copyright (c) 2018, JANET(UK)
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
 * GSS-EAP tester application
 * This application performs the initiator and responder part of a
 * GSS-EAP authentication.
 */

#include <stdio.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

static void display_status(char *m, OM_uint32 code, int type) {
    OM_uint32 min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        (void) gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
                                  &msg_ctx, &msg);
        printf("GSS-API error %s: %s\n", m, (char *) msg.value);
        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

static void
dumpAttribute(OM_uint32 *minor,
              gss_name_t name,
              gss_buffer_t attribute,
              int noisy)
{
    OM_uint32 major, tmp;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete = 0;
    int more = -1;
    unsigned int i;

    printf("[%.*s]\n", (int)attribute->length, (char *)attribute->value);

    while (more != 0) {
        value.value = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(minor, name, attribute, &authenticated,
                                       &complete, &value, &display_value,
                                       &more);
        if (GSS_ERROR(major)) {
            display_status("gss_get_name_attribute", major, *minor);
            break;
        }

        if (noisy) {
            if (display_value.length)
                printf("  - display: %.*s\n", (int)display_value.length, (char *)display_value.value);
            else {
                printf("  - b64value: ");
                for (i = 0; i < value.length; i++)
                    printf("%02x", ((char *)value.value)[i] & 0xFF);
                printf("\n");
            }
        }

        gss_release_buffer(&tmp, &value);
        gss_release_buffer(&tmp, &display_value);
    }
    printf("\n");
}

static OM_uint32
enumerateAttributes(OM_uint32 *minor,
                    gss_name_t name,
                    int noisy)
{
    OM_uint32 major, tmp;
    int name_is_MN;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    unsigned int i;

    major = gss_inquire_name(minor, name, &name_is_MN, &mech, &attrs);
    if (GSS_ERROR(major)) {
        display_status("gss_inquire_name", major, *minor);
        return major;
    }
    printf("Name contains %d attributes\n", (int) attrs->count);
    if (attrs != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < attrs->count; i++)
            dumpAttribute(minor, name, &attrs->elements[i], noisy);
    }

    gss_release_oid(&tmp, &mech);
    gss_release_buffer_set(&tmp, &attrs);

    return major;
}

static OM_uint32
showLocalIdentity(OM_uint32 *minor, gss_name_t name)
{
    OM_uint32 major;
    gss_buffer_desc buf, client_name;

    major = gss_display_name(minor, name, &client_name, NULL);
    if (major != GSS_S_COMPLETE) {
        display_status("displaying name", major, *minor);
        return -1;
    }
    printf("Username: %-*s\n", (int)client_name.length, (char *)client_name.value);


    major = gss_localname(minor, name, GSS_C_NO_OID, &buf);
    if (major == GSS_S_COMPLETE)
        printf("localname: %-*s\n", (int)buf.length, (char *)buf.value);
    else if (major != GSS_S_UNAVAILABLE)
        display_status("gss_localname", major, *minor);
    gss_release_buffer(minor, &buf);
    return major;
}

void makeStringBuffer(const char *string, gss_buffer_t buffer)
{
    size_t len = strlen(string);

    buffer->value = malloc(len + 1);
    memcpy(buffer->value, string, len + 1);
    buffer->length = len;
}

static gss_OID_desc gss_eap_mechanism_oid_desc = {9, (void *)"\x2b\x06\x01\x05\x05\x0f\x01\x01\x12"};

int main() {
    gss_ctx_id_t client_ctx = GSS_C_NO_CONTEXT, server_ctx = GSS_C_NO_CONTEXT;;
    OM_uint32 client_major, server_major, minor, req_flags, ret_flags;
    gss_buffer_desc server_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc client_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_cred_id_t server_creds;
    char acceptorname[1024];

    /* compute the acceptor name as test@hostname */
    strcpy(acceptorname, "test@");
    gethostname(&acceptorname[5], 1000);
    printf("Testing authentication with application: [%s]\n", acceptorname);

    /* Applications should set target_name to a real value. */
    name_buf.value = acceptorname;
    name_buf.length = strlen(name_buf.value);
    client_major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (GSS_ERROR(client_major)) {
        display_status("gss_import_name()", client_major, minor);
        goto cleanup;
    }

    req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;

    server_major = gss_acquire_cred(&minor, target_name, 0, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &server_creds, NULL, NULL);
    if (server_major != GSS_S_COMPLETE) {
        display_status("acquiring credentials", server_major, minor);
        goto cleanup;
    }

     while (1) {
        printf("Authentication roundtrip\n");
        client_major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &client_ctx, target_name,
                                            &gss_eap_mechanism_oid_desc, req_flags, 0, NULL,
                                            &server_token, NULL, &client_token, &ret_flags, NULL);

        if (GSS_ERROR(client_major)) {
            display_status("gss_init_sec_context()", client_major, GSS_C_GSS_CODE);
            display_status("gss_init_sec_context()", minor, GSS_C_MECH_CODE);
            goto cleanup;
        }

        if (client_major != GSS_S_CONTINUE_NEEDED) {
            break;
        }

        server_major = gss_accept_sec_context(&minor, &server_ctx, server_creds, &client_token,
                                              NULL, &client_name, NULL, &server_token, &ret_flags, NULL, NULL);

        if (GSS_ERROR(server_major)) {
            display_status("gss_init_sec_context()", server_major, GSS_C_GSS_CODE);
            display_status("gss_init_sec_context()", minor, GSS_C_MECH_CODE);
            goto cleanup;
        }
    }


    enumerateAttributes(&minor, client_name, TRUE);
    showLocalIdentity(&minor, client_name);

    gss_delete_sec_context(&minor, &client_ctx, GSS_C_NO_BUFFER);
    gss_delete_sec_context(&minor, &server_ctx, GSS_C_NO_BUFFER);

    return 0;
cleanup:
    printf("ERROR\n");
    return 1;
}
