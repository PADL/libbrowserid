/*
 * Copyright (C) 2004 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */


#include "gss-misc.h"

#include <Authz.h>

static int
dumpAttributes(PCtxtHandle context);

void usage(void)
{
    fprintf(stderr, "Usage: gssserver [-port port] [-verbose] [-once] [-logfile file] \n");
    fprintf(stderr, "       [-confidentiality] [-delegate] [-integrity] [-use_session_key]\n");
    fprintf(stderr, "       [-replay_detect] [-sequence_detect] [-package mech] [-pass pw]\n");
    fprintf(stderr, "       service_name service_realm\n");
    exit(1);
}

FILE *logfile;

int verbose = 0;

static char *package_name = "Negotiate";

/*
 * Function: server_acquire_creds
 *
 * Purpose: imports a service name and acquires credentials for it
 *
 * Arguments:
 *
 *      service_name    (r) the ASCII service name
 *      server_creds    (w) the GSS-API service credentials
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * The service name is imported with gss_import_name, and service
 * credentials are acquired with gss_acquire_cred.  If either opertion
 * fails, an error message is displayed and -1 is returned; otherwise,
 * 0 is returned.
 */
int server_acquire_creds(
    char *service_name,
    char *package_name,
    char *service_password,
    char *service_realm,
    CredHandle *server_creds)
{
   OM_uint32 maj_stat;
   TimeStamp expiry;
   wchar_t wide_password[100];
   wchar_t wide_realm[100];
   SEC_WINNT_AUTH_IDENTITY_W auth_identity;
   memset(&auth_identity,0,sizeof(auth_identity));

   if (service_password != NULL) {
      mbstowcs(wide_password, service_password, sizeof(wide_password) / sizeof(wchar_t));
      auth_identity.Password = wide_password;
      auth_identity.PasswordLength = (ULONG)wcslen(wide_password);
   }

   mbstowcs(wide_realm, service_realm, sizeof(wide_realm) / sizeof(wchar_t));
   auth_identity.Domain = wide_realm;
   auth_identity.DomainLength = (ULONG)wcslen(wide_realm);
   auth_identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

   maj_stat = AcquireCredentialsHandle(
                                      service_name,
                                      package_name,
                                      SECPKG_CRED_INBOUND,
                                      NULL,                       // no logon id
                                      &auth_identity,             // no auth data
                                      NULL,                       // no get key fn
                                      NULL,                       // no get key arg
                                      server_creds,
                                      &expiry
                                      );
   if (maj_stat != SEC_E_OK)
   {
      display_status("acquiring credentials", maj_stat, 0);
      return -1;
   }


   return 0;
}

OM_uint32 global_asc_flags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_MUTUAL_AUTH;

/*
 * Function: server_establish_context
 *
 * Purpose: establishses a GSS-API context as a specified service with
 * an incoming client, and returns the context handle and associated
 * client name
 *
 * Arguments:
 *
 *      s               (r) an established TCP connection to the client
 *      service_creds   (r) server credentials, from gss_acquire_cred
 *      context         (w) the established GSS-API context
 *      client_name     (w) the client's ASCII name
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * Any valid client request is accepted.  If a context is established,
 * its handle is returned in context and the client name is returned
 * in client_name and 0 is returned.  If unsuccessful, an error
 * message is displayed and -1 is returned.
 */
int server_establish_context(
    int s,
    CredHandle *server_creds,
    CtxtHandle *context,
    OM_uint32 *ret_flags)
{
   SecBufferDesc input_desc;
   SecBufferDesc output_desc;
   SecBuffer send_tok, recv_tok;
   OM_uint32 maj_stat;
   TimeStamp expiry;
   PCtxtHandle context_handle = NULL;
   int token_flags;

   context->dwUpper = 0;
   context->dwLower = 0;

   input_desc.cBuffers = 1;
   input_desc.ulVersion = SECBUFFER_VERSION;
   input_desc.pBuffers = &recv_tok;

   output_desc.cBuffers = 1;
   output_desc.ulVersion = SECBUFFER_VERSION;
   output_desc.pBuffers = &send_tok;

    if (recv_token(s, &token_flags, &recv_tok) < 0)
        return -1;

    if (recv_tok.pvBuffer) {
        free (recv_tok.pvBuffer);
        recv_tok.pvBuffer = NULL;
        recv_tok.cbBuffer = 0;
    }

    if (! (token_flags & TOKEN_NOOP)) {
        if (logfile)
            fprintf(logfile, "Expected NOOP token, got %d token instead\n",
                     token_flags);
        return -1;
    }

    if (token_flags & TOKEN_CONTEXT_NEXT) {
        do {
            if (recv_token(s, &token_flags, &recv_tok) < 0)
                return -1;

            if (verbose && logfile)
            {
                fprintf(logfile, "Received token (size=%d): \n", recv_tok.cbBuffer);
                print_token(&recv_tok);
            }

            recv_tok.BufferType = SECBUFFER_TOKEN;
            send_tok.cbBuffer = 0;
            send_tok.pvBuffer = NULL;
            send_tok.BufferType = SECBUFFER_TOKEN;
            maj_stat = AcceptSecurityContext( server_creds,
                                              context_handle,
                                              &input_desc,
                                              global_asc_flags,
                                              SECURITY_NATIVE_DREP,
                                              context,
                                              &output_desc,
                                              ret_flags,
                                              &expiry
                                              );


            if (maj_stat!=SEC_E_OK && maj_stat!=SEC_I_CONTINUE_NEEDED)
            {
                display_status("accepting context", maj_stat, 0);
                (void) free(recv_tok.pvBuffer);
                return -1;
            }

            context_handle = context;
            free(recv_tok.pvBuffer);

            if (send_tok.cbBuffer != 0)
            {
                if (verbose && logfile)
                {
                    fprintf(logfile,
                             "Sending accept_sec_context token (size=%d):\n",
                             send_tok.cbBuffer);
                    print_token(&send_tok);
                }
                if (send_token(s, TOKEN_CONTEXT, &send_tok) < 0)
                {
                    fprintf(logfile, "failure sending token\n");
                    return -1;
                }

                FreeContextBuffer(send_tok.pvBuffer);
                send_tok.pvBuffer = NULL;
            }

            if (verbose && logfile)
            {
                if (maj_stat == SEC_I_CONTINUE_NEEDED)
                    fprintf(logfile, "continue needed...\n");
                else
                    fprintf(logfile, "\n");
                fflush(logfile);
            }

        } while (maj_stat == SEC_I_CONTINUE_NEEDED);

        /* display the flags */
        display_ctx_flags(*ret_flags);

        if (logfile)
            fprintf(logfile, "Accepted connection using mechanism %s\n", package_name);
    } else {
        if (logfile)
            fprintf(logfile, "Accepted unauthenticated connection.\n");
    }
    return 0;
}

/*
 * Function: create_socket
 *
 * Purpose: Opens a listening TCP socket.
 *
 * Arguments:
 *
 *      port            (r) the port number on which to listen
 *
 * Returns: the listening socket file descriptor, or -1 on failure
 *
 * Effects:
 *
 * A listening socket on the specified port and created and returned.
 * On error, an error message is displayed and -1 is returned.
 */
int create_socket(USHORT port)
{
   struct sockaddr_in saddr;
   int s;
   int on = 1;

   saddr.sin_family = AF_INET;
   saddr.sin_port = htons(port);
   saddr.sin_addr.s_addr = INADDR_ANY;

   if ((s = (int)socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
   {
      fprintf(stderr, "creating socket - %x", GetLastError());
      return -1;
   }

   /* Let the socket be reused right away */
   (void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

   if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr)) == SOCKET_ERROR)
   {
      fprintf(stderr, "binding socket - %x", GetLastError());
      (void) closesocket(s);
      return -1;
   }

   if (listen(s, 5) == SOCKET_ERROR)
   {
      fprintf(stderr, "listening on socket", GetLastError());
      (void) closesocket(s);
      return -1;
   }
   return s;
}

/*
 * Function: sign_server
 *
 * Purpose: Performs the "sign" service.
 *
 * Arguments:
 *
 *      s               (r) a TCP socket on which a connection has been
 *                      accept()ed
 *      service_name    (r) the ASCII name of the GSS-API service to
 *                      establish a context as
 *
 * Returns: -1 on error
 *
 * Effects:
 *
 * sign_server establishes a context, and performs a single sign request.
 *
 * A sign request is a single GSS-API sealed token.  The token is
 * unsealed and a signature block, produced with gss_sign, is returned
 * to the sender.  The context is the destroyed and the connection
 * closed.
 *
 * If any error occurs, -1 is returned.
 */
int sign_server(int s, CredHandle *server_creds)
{
   SecBuffer xmit_buf, msg_buf;
   SecBuffer wrap_bufs[2];
   SecBufferDesc wrap_buf_desc;
   CtxtHandle context;
   OM_uint32 maj_stat;
   OM_uint32 ret_flags;
   int token_flags;
   char *cp;
   SecPkgContext_Names names;
   SecPkgContext_Sizes sizes = { 0 };
   ULONG qop = 0;

   /* Establish a context with the client */
   if (server_establish_context(s, server_creds, &context, &ret_flags) < 0)
      return (-1);

    if (!(context.dwUpper == 0 && context.dwLower == 0)) {
        maj_stat = QueryContextAttributes(&context, SECPKG_ATTR_NAMES, &names);
        if (maj_stat != SEC_E_OK)
        {
            display_status("Query context attributes",maj_stat, 0 );
            return ( -1 );
        }
        if ( logfile )
            fprintf(logfile, "Accepted connection: \"%s\"\n", names.sUserName);
        (void) FreeContextBuffer(names.sUserName);

        maj_stat = QueryContextAttributes(&context, SECPKG_ATTR_SIZES, &sizes);
        if (maj_stat != SEC_E_OK)
        {
            display_status("Query context attributes",maj_stat, 0 );
            return ( -1 );
        }

        dumpAttributes(&context);
    }
   
    do {
        /* Receive the sealed message token */
        if (recv_token(s, &token_flags, &xmit_buf) < 0)
            return (-1);

        if (token_flags & TOKEN_NOOP) {
            if (verbose && logfile)
                fprintf(logfile, "NOOP token\n");
            if(xmit_buf.pvBuffer) {
                free(xmit_buf.pvBuffer);
                xmit_buf.pvBuffer = 0;
                xmit_buf.cbBuffer = 0;
            }
            break;
        }

        if (verbose && logfile)
        {
            fprintf(logfile, "Sealed message token (flags=%d):", token_flags);
            if ( token_flags & TOKEN_NOOP )
                fprintf(logfile, " NOOP");
            if ( token_flags & TOKEN_CONTEXT )
                fprintf(logfile, " CONTEXT");
            if ( token_flags & TOKEN_DATA )
                fprintf(logfile, " DATA");
            if ( token_flags & TOKEN_MIC )
                fprintf(logfile, " MIC" );
            if ( token_flags & TOKEN_CONTEXT_NEXT )
                fprintf(logfile, " CONTEXT_NEXT" );
            if ( token_flags & TOKEN_WRAPPED )
                fprintf(logfile, " WRAPPED" );
            if ( token_flags & TOKEN_ENCRYPTED )
                fprintf(logfile, " ENCRYPTED" );
            if ( token_flags & TOKEN_SEND_MIC )
                fprintf(logfile, " SEND_MIC" );
            fprintf(logfile, "\n");

            print_token(&xmit_buf);
        }

        if ((context.dwUpper == 0 && context.dwLower == 0) &&
             (token_flags & (TOKEN_WRAPPED|TOKEN_ENCRYPTED|TOKEN_SEND_MIC))) {
            if (logfile)
                fprintf(logfile,
                         "Unauthenticated client requested authenticated services!\n");
            if(xmit_buf.pvBuffer) {
                free (xmit_buf.pvBuffer);
                xmit_buf.pvBuffer = 0;
                xmit_buf.cbBuffer = 0;
            }
            return(-1);
        }

        if (token_flags & TOKEN_WRAPPED) {
            wrap_buf_desc.cBuffers = 2;
            wrap_buf_desc.pBuffers = wrap_bufs;
            wrap_buf_desc.ulVersion = SECBUFFER_VERSION;
            wrap_bufs[0].BufferType = SECBUFFER_STREAM;
            wrap_bufs[0].pvBuffer = xmit_buf.pvBuffer;
            wrap_bufs[0].cbBuffer = xmit_buf.cbBuffer;
            wrap_bufs[1].BufferType = SECBUFFER_DATA;
            wrap_bufs[1].cbBuffer = 0;
            wrap_bufs[1].pvBuffer = NULL;

            maj_stat = DecryptMessage( &context,
                                       &wrap_buf_desc,
                                       0,                  // no sequence number
                                       &qop
                                       );
            if (maj_stat != SEC_E_OK)
            {
                display_status("unsealing message", maj_stat, 0);
                return (-1);
            }

            msg_buf = wrap_bufs[1];
        } else {
            msg_buf = xmit_buf;
        }

        if ( logfile ) {
            fprintf(logfile, "Received message %s: ", (qop == KERB_WRAP_NO_ENCRYPT ? "signed only" : ""));
            cp = (char *) msg_buf.pvBuffer;
            if (isprint(cp[0]) && isprint(cp[1])) {
                unsigned int i;
                fprintf(logfile,"\"");
                for ( i=0; i<msg_buf.cbBuffer; i++)
                    fprintf(logfile, "%c", cp[i]);
                fprintf(logfile,"\"\n");
            }
            else
            {
                printf("\n");
                print_token(&msg_buf);
            }
        }

        /* Produce a signature block for the message */
        if (token_flags & TOKEN_SEND_MIC) {
            wrap_bufs[0] = msg_buf;

            wrap_bufs[1].BufferType = SECBUFFER_TOKEN;
            wrap_bufs[1].cbBuffer = sizes.cbMaxSignature;
            wrap_bufs[1].pvBuffer = malloc(sizes.cbMaxSignature);

            if (wrap_bufs[1].pvBuffer == NULL)
            {
                fprintf(stderr, "Failed to allocate memory for signature\n");
                return (-1);
            }

            maj_stat = MakeSignature( &context,
                                      0,
                                      &wrap_buf_desc,
                                      0
                                      );
            if (maj_stat != SEC_E_OK)
            {
                display_status("signing message", maj_stat, 0);
                return (-1);
            }

            free(xmit_buf.pvBuffer);
            xmit_buf.pvBuffer = NULL;
            xmit_buf.cbBuffer = 0;

            xmit_buf = wrap_bufs[1];

            /* Send the signature block to the client */
            if (send_token(s, TOKEN_MIC, &xmit_buf) < 0)
                return (-1);

            free(wrap_bufs[1].pvBuffer);
            wrap_bufs[1].pvBuffer = NULL;
        } else {
            if ( msg_buf.pvBuffer )
                free(msg_buf.pvBuffer);
            msg_buf.pvBuffer = 0;
            msg_buf.cbBuffer = 0;
        }

        if (send_token(s, TOKEN_NOOP, empty_token) < 0)
            return(-1);
    } while ( 1 /* Loop will break if NOOP received */);

    if (context.dwUpper != 0 || context.dwLower != 0)
    {
        maj_stat = ImpersonateSecurityContext( &context );
        if (maj_stat == SEC_E_OK)
        {
            char nameBuffer[256];
            ULONG nameBufferSize = sizeof(nameBuffer);
            HANDLE TokenHandle;

            if (GetUserNameExA(NameSamCompatible, nameBuffer, &nameBufferSize))
                fprintf(logfile, "Token identity: %s\r\n", nameBuffer);
            else
                fprintf(stderr, "GetUserNameExA failed: %d\r\n", GetLastError());
       
            if (OpenThreadToken(GetCurrentThread(),
                                TOKEN_READ, TRUE, &TokenHandle))
            {
                fprintf(stderr, "Thread token handle is %08x\r\n", TokenHandle);
                CloseHandle(TokenHandle);
            }
            else
            {
                fprintf(stderr, "OpenThreadToken failed: %d\r\n", GetLastError());
            }
         
            RevertSecurityContext( &context );
        }
        else
        {
            display_status("impersonating context", maj_stat, 0);
        }

        /* Delete context */
        maj_stat = DeleteSecurityContext( &context );
        if (maj_stat != SEC_E_OK)
        {
            display_status("deleting context", maj_stat, 0);
            return (-1);
        }
    }

    if ( logfile )
        fflush(logfile);

   return (0);
}

int _cdecl
main(int argc, char **argv)
{
   SOCKET stmp;
   int err;
   WSADATA socket_data;
   USHORT version_required = 0x0101;
   char *service_name = NULL;
   char *service_password = NULL;
   char *service_realm = NULL;
   CredHandle server_creds;
   u_short port = 4444;
   int s = -1;
   int once = 0;

   FLAGMAPPING FlagMappings[] = {
#define DUPE( x ) { "-" #x, ASC_REQ_ ## x }

      DUPE( CONFIDENTIALITY ),
      DUPE( DELEGATE ),
      DUPE( INTEGRITY ),
      DUPE( USE_SESSION_KEY ),
      DUPE( REPLAY_DETECT ),
      DUPE( SEQUENCE_DETECT )
   };

   logfile = stdout;
   display_file = stdout;
   argc--; argv++;

   while (argc)
   {
      if (strcmp(*argv, "-port") == 0)
      {
         argc--; argv++;
         if (!argc) usage();
         port = (u_short)atoi(*argv);
      }
      else if (strcmp(*argv, "-pass") == 0)
      {
         argc--; argv++;
         service_password = *argv;
      }
      else if (strcmp(*argv, "-package") == 0)
      {
         argc--; argv++;
         package_name = *argv;
      }
      else if (strcmp(*argv, "-verbose") == 0)
      {
         verbose = 1;
      }
      else if (strcmp(*argv, "-once") == 0)
      {
         once = 1;
      }
      else if (strcmp(*argv, "-logfile") == 0)
      {
         argc--; argv++;
         if (!argc) usage();
         logfile = fopen(*argv, "a");
         display_file = logfile;
         if (!logfile)
         {
            perror(*argv);
            exit(1);
         }
      }
      else
      {

         int i;
         BOOL found = FALSE;


         for ( i = 0 ;
             i < ( sizeof( FlagMappings ) /
                   sizeof( FLAGMAPPING ) ) ;
             i ++ )
         {

            if ( _strcmpi( *argv, FlagMappings[ i ].name ) == 0 )
            {

               found = TRUE;
               global_asc_flags |= FlagMappings[ i ].value ;
               break;

            }
         }

         if ( !found )
         {
            break;
         }
      }

      argc--; argv++;
   }
   if (argc != 2)
      usage();

   if ((*argv)[0] == '-')
      usage();

   service_name = *argv;
   argv++;
   service_realm = *argv;
   argv++;


   if (server_acquire_creds(service_name,
                            package_name,
                            service_password,
                            service_realm,
                            &server_creds) < 0)
      return -1;


   err = WSAStartup(version_required, &socket_data);
   if (err)
   {
      fprintf(stderr,"Failed to initailize WSA: %d\n",err);

   }
   else if ((stmp = create_socket(port)) != 0)
   {
      do
      {
          fd_set rfds;

          FD_ZERO(&rfds);
          FD_SET((DWORD)stmp, &rfds);

          if ( select(FD_SETSIZE, &rfds, NULL, NULL, 0) <= 0 || !FD_ISSET(stmp, &rfds) )
          {
              fprintf(stderr,"select on new socket failed: %d\n", GetLastError());
          }

         /* Accept a TCP connection */
         if ((s = (int)accept(stmp, NULL, 0)) == SOCKET_ERROR)
         {
            fprintf(stderr,"accepting connection: %d\n", GetLastError());
         }
         else
         {
            /* this return value is not checked, because there's
               not really anything to do if it fails */
            sign_server(s, &server_creds);
         }
      } while (!once);

      closesocket(stmp);
   }

   (void) FreeCredentialsHandle( &server_creds);

   /*NOTREACHED*/
   (void) closesocket(s);
   return 0;
}

static void
dumpAttribute(PAUTHZ_SECURITY_ATTRIBUTE_V1 attr)
{
    ULONG i;

    printf("Name:       %S\r\n", attr->pName);
    printf("ValueType:  %d\r\n", attr->ValueType);
    printf("Flags:      %08x\r\n", attr->Flags);
    printf("ValueCount: %u\r\n", attr->ValueCount);

    for (i = 0; i < attr->ValueCount; i++)
    {
        printf("Value[%02d]:  ", i);

        switch (attr->ValueType)
        {
            case AUTHZ_SECURITY_ATTRIBUTE_TYPE_INT64:
                printf("%lld", attr->Values.pInt64[i]);
                break;
            case AUTHZ_SECURITY_ATTRIBUTE_TYPE_UINT64:
                printf("%llu", attr->Values.pUint64[i]);
                break;
            case AUTHZ_SECURITY_ATTRIBUTE_TYPE_STRING:
                printf("%S", attr->Values.ppString[i]);
                break;
            case AUTHZ_SECURITY_ATTRIBUTE_TYPE_FQBN: {
                PAUTHZ_SECURITY_ATTRIBUTE_FQBN_VALUE v =
                    &attr->Values.pFqbn[i];

                printf("%d[%llu]", v->pName, v->Version);
                break;
            }
            case AUTHZ_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING: {
                PAUTHZ_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE v =
                    &attr->Values.pOctetString[i];
                PUCHAR p = (PUCHAR)v->pValue;
                ULONG j;

                for (j = 0; j < v->ValueLength; j++)
                    printf("%02x", p[j]);
                break;
            }
            default:
                break;
        }

        printf("\r\n");
    }
}

static int
dumpAttributes(PCtxtHandle context)
{
    DWORD dwStatus;
    DWORD i;
    PAUTHZ_SECURITY_ATTRIBUTES_INFORMATION attrs;

    dwStatus = QueryContextAttributes(context,
                                      SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES,
                                      &attrs);
    if (dwStatus != SEC_E_OK)
    {
        display_status("Query context attributes", dwStatus, 0 );
        return dwStatus;
    }

    if (attrs == NULL || attrs->Version != 1)
    {
        return SEC_E_OK;
    }

    for (i = 0; i < attrs->AttributeCount; i++)
        dumpAttribute(&attrs->Attribute.pAttributeV1[i]);

    return SEC_E_OK;
}
