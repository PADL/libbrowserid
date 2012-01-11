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

FILE *display_file;

SecBuffer  empty_token_buf = { 0, 0 };
PSecBuffer empty_token = &empty_token_buf;

void display_status_1
PROTOTYPE( (char *m, ULONG code, int type) );

SSIZE_T write_all(int fildes, char *buf, unsigned int nbyte)
{
   int ret;
   char *ptr;

   for (ptr = buf; nbyte; ptr += ret, nbyte -= ret)
   {
      ret = send(fildes, ptr, nbyte,0);
      if (ret < 0)
      {
         return (ret);
      }
      else if (ret == 0)
          break;
   }

   return (ptr-buf);
}

SSIZE_T read_all(int fildes, char *buf, unsigned int nbyte)
{
    int ret;
    char *ptr;
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET((DWORD)fildes, &rfds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;

   for (ptr = buf; nbyte; ptr += ret, nbyte -= ret)
   {
       if ( (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) <= 0) || !FD_ISSET(fildes, &rfds) ) {
           perror("read_all select failed");
           return(ptr-buf);
       }
       ret = recv(fildes, ptr, nbyte,0);
      if (ret < 0)
      {
         return (ret);
      }
      else if (ret == 0) {
          break;
      }
   }

   return (ptr-buf);
}

/*
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *   	flags		(r) the flags to write
 *      tok             (r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * If the flags are non-null, send_token writes the token flags (a
 * single byte, even though they're passed in in an integer). Next,
 * the token length (as a network long) and then the token data are
 * written to the file descriptor s.  It returns 0 on success, and -1
 * if an error occurs or if it could not write all the data.
 */
int send_token(int s, int flags, PSecBuffer tok)
{
    SSIZE_T ret;
    unsigned char char_flags = (unsigned char) flags;
    unsigned char lenbuf[4];

    if (char_flags) {
        ret = write_all(s, (char *)&char_flags, 1);
        if (ret != 1) {
            perror("sending token flags");
            return -1;
        }
    }
    if (tok->cbBuffer > 0xffffffffUL)
        abort();
    lenbuf[0] = (unsigned char)((tok->cbBuffer >> 24) & 0xff);
    lenbuf[1] = (unsigned char)((tok->cbBuffer >> 16) & 0xff);
    lenbuf[2] = (unsigned char)((tok->cbBuffer >> 8) & 0xff);
    lenbuf[3] = (unsigned char)(tok->cbBuffer & 0xff);

    ret = write_all(s, (char *)lenbuf, 4);
    if (ret < 0) {
        perror("sending token length");
        return -1;
    } else if (ret != 4) {
        if (display_file)
            fprintf(display_file, 
                     "sending token length: %d of %d bytes written\n", 
                     ret, 4);
        return -1;
    }

   ret = write_all(s, tok->pvBuffer, tok->cbBuffer);
   if (ret < 0)
   {
      perror("sending token data");
      return -1;
   }
   else if ((ULONG)ret != tok->cbBuffer)
   {
      if (display_file)
         fprintf(display_file,
                 "sending token data: %d of %d bytes written\n",
                 ret, tok->cbBuffer);
      return -1;
   }

   return 0;
}

/*
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *	    flags		(w) the read flags
 *      tok             (w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * recv_token reads the token flags (a single byte, even though
 * they're stored into an integer, then reads the token length (as a
 * network long), allocates memory to hold the data, and then reads
 * the token data from the file descriptor s.  It blocks to read the
 * length and data, if necessary.  On a successful return, the token
 * should be freed with gss_release_buffer.  It returns 0 on success,
 * and -1 if an error occurs or if it could not read all the data.
 */
int recv_token(int s, int *flags, PSecBuffer tok)
{
    SSIZE_T ret;
    unsigned char char_flags;
    unsigned char lenbuf[4];

    ret = read_all(s, (char *) &char_flags, 1);
    if (ret < 0) {
        perror("reading token flags");
        return -1;
    } else if (! ret) {
        if (display_file)
            fputs("reading token flags: 0 bytes read\n", display_file);
        return -1;
    } else {
        *flags = (int) char_flags;
    }

    if (char_flags == 0 ) {
        lenbuf[0] = 0;
        ret = read_all(s, (char *)&lenbuf[1], 3);
        if (ret < 0) {
            perror("reading token length");
            return -1;
        } else if (ret != 3) {
            if (display_file)
                fprintf(display_file, 
                         "reading token length: %d of %d bytes read\n", 
                         ret, 3);
            return -1;
        }
    }
    else {
        ret = read_all(s, (char *)lenbuf, 4);
        if (ret < 0) {
            perror("reading token length");
            return -1;
        } else if (ret != 4) {
            if (display_file)
                fprintf(display_file, 
                         "reading token length: %d of %d bytes read\n", 
                         ret, 4);
            return -1;
        }
    }

    tok->cbBuffer = ((lenbuf[0] << 24)
                    | (lenbuf[1] << 16)
                    | (lenbuf[2] << 8)
                    | lenbuf[3]);
    tok->pvBuffer = (char *) malloc(tok->cbBuffer ? tok->cbBuffer : 1);
    if (tok->cbBuffer && tok->pvBuffer == NULL) {
        if (display_file)
            fprintf(display_file, 
                     "Out of memory allocating token data\n");
        return -1;
    }

   ret = read_all(s, (char *) tok->pvBuffer, tok->cbBuffer);
   if (ret < 0)
   {
      perror("reading token data");
      free(tok->pvBuffer);
      return -1;
   }
   else if ((ULONG)ret != tok->cbBuffer)
   {
      fprintf(display_file, "sending token data: %d of %d bytes written\n",
              ret, tok->cbBuffer);
      free(tok->pvBuffer);
      return -1;
   }

   return 0;
}

void display_status_1(char *m, ULONG code, int type)
{

   if (display_file)
      fprintf(display_file, "GSS-API error %s: %x\n", m,
              code);
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *      msg             a string to be displayed with the message
 *      maj_stat        the GSS-API major status code
 *      min_stat        the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on display_file, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void display_status(char *msg, ULONG maj_stat, ULONG min_stat)
{
   display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
   display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/*
 * Function: display_ctx_flags
 *
 * Purpose: displays the flags returned by context initation in
 *          a human-readable form
 *
 * Arguments:
 *
 *      int             ret_flags
 *
 * Effects:
 *
 * Strings corresponding to the context flags are printed on
 * stdout, preceded by "context flag: " and followed by a newline
 */

void display_ctx_flags(ULONG flags)
{
   if (flags & GSS_C_DELEG_FLAG)
      fprintf(display_file, "context flag: GSS_C_DELEG_FLAG\n");
   if (flags & GSS_C_MUTUAL_FLAG)
      fprintf(display_file, "context flag: GSS_C_MUTUAL_FLAG\n");
   if (flags & GSS_C_REPLAY_FLAG)
      fprintf(display_file, "context flag: GSS_C_REPLAY_FLAG\n");
   if (flags & GSS_C_SEQUENCE_FLAG)
      fprintf(display_file, "context flag: GSS_C_SEQUENCE_FLAG\n");
   if (flags & GSS_C_CONF_FLAG )
      fprintf(display_file, "context flag: GSS_C_CONF_FLAG \n");
   if (flags & GSS_C_INTEG_FLAG )
      fprintf(display_file, "context flag: GSS_C_INTEG_FLAG \n");
}

void print_token(PSecBuffer tok)
{
   ULONG i;
   unsigned char *p = (PUCHAR) tok->pvBuffer;

   if (!display_file)
      return;
   for (i=0; i < tok->cbBuffer; i++, p++)
   {
      fprintf(display_file, "%02x ", *p);
      if ((i % 16) == 15)
      {
         fprintf(display_file, "\n");
      }
   }
   fprintf(display_file, "\n");
   fflush(display_file);
}
