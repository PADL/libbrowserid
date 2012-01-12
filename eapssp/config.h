#ifndef _CONFIG_H_
#define _CONFIG_H_ 1

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #define HAVE_DLFCN_H 1 */

/* Define if GSS-API library supports recent naming extensions draft */
/* #undef HAVE_GSS_C_NT_COMPOSITE_EXPORT */

/* Define if GSS-API library supports RFC 5587 */
#define HAVE_GSS_INQUIRE_ATTRS_FOR_MECH 1

/* Define if GSS-API library supports gss_krb5_import_cred */
/* #define HAVE_GSS_KRB5_IMPORT_CRED 1 */

/* Define if building against Heimdal Kerberos implementation */
#define HAVE_HEIMDAL_VERSION 1

/* Define to 1 if you have the <inttypes.h> header file. */
/* #define HAVE_INTTYPES_H 1 */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if Moonshot identity selector is available */
/* #undef HAVE_MOONSHOT_GET_IDENTITY */

/* Define is OpenSAML is available */
/* #define HAVE_OPENSAML 1 */

/* Define is Shibboleth resolver is available */
/* #define HAVE_SHIBRESOLVER 1 */

/* Define is Shibboleth SP is available */
/* #define HAVE_SHIBSP 1 */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
/* #define HAVE_STRINGS_H 1 */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
/* #define HAVE_SYS_PARAM_H 1 */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #define HAVE_UNISTD_H 1 */

/* Define to 1 if you have the `vasprintf' function. */
/* #define HAVE_VASPRINTF 1 */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "EapSSP"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "support@padl.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "EapSSP"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "EapSSP 0.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "EapSSP"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.1"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

#define EAP_TLS
#define EAP_PEAP
#define EAP_TTLS
#define EAP_MD5
#define EAP_MSCHAPv2
#define EAP_GTC
#define EAP_OTP
#define EAP_LEAP
#define EAP_PSK
#define EAP_PAX
#define EAP_SAKE
#define EAP_GPSK
#define EAP_GPSK_SHA256
#define EAP_SERVER_IDENTITY
#define EAP_SERVER_TLS
#define EAP_SERVER_PEAP
#define EAP_SERVER_TTLS
#define EAP_SERVER_MD5
#define EAP_SERVER_MSCHAPV2
#define EAP_SERVER_GTC
#define EAP_SERVER_PSK
#define EAP_SERVER_PAX
#define EAP_SERVER_SAKE
#define EAP_SERVER_GPSK
#define EAP_SERVER_GPSK_SHA256
#define IEEE8021X_EAPOL
#define CONFIG_NATIVE_WINDOWS

typedef unsigned int uid_t;

#include <BaseTsd.h>

typedef SSIZE_T ssize_t;

#define GSSAPI_LIB_FUNCTION
#define GSSAPI_LIB_CALL
#define GSSAPI_LIB_VARIABLE

/* keep symbols out of the way in case gssapi.dll is ever linked in */
#define gss_release_buffer              GsspReleaseBuffer
#define gss_add_oid_set_member          GsspAddOidSetMember
#define gss_test_oid_set_member         GsspTestOidSetMember
#define gss_release_oid_set             GsspReleaseOidSet
#define gss_create_empty_oid_set        GsspCreateEmptyOidSet
#define gss_create_empty_buffer_set     GsspCreateEmptyBufferSet
#define gss_add_buffer_set_member       GsspAddBufferSetMember
#define gss_release_buffer_set          GsspReleaseBufferSet

/* override malloc/free */
#define GSSEAP_CALLOC                   GsspCallocPtr
#define GSSEAP_MALLOC                   GsspAllocPtr
#define GSSEAP_FREE                     GsspFreePtr
#define GSSEAP_REALLOC                  GsspReallocPtr

#include <gssp.h>

#endif /* _CONFIG_H_ */
