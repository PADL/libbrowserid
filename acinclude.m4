dnl Based on the one from the Boinc project by Reinhard

AC_DEFUN([AX_CHECK_WINDOWS],
[AC_MSG_CHECKING(for windows)
target_windows="no"
AC_CHECK_HEADER(windows.h,[target_windows="yes"],[target_windows="no"])
AC_MSG_RESULT($target_windows)
AM_CONDITIONAL(TARGET_WINDOWS,test "x$target_windows" = "xyes")
])dnl

AC_DEFUN([AX_CHECK_MACOSX],
[AC_MSG_CHECKING(for OSX)
target_macosx="no"
AC_CHECK_HEADER(Availability.h,[target_macosx="yes"],[target_macosx="no"])
AC_MSG_RESULT($target_macosx)
AM_CONDITIONAL(TARGET_MACOSX,test "x$target_macosx" = "xyes")
])dnl

AC_DEFUN([AX_CHECK_KRB5],
[AC_MSG_CHECKING(for GSS-API and Kerberos implementation)
KRB5_DIR=
found_krb5="no"
AC_ARG_WITH(krb5,
    AC_HELP_STRING([--with-krb5],
       [Use krb5 (in specified installation directory)]),
    [check_krb5_dir="$withval"],
    [check_krb5_dir=])
for dir in $check_krb5_dir $prefix /usr/local /usr ; do
   krb5dir="$dir"
   if test -x "$dir/bin/krb5-config"; then
     found_krb5="yes";
     if test "x$target_windows" = "xyes"; then
        KRB5_CFLAGS=-I"$check_krb5_dir/include";
        KRB5_LDFLAGS="-L$check_krb5_dir/lib/";
        KRB5_LIBS="-lkrb5_32 -lgssapi32";
        COMPILE_ET="$check_krb5_dir/bin/compile_et";
	AC_MSG_RESULT([yes])
     else
        KRB5_CFLAGS=`$dir/bin/krb5-config gssapi --cflags`;
        KRB5_LDFLAGS="-L$dir/lib";
        KRB5_LIBS=`$dir/bin/krb5-config gssapi --libs`
AC_MSG_RESULT([yes])
        AC_PATH_PROG(COMPILE_ET, [compile_et], [compile_et], [$dir/bin$PATH_SEPARATOr])
     fi
     break;
   fi
done
if test x_$found_krb5 != x_yes; then
   AC_MSG_RESULT($found_krb5)
if test x_$build_mech != x_no; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find GSS-API/Kerberos libraries.

  Please install MIT or Heimdal or specify installation directory with
  --with-krb5=(dir).
----------------------------------------------------------------------
])
fi
else
	printf "Kerberos found in $krb5dir\n";
	AC_SUBST(KRB5_CFLAGS)
        AC_SUBST(KRB5_LDFLAGS)
	AC_SUBST(KRB5_LIBS)
	AC_SUBST(COMPILE_ET)
	AC_CHECK_LIB(krb5, GSS_C_NT_COMPOSITE_EXPORT, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_NT_COMPOSITE_EXPORT], 1, [Define if GSS-API library supports recent naming extensions draft])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_inquire_attrs_for_mech, [AC_DEFINE_UNQUOTED([HAVE_GSS_INQUIRE_ATTRS_FOR_MECH], 1, [Define if GSS-API library supports RFC 5587])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_krb5_import_cred, [AC_DEFINE_UNQUOTED([HAVE_GSS_KRB5_IMPORT_CRED], 1, [Define if GSS-API library supports gss_krb5_import_cred])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_acquire_cred_from, [AC_DEFINE_UNQUOTED([HAVE_GSS_ACQUIRE_CRED_FROM], 1, [Define if GSS-API library supports gss_acquire_cred_from]), gss_acquire_cred_from=yes], [gss_acquire_cred_from=no], "$KRB5_LIBS")
	AM_CONDITIONAL(HAVE_GSS_ACQUIRE_CRED_FROM, test "x$gss_acquire_cred_from" != "xno")
	AC_CHECK_LIB(krb5, heimdal_version, [AC_DEFINE_UNQUOTED([HAVE_HEIMDAL_VERSION], 1, [Define if building against Heimdal Kerberos implementation]), heimdal=yes], [heimdal=no], "$KRB5_LIBS")
	AM_CONDITIONAL(HEIMDAL, test "x$heimdal" != "xno")
fi
])dnl

AC_DEFUN([AX_CHECK_SHIBSP],
[AC_MSG_CHECKING(for Shibboleth implementation)
SHIBSP_DIR=
found_shibsp="no"
AC_ARG_WITH(shibsp,
    AC_HELP_STRING([--with-shibsp],
       [Use shibspboleth (in specified installation directory)]),
    [check_shibsp_dir="$withval"],
    [check_shibsp_dir=])
for dir in $check_shibsp_dir $prefix /usr /usr/local ; do
   shibspdir="$dir"
   if test -f "$dir/include/shibsp/SPConfig.h"; then
     found_shibsp="yes";
     SHIBSP_DIR="${shibspdir}"
     SHIBSP_CXXFLAGS="-I$shibspdir/include";
     break;
   fi
done
AC_MSG_RESULT($found_shibsp)
if test x_$found_shibsp = x_yes; then
	printf "Shibboleth found in $shibspdir\n";
	SHIBSP_LIBS="-lshibsp -lsaml -lxml-security-c -lxmltooling -lxerces-c";
	SHIBSP_LDFLAGS="-L$shibspdir/lib";
	AC_SUBST(SHIBSP_CXXFLAGS)
	AC_SUBST(SHIBSP_LDFLAGS)
	AC_SUBST(SHIBSP_LIBS)
	AC_DEFINE_UNQUOTED([HAVE_SHIBSP], 1, [Define is Shibboleth SP is available])
fi
])dnl

AC_DEFUN([AX_CHECK_SHIBRESOLVER],
[AC_MSG_CHECKING(for Shibboleth resolver implementation)
SHIBRESOLVER_DIR=
found_shibresolver="no"
AC_ARG_WITH(shibresolver,
    AC_HELP_STRING([--with-shibresolver],
       [Use Shibboleth resolver (in specified installation directory)]),
    [check_shibresolver_dir="$withval"],
    [check_shibresolver_dir=])
if test x_$check_shibresolver_dir != x_no; then
for dir in $check_shibresolver_dir $prefix /usr /usr/local ; do
   shibresolverdir="$dir"
   if test -f "$dir/include/shibresolver/resolver.h"; then
     found_shibresolver="yes";
     SHIBRESOLVER_DIR="${shibresolverdir}"
     SHIBRESOLVER_CXXFLAGS="-I$shibresolverdir/include";
     break;
   fi
done
fi
AC_MSG_RESULT($found_shibresolver)
if test x_$check_shibresolver_dir != x_no; then
if test x_$found_shibresolver = x_yes; then
	printf "Shibboleth resolver found in $shibresolverdir\n";
	SHIBRESOLVER_LIBS="-lshibresolver";
	SHIBRESOLVER_LDFLAGS="-L$shibresolverdir/lib";
	AC_SUBST(SHIBRESOLVER_CXXFLAGS)
	AC_SUBST(SHIBRESOLVER_LDFLAGS)
	AC_SUBST(SHIBRESOLVER_LIBS)
	AC_DEFINE_UNQUOTED([HAVE_SHIBRESOLVER], 1, [Define is Shibboleth resolver is available])
fi
fi
])dnl

AC_DEFUN([AX_CHECK_OPENSAML],
[AC_MSG_CHECKING(for OpenSAML implementation)
OPENSAML_DIR=
found_opensaml="no"
AC_ARG_WITH(opensaml,
    AC_HELP_STRING([--with-opensaml],
       [Use OpenSAML (in specified installation directory)]),
    [check_opensaml_dir="$withval"],
    [check_opensaml_dir=])
if test x_$check_opensaml_dir != x_no; then
for dir in $check_opensaml_dir $prefix /usr /usr/local ; do
   opensamldir="$dir"
   if test -f "$dir/include/saml/Assertion.h"; then
     found_opensaml="yes";
     OPENSAML_DIR="${opensamldir}"
     OPENSAML_CXXFLAGS="-I$opensamldir/include";
     break;
   fi
done
fi
AC_MSG_RESULT($found_opensaml)
if test x_$check_opensaml_dir != x_no; then
if test x_$found_opensaml = x_yes; then
	printf "OpenSAML found in $opensamldir\n";
	OPENSAML_LIBS="-lsaml -lxml-security-c -lxmltooling -lxerces-c";
	OPENSAML_LDFLAGS="-L$opensamldir/lib";
	AC_SUBST(OPENSAML_CXXFLAGS)
	AC_SUBST(OPENSAML_LDFLAGS)
	AC_SUBST(OPENSAML_LIBS)
	AC_DEFINE_UNQUOTED([HAVE_OPENSAML], 1, [Define is OpenSAML is available])
fi
fi
])dnl

AC_DEFUN([AX_CHECK_JANSSON],
[AC_MSG_CHECKING(for jansson)
JANSSON_DIR=
found_jansson="no"
AC_ARG_WITH(jansson,
    AC_HELP_STRING([--with-jansson],
       [Use jansson (in specified installation directory)]),
    [check_jansson_dir="$withval"],
    [check_jansson_dir=])
for dir in $check_jansson_dir $prefix /usr /usr/local ; do
   janssondir="$dir"
   if test -f "$dir/include/jansson.h"; then
     found_jansson="yes";
     JANSSON_DIR="${janssondir}"
     JANSSON_CFLAGS="-I$janssondir/include";
     break;
   fi
done
AC_MSG_RESULT($found_jansson)
if test x_$found_jansson != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find jansson libraries.

  Please install libjansson or specify installation directory with
  --with-jansson=(dir).
----------------------------------------------------------------------
])
else
	printf "jansson found in $janssondir\n";
	JANSSON_LIBS="-ljansson";
	JANSSON_LDFLAGS="-L$janssondir/lib";
	AC_SUBST(JANSSON_CFLAGS)
	AC_SUBST(JANSSON_LDFLAGS)
	AC_SUBST(JANSSON_LIBS)
fi
])dnl

AC_DEFUN([AX_CHECK_CURL],
[AC_MSG_CHECKING(for curl)
CURL_DIR=
found_curl="no"
AC_ARG_WITH(curl,
    AC_HELP_STRING([--with-curl],
       [Use curl (in specified installation directory)]),
    [check_curl_dir="$withval"],
    [check_curl_dir=])
for dir in $check_curl_dir $prefix /usr /usr/local ; do
   curldir="$dir"
   if test -f "$dir/include/curl/curl.h"; then
     found_curl="yes";
     CURL_DIR="${curldir}"
     CURL_CFLAGS="-I$curldir/include";
     break;
   fi
done
AC_MSG_RESULT($found_curl)
if test x_$found_curl != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find curl libraries.

  Please install libcurl or specify installation directory with
  --with-curl=(dir).
----------------------------------------------------------------------
])
else
	printf "curl found in $curldir\n";
	CURL_LIBS="-lcurl";
	CURL_LDFLAGS="-L$curldir/lib";
	AC_SUBST(CURL_CFLAGS)
	AC_SUBST(CURL_LDFLAGS)
	AC_SUBST(CURL_LIBS)
fi
])dnl

AC_DEFUN([AX_CHECK_OPENSSL],
[AC_MSG_CHECKING(for OpenSSL)
OPENSSL_DIR=
found_openssl="no"
AC_ARG_WITH(openssl,
    AC_HELP_STRING([--with-openssl],
       [Use OpenSSL (in specified installation directory)]),
    [check_openssl_dir="$withval"],
    [check_openssl_dir=])
for dir in $check_openssl_dir $prefix /usr /usr/local ; do
   openssldir="$dir"
   if test -f "$dir/include/openssl/dsa.h"; then
     found_openssl="yes";
     OPENSSL_DIR="${openssldir}"
     OPENSSL_CFLAGS="-I$openssldir/include";
     break;
   fi
done
AC_MSG_RESULT($found_openssl)
if test x_$found_openssl != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find OpenSSL libraries.

  Please install libcrypto or specify installation directory with
  --with-openssl=(dir).
----------------------------------------------------------------------
])
else
	printf "OpenSSL found in $openssldir\n";
	OPENSSL_LIBS="-lcrypto";
	OPENSSL_LDFLAGS="-L$openssldir/lib";
	AC_SUBST(OPENSSL_CFLAGS)
	AC_SUBST(OPENSSL_LDFLAGS)
	AC_SUBST(OPENSSL_LIBS)
fi
])dnl

