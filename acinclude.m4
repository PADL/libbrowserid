dnl Based on the one from the Boinc project by Reinhard

AC_DEFUN([AX_CHECK_WINDOWS],
[AC_MSG_CHECKING(for windows)
target_windows="no"
AC_CHECK_HEADER(windows.h,[target_windows="yes"],[target_windows="no"])
AC_MSG_RESULT($target_windows)
AM_CONDITIONAL(TARGET_WINDOWS,test "x$target_windows" = "xyes")
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
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find GSS-API/Kerberos libraries.

  Please install MIT or Heimdal or specify installation directory with
  --with-krb5=(dir).
----------------------------------------------------------------------
])
else
	printf "Kerberos found in $krb5dir\n";
	AC_SUBST(KRB5_CFLAGS)
        AC_SUBST(KRB5_LDFLAGS)
	AC_SUBST(KRB5_LIBS)
	AC_SUBST(COMPILE_ET)
	AC_CHECK_LIB(krb5, GSS_C_NT_COMPOSITE_EXPORT, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_NT_COMPOSITE_EXPORT], 1, [Define if GSS-API library supports recent naming extensions draft])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_inquire_attrs_for_mech, [AC_DEFINE_UNQUOTED([HAVE_GSS_INQUIRE_ATTRS_FOR_MECH], 1, [Define if GSS-API library supports RFC 5587])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, gss_krb5_import_cred, [AC_DEFINE_UNQUOTED([HAVE_GSS_KRB5_IMPORT_CRED], 1, [Define if GSS-API library supports gss_krb5_import_cred])], [], "$KRB5_LIBS")
	AC_CHECK_LIB(krb5, heimdal_version, [AC_DEFINE_UNQUOTED([HAVE_HEIMDAL_VERSION], 1, [Define if building against Heimdal Kerberos implementation]), heimdal=yes], [heimdal=no], "$KRB5_LIBS")
	AM_CONDITIONAL(HEIMDAL, test "x$heimdal" != "xno")
fi
])dnl

AC_DEFUN([AX_CHECK_EAP],
[AC_MSG_CHECKING(for EAP implementation)
EAP_DIR=
found_eap="no"
AC_ARG_WITH(eap,
    AC_HELP_STRING([--with-eap],
       [Use eap (in specified installation directory)]),
    [check_eap_dir="$withval"],
    [check_eap_dir=])
for dir in $check_eap_dir $prefix /usr /usr/local ../libeap ; do
   eapdir="$dir"
   if test -f "$dir/src/eap_peer/eap.h"; then
     found_eap="yes";
     EAP_DIR="${eapdir}"
     EAP_CFLAGS="-I$eapdir/src/common -I$eapdir/src -I$eapdir/src/utils";
     break;
   fi
done
AC_MSG_RESULT($found_eap)
if test x_$found_eap != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find EAP libraries.

  Please install wpa_supplicant or specify installation directory with
  --with-eap=(dir).
----------------------------------------------------------------------
])
else
	printf "EAP found in $eapdir\n";
	EAP_CFLAGS="$EAP_CFLAGS \
-DEAP_TLS \
-DEAP_PEAP \
-DEAP_TTLS \
-DEAP_MD5 \
-DEAP_MSCHAPv2 \
-DEAP_GTC \
-DEAP_OTP \
-DEAP_LEAP \
-DEAP_PSK \
-DEAP_PAX \
-DEAP_SAKE \
-DEAP_GPSK \
-DEAP_GPSK_SHA256 \
-DEAP_SERVER_IDENTITY \
-DEAP_SERVER_TLS \
-DEAP_SERVER_PEAP \
-DEAP_SERVER_TTLS \
-DEAP_SERVER_MD5 \
-DEAP_SERVER_MSCHAPV2 \
-DEAP_SERVER_GTC \
-DEAP_SERVER_PSK \
-DEAP_SERVER_PAX \
-DEAP_SERVER_SAKE \
-DEAP_SERVER_GPSK \
-DEAP_SERVER_GPSK_SHA256 \
-DIEEE8021X_EAPOL";
	EAP_LIBS="-leap -lutils -lcrypto -ltls -lssl";
	EAP_LDFLAGS="-L$eapdir/eap_example -L$eapdir/src/utils -L$eapdir/src/crypto -L$eapdir/src/tls";
	AC_SUBST(EAP_CFLAGS)
	AC_SUBST(EAP_LDFLAGS)
	AC_SUBST(EAP_LIBS)
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
if test x_$found_shibsp != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find Shibboleth libraries.

  Please install Shibboleth or specify installation directory with
  --with-shibsp=(dir).
----------------------------------------------------------------------
])
else
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
if test x_$found_shibresolver != x_yes; then
   AC_MSG_WARN([
----------------------------------------------------------------------
  Cannot find Shibboleth resolver libraries, building without
  Shibboleth support.

  Please install Shibboleth or specify installation directory with
  --with-shibresolver=(dir).
----------------------------------------------------------------------
])
else
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
if test x_$found_opensaml != x_yes; then
   AC_MSG_WARN([
----------------------------------------------------------------------
  Cannot find OpenSAML libraries, building without OpenSAML support.

  Please install OpenSAML or specify installation directory with
  --with-opensaml=(dir).
----------------------------------------------------------------------
])
else
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
   if test -f "$dir/include/openssl/opensslv.h"; then
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

  Please install libssl or specify installation directory with
  --with-openssl=(dir).
----------------------------------------------------------------------
])
else
	printf "OpenSSL found in $openssldir\n";
	OPENSSL_LIBS="-lssl -lcrypto";
	OPENSSL_LDFLAGS="-L$openssldir/lib";
	AC_SUBST(OPENSSL_CFLAGS)
	AC_SUBST(OPENSSL_LDFLAGS)
	AC_SUBST(OPENSSL_LIBS)
fi
])dnl

AC_DEFUN([AX_CHECK_RADSEC],
[AC_MSG_CHECKING(for radsec)
RADSEC_DIR=
found_radsec="no"
AC_ARG_WITH(radsec,
    AC_HELP_STRING([--with-radsec],
       [Use radsec (in specified installation directory)]),
    [check_radsec_dir="$withval"],
    [check_radsec_dir=])
for dir in $check_radsec_dir $prefix /usr /usr/local ; do
   radsecdir="$dir"
   if test -f "$dir/include/radsec/radsec.h"; then
     found_radsec="yes";
     RADSEC_DIR="${radsecdir}"
     RADSEC_CFLAGS="-I$radsecdir/include";
     break;
   fi
done
AC_MSG_RESULT($found_radsec)
if test x_$found_radsec != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find radsec libraries.

  Please install libradsec or specify installation directory with
  --with-radsec=(dir).
----------------------------------------------------------------------
])
else
	printf "radsec found in $radsecdir\n";
	RADSEC_LIBS="-lradsec";
	RADSEC_LDFLAGS="-L$radsecdir/lib";
	AC_SUBST(RADSEC_CFLAGS)
	AC_SUBST(RADSEC_LDFLAGS)
	AC_SUBST(RADSEC_LIBS)
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

AC_DEFUN([AX_CHECK_LIBMOONSHOT],
[AC_MSG_CHECKING(for Moonshot identity selector implementation)
LIBMOONSHOT_DIR=
LIBMOONSHOT_CFLAGS=
LIBMOONSHOT_LDFLAGS=
LIBMOONSHOT_LIBS=
found_libmoonshot="no"
AC_ARG_WITH(libmoonshot,
    AC_HELP_STRING([--with-libmoonshot],
       [Use libmoonshot (in specified installation directory)]),
    [check_libmoonshot_dir="$withval"],
    [check_libmoonshot_dir=])
for dir in $check_libmoonshot_dir $prefix /usr /usr/local ; do
   libmoonshotdir="$dir"
   if test -f "$dir/include/libmoonshot.h"; then
     found_libmoonshot="yes";
     LIBMOONSHOT_DIR="${libmoonshotdir}"
     LIBMOONSHOT_CFLAGS="-I$libmoonshotdir/include";
     break;
   fi
done
AC_MSG_RESULT($found_libmoonshot)
if test x_$found_libmoonshot = x_yes; then
    printf "libmoonshot found in $libmoonshotdir\n";
    LIBMOONSHOT_LIBS="-lmoonshot";
    LIBMOONSHOT_LDFLAGS="-L$libmoonshot/lib";
    AC_CHECK_LIB(moonshot, moonshot_get_identity, [AC_DEFINE_UNQUOTED([HAVE_MOONSHOT_GET_IDENTITY], 1, [Define if Moonshot identity selector is available])], [], "$LIBMOONSHOT_LIBS")
fi
    AC_SUBST(LIBMOONSHOT_CFLAGS)
    AC_SUBST(LIBMOONSHOT_LDFLAGS)
    AC_SUBST(LIBMOONSHOT_LIBS)
    AM_CONDITIONAL(LIBMOONSHOT, test "x$found_libmoonshot" != "xno")
])dnl

