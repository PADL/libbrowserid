dnl Based on the one from the Boinc project by Reinhard

AC_DEFUN([AX_CHECK_KRB5],
[AC_MSG_CHECKING(for GSS-API and Kerberos implementation)
KRB5_DIR=
found_krb5="no"
AC_ARG_WITH(krb5,
    AC_HELP_STRING([--with-krb5],
       [Use krb5 (in specified installation directory)]),
    [check_krb5_dir="$withval"],
    [check_krb5_dir=])
for dir in $check_krb5_dir /usr /usr/local ; do
   krb5dir="$dir"
   if test -f "$dir/include/krb5.h"; then
     found_krb5="yes";
     KRB5_DIR="${krb5dir}"
     KRB5_CFLAGS="-I$krb5dir/include";
     break;
   fi
done
AC_MSG_RESULT($found_krb5)
if test x_$found_krb5 != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find GSS-API/Kerberos libraries.

  Please install MIT or Heimdal or specify installation directory with
  --with-krb5=(dir).
----------------------------------------------------------------------
])
else
	printf "Kerberos found in $krb5dir\n";
	KRB5_LIBS="-lgssapi_krb5 -lkrb5 -lk5crypto";
	KRB5_LDFLAGS="-L$krb5dir/lib";
	AC_SUBST(KRB5_CFLAGS)
	AC_SUBST(KRB5_LDFLAGS)
	AC_SUBST(KRB5_LIBS)
	AC_CHECK_LIB(gssapi_krb5, GSS_C_NT_COMPOSITE_EXPORT, [AC_DEFINE_UNQUOTED([HAVE_GSS_C_NT_COMPOSITE_EXPORT], 1, [Define if GSS-API library supports recent naming extensions draft])], [], "$KRB5_LDFLAGS")
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
for dir in $check_eap_dir /usr /usr/local ; do
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
	EAP_LIBS="-leap -lutils -lcrypto -ltls";
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
for dir in $check_shibsp_dir /usr /usr/local ; do
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
  Cannot find Shibboleth/OpenSAML libraries.

  Please install Shibboleth or specify installation directory with
  --with-shibsp=(dir).
----------------------------------------------------------------------
])
else
	printf "Shibboleth found in $shibspdir\n";
	SHIBSP_LIBS="-lshibsp -llog4shib -lsaml -lxml-security-c -lxmltooling -lxerces-c";
	SHIBSP_LDFLAGS="-L$shibspdir/lib";
	AC_SUBST(SHIBSP_CXXFLAGS)
	AC_SUBST(SHIBSP_LDFLAGS)
	AC_SUBST(SHIBSP_LIBS)
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
for dir in $check_shibresolver_dir /usr /usr/local ; do
   shibresolverdir="$dir"
   if test -f "$dir/include/shibresolver/resolver.h"; then
     found_shibresolver="yes";
     SHIBRESOLVER_DIR="${shibresolverdir}"
     SHIBRESOLVER_CXXFLAGS="-I$shibresolverdir/include";
     break;
   fi
done
AC_MSG_RESULT($found_shibresolver)
if test x_$found_shibresolver != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find Shibboleth resolver libraries.

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
fi
])dnl
