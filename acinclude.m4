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
	KRB5_LIBS="-lgssapi_krb5 -lkrb5";
        KRB5_LDFLAGS="-L$krb5dir/lib";
	AC_SUBST(KRB5_CFLAGS)
	AC_SUBST(KRB5_LDFLAGS)
	AC_SUBST(KRB5_LIBS)
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
	EAP_LIBS="-leap";
        EAP_LDFLAGS="-L$eapdir/eap_example";
	AC_SUBST(EAP_CFLAGS)
	AC_SUBST(EAP_LDFLAGS)
	AC_SUBST(EAP_LIBS)
fi
])dnl

