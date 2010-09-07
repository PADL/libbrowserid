dnl Based on the one from the Boinc project by Reinhard

AC_DEFUN([AX_CHECK_KRB5],
[AC_MSG_CHECKING(for Kerberos)
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
     krb5_DIR="${krb5dir}"
     krb5_CFLAGS="-I$krb5dir/include";
     break;
   fi
   if test -f "$dir/include/krb5.h"; then
     found_krb5="yes";
     krb5_DIR="${krb5dir}"
     krb5_CFLAGS="-I$krb5dir/include/";
     break
   fi
done
AC_MSG_RESULT($found_krb5)
if test x_$found_krb5 != x_yes; then
   AC_MSG_ERROR([
----------------------------------------------------------------------
  Cannot find krb5 libraries.

  Please install MIT or Heimdal or specify installation directory with
  --with-krb5=(dir).
----------------------------------------------------------------------
])
else
        printf "Kerberos found in $krb5dir\n";
	krb5_LIBS="-lgssapi_krb5 -lkrb5";
        krb5_LDFLAGS="-L$krb5dir/lib";
	AC_SUBST(krb5_CFLAGS)
	AC_SUBST(krb5_LDFLAGS)
	AC_SUBST(krb5_LIBS)
fi
])dnl
