AC_PREREQ([2.61])
AC_INIT([mech_eap], [0.1], [bugs@project-moonshot.org])
dnl AC_CONFIG_MACRO_DIR([m4])
dnl AM_INIT_AUTOMAKE([silent-rules])
AM_INIT_AUTOMAKE
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static])

AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(stdarg.h stdio.h stdint.h sys/param.h)
AC_REPLACE_FUNCS(vasprintf)
AC_GNU_SOURCE

dnl Check if we're on Solaris and set CFLAGS accordingly
dnl AC_CANONICAL_TARGET
dnl case "${target_os}" in
dnl   solaris*)
dnl     TARGET_CFLAGS="-DSYS_SOLARIS9 -D_POSIX_PTHREAD_SEMANTICS"
dnl     if test "$GCC" != yes ; then
dnl       TARGET_CFLAGS="$TARGET_CFLAGS -mt"
dnl     else
dnl       TARGET_CFLAGS="$TARGET_CFLAGS -pthreads"
dnl     fi
dnl     TARGET_LDFLAGS="-lpthread -lsocket -lnsl"
dnl     ;;
dnl   *)
dnl     TARGET_CFLAGS="-Wall -pedantic -pthread"
dnl     TARGET_LDFLAGS=""
dnl   esac

reauth=no
AC_ARG_ENABLE(reauth,
  [  --enable-reauth whether to enable fast reauthentication protocol: yes/no; default no ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      reauth=$enableval
    else
      echo "--enable-reauth argument must be yes or no"
      exit -1
    fi
  ])

if test "x$reauth" = "xyes" ; then
  echo "Fast reauthentication protocol enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DGSSEAP_ENABLE_REAUTH"
fi
AM_CONDITIONAL(GSSEAP_ENABLE_REAUTH, test "x$reauth" != "xno")

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_KRB5
dnl AX_CHECK_EAP
AX_CHECK_SHIBSP
AX_CHECK_SHIBRESOLVER
AX_CHECK_RADSEC
AX_CHECK_JANSSON
AX_CHECK_LIBMOONSHOT
AC_CONFIG_FILES([Makefile libeap/Makefile mech_eap/Makefile])
AC_OUTPUT
