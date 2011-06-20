AC_PREREQ([2.61])
AC_INIT([mech_eap], [0.1], [bugs@project-moonshot.org])
dnl AC_CONFIG_MACRO_DIR([m4])
dnl AM_INIT_AUTOMAKE([silent-rules])
AC_USE_SYSTEM_EXTENSIONS
AC_GNU_SOURCE
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE()
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static win32-dll])

AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])

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

acceptor=yes
AC_ARG_ENABLE(acceptor,
  [  --enable-acceptor whether to enable acceptor codepaths: yes/no; default yes ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      acceptor=$enableval
    else
      echo "--enable-acceptor argument must be yes or no"
      exit -1
    fi
  ])

if test "x$acceptor" = "xyes" ; then
  echo "acceptor enabled"
  TARGET_CFLAGS="$TARGET_CFLAGS -DGSSEAP_ENABLE_ACCEPTOR"
fi
AM_CONDITIONAL(GSSEAP_ENABLE_ACCEPTOR, test "x$acceptor" != "xno")

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
dnl AX_CHECK_KRB5
AM_CONDITIONAL(HEIMDAL, test "x$heimdal" != "xno")
dnl AX_CHECK_EAP
if test "x$acceptor" = "xyes" ; then
  AX_CHECK_SHIBSP
  AX_CHECK_SHIBRESOLVER
  AX_CHECK_RADSEC
  AX_CHECK_JANSSON
fi
AC_CONFIG_FILES([Makefile libeap/Makefile mech_eap/Makefile])
AC_OUTPUT
