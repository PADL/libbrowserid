AC_PREREQ([2.61])
AC_INIT([mech_eap], [0.9.2], [bugs@project-moonshot.org])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

dnl AM_INIT_AUTOMAKE([silent-rules])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O
AM_MAINTAINER_MODE()
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static win32-dll])

dnl AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(stdarg.h stdio.h stdint.h sys/param.h)
AC_REPLACE_FUNCS(vasprintf)

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
AX_CHECK_WINDOWS
AX_CHECK_KRB5
AX_CHECK_OPENSAML
AM_CONDITIONAL(OPENSAML, test "x_$check_opensaml_dir" != "x_no")

AX_CHECK_SHIBRESOLVER
AM_CONDITIONAL(SHIBRESOLVER, test "x_$check_shibresolver_dir" != "x_no")
if test x_$found_shibresolver = x_yes; then
  AX_CHECK_SHIBSP
fi

AX_CHECK_OPENSSL

if test "x$acceptor" = "xyes" ; then
  AX_CHECK_RADSEC
  AX_CHECK_JANSSON
fi

AX_CHECK_LIBMOONSHOT
AC_CONFIG_FILES([Makefile libeap/Makefile mech_eap/Makefile
			  mech_eap.spec])
AC_OUTPUT
