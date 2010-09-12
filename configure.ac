AC_PREREQ([2.61])
AC_INIT([mech_eap], [0.1], [bugs@project-moonshot.org])
dnl AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
LT_PREREQ([2.2])
LT_INIT([dlopen disable-static])

AC_PROG_CC
AC_PROG_CXX

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

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_KRB5
AX_CHECK_EAP
AX_CHECK_SHIBSP
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
