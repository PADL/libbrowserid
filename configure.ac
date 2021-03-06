AC_PREREQ([2.61])
AC_INIT([libbrowserid], [1.0], [lukeh@padl.com])
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
AC_PROG_OBJC
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS(stdarg.h stdio.h stdint.h sys/param.h fcntl.h)
AC_REPLACE_FUNCS(vasprintf)

build_mech=no
AC_ARG_ENABLE(gss-mech,
  [  --enable-gss-mech whether to build GSS BrowserID mechanism: yes/no; default no ],
  [ if test "x$enableval" = "xyes" -o "x$enableval" = "xno" ; then
      build_mech=$enableval
    else
      echo "--enable-gss-mech argument must be yes or no"
      exit -1
    fi
  ])

AM_CONDITIONAL(GSSBID_BUILD_MECH, test "x$build_mech" = "xyes")

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
  TARGET_CFLAGS="$TARGET_CFLAGS -DGSSBID_ENABLE_ACCEPTOR"
fi
AM_CONDITIONAL(GSSBID_ENABLE_ACCEPTOR, test "x$acceptor" = "xyes")

AC_SUBST(TARGET_CFLAGS)
AC_SUBST(TARGET_LDFLAGS)
AX_CHECK_WINDOWS
AX_CHECK_MACOSX
AX_CHECK_IOS
AX_CHECK_OPENSSL
AM_CONDITIONAL(OPENSSL, test "x$found_openssl" = "xyes")

if test x_$target_macosx != x_yes; then
  AX_CHECK_CURL
  AX_CHECK_JANSSON
fi

AC_CHECK_HEADERS(CFNetwork/CFNetwork.h, [CFNetwork=yes], [CFNetwork=no])
AM_CONDITIONAL(CFNETWORK, test "x$CFNetwork" = "xyes")

dnl AC_CHECK_HEADERS(CoreFoundation/CFRuntime.h, [CFBrowserID=yes], [CFBrowserID=no])
AM_CONDITIONAL(CFBROWSERID, test "x$target_macosx" = "xyes")

if test x_$build_mech != x_no; then
  AX_CHECK_KRB5
  AX_CHECK_OPENSAML
  AX_CHECK_SHIBRESOLVER
  if test x$found_shibresolver = xyes; then
    AX_CHECK_SHIBSP
  fi
fi
AM_CONDITIONAL(SHIBRESOLVER, test "x$found_shibresolver" = "xyes")
AM_CONDITIONAL(SHIBSP, test "x$found_shibsp" = "xyes")
AM_CONDITIONAL(OPENSAML, test "x$found_opensaml" = "xyes")
AM_CONDITIONAL(HAVE_GSS_ACQUIRE_CRED_FROM, test "x$gss_acquire_cred_from" != "xno")
AM_CONDITIONAL(HEIMDAL, test "x$heimdal" != "xno")

AC_CONFIG_FILES([Makefile libcfjson/Makefile libbrowserid/Makefile bidtool/Makefile
		 sample/Makefile mech_browserid/Makefile
		 mech_browserid/mech_browserid.spec])
AC_OUTPUT
