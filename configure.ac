AC_INIT([urmail], [1.0])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([urmail.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror -Wno-portability])

AC_PROG_CC
AM_PROG_AR
LT_INIT
PKG_PROG_PKG_CONFIG

URMAIL_LT_VERSION=0:0:0
AC_SUBST([URMAIL_LT_VERSION])

dnl libcurl: through pkg-config, and its library directory, so that the
dnl generated .urp files can name the shared object by absolute path (an
dnl Ur/Web application is linked without this library's -L flags).
PKG_CHECK_MODULES([LIBCURL], [libcurl], [],
  [AC_MSG_ERROR([libcurl development files are required])])
LIBCURL_LIBDIR=`$PKG_CONFIG --variable=libdir libcurl`
AC_SUBST([LIBCURL_LIBDIR])

dnl Ur/Web: --with-urweb=PREFIX, else the prefix of the urweb on the PATH,
dnl else this package's own prefix. URWEB_INC and URWEB_LIB override the
dnl include and library directories, as in the original configure script.
AC_ARG_WITH([urweb],
  [AS_HELP_STRING([--with-urweb=PREFIX], [where Ur/Web is installed])],
  [urweb_prefix=$withval],
  [urweb_prefix=
   AC_PATH_PROG([URWEB_BIN], [urweb])
   AS_IF([test -n "$URWEB_BIN"], [urweb_prefix=`dirname "$URWEB_BIN"`; urweb_prefix=`dirname "$urweb_prefix"`])])
AS_IF([test "x$prefix" = xNONE], [prefix=$ac_default_prefix])
AS_IF([test "x$exec_prefix" = xNONE], [exec_prefix=$prefix])
AS_IF([test -z "$urweb_prefix"], [urweb_prefix=$prefix])
AS_IF([test -z "$URWEB_INC"], [URWEB_INC=$urweb_prefix/include])
AS_IF([test -z "$URWEB_LIB"], [URWEB_LIB=$urweb_prefix/lib/urweb])
AC_ARG_VAR([URWEB_INC], [include directory holding urweb/urweb.h])
AC_ARG_VAR([URWEB_LIB], [Ur/Web's library directory, holding ur/])
AC_CHECK_FILE([$URWEB_INC/urweb/urweb.h], [],
  [AC_MSG_ERROR([urweb/urweb.h not found under $URWEB_INC; use --with-urweb=PREFIX or URWEB_INC=DIR])])
AC_SUBST([URWEB_INC])
AC_SUBST([URWEB_LIB])

dnl Where this library's own files land, as absolute paths for the .urp files.
LIB_UR=$libdir/urweb/ur/urmail
INCLUDE=$includedir/urweb
PKGCONFIG=$libdir/pkgconfig
AC_SUBST([LIB_UR])
AC_SUBST([INCLUDE])
AC_SUBST([PKGCONFIG])
abs_INCLUDE=`eval echo "$INCLUDE"`
abs_INCLUDE=`eval echo "$abs_INCLUDE"`
abs_libdir=`eval echo "$libdir"`
abs_libdir=`eval echo "$abs_libdir"`
AC_SUBST([abs_INCLUDE])
AC_SUBST([abs_libdir])

case $host_os in
  darwin*) SHLIB_EXT=dylib ;;
  *) SHLIB_EXT=so ;;
esac
AC_SUBST([SHLIB_EXT])

AC_CONFIG_FILES([
  Makefile
  config.urp
  tests/config.urp
  urmail.pc
])

AC_OUTPUT

cat <<EOM

urmail configuration:
  Ur/Web include:      $URWEB_INC
  Ur/Web lib:          $URWEB_LIB
  libcurl:             $LIBCURL_LIBS ($LIBCURL_LIBDIR)
  install .urp/.urs:   $LIB_UR
  install header:      $INCLUDE
EOM
