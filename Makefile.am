ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = liburmail.la

liburmail_la_SOURCES = urmail.c urmail.h
liburmail_la_LDFLAGS = -version-info $(URMAIL_LT_VERSION)
liburmail_la_LIBADD = $(LIBCURL_LIBS)

AM_CPPFLAGS = -I$(top_srcdir) -I$(URWEB_INC) -I$(URWEB_INC)/urweb $(LIBCURL_CFLAGS)
AM_CFLAGS = -Wall -Werror -Wimplicit

# The Ur/Web side: the signature and the .urp files an application imports
# with `library $(LIB_UR)`.
LIB_URdir = $(LIB_UR)
LIB_UR_DATA = \
  urmail.ur \
  urmail.urs \
  urmailFfi.urs \
  lib.urp \
  config.urp

INCLUDEdir = $(INCLUDE)
INCLUDE_HEADERS = urmail.h

PKGCONFIGdir = $(PKGCONFIG)
PKGCONFIG_DATA = urmail.pc

EXTRA_DIST = \
  urmail.ur \
  urmail.urs \
  urmailFfi.urs \
  lib.urp \
  config.urp.in \
  urmail.pc.in \
  README.md \
  LICENSE \
  examples \
  tests

CLEANFILES = config.urp urmail.pc tests/config.urp

# The tests run against the library as built in this tree (tests/config.urp),
# with the urweb named by URWEB, else the one on the PATH, and build under
# this tree's tests/out.
check-local:
	BUILDDIR=$(abs_top_builddir) $(SHELL) $(top_srcdir)/tests/run.sh

distclean-local:
	rm -rf tests/out tests/out.lock

# tests goes into the distribution as a directory; what a test run in the
# source tree or configure left there is not part of it.
dist-hook:
	rm -rf $(distdir)/tests/out $(distdir)/tests/out.lock $(distdir)/tests/app/test.exe $(distdir)/tests/config.urp

.PHONY: check-local distclean-local dist-hook
