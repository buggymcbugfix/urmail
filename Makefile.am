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
# with the urweb named by URWEB, else the one on the PATH.
check-local:
	$(SHELL) $(top_srcdir)/tests/run.sh

.PHONY: check-local
