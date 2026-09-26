ACLOCAL_AMFLAGS = -I m4

LIB = @URWEB_LIB@/ur/urmail

lib_LTLIBRARIES = liburmail.la

liburmail_la_SOURCES = urmail.c

AM_CPPFLAGS = -I@URWEB_INC@
AM_CFLAGS = -Wimplicit -Wall -Werror

install-exec-local:
	mkdir -p $(LIB)
	cp lib.urp $(LIB)/
	cp *.h $(LIB)/
	cp *.urs $(LIB)/
	-ldconfig
