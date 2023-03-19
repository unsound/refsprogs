MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if INSTALL_LIBRARY
lib_LTLIBRARIES    =
else
noinst_LTLIBRARIES =
endif

COMMON_CFLAGS  = \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/include/refs

COMMON_LDFLAGS = \
	-version-info $(LIBREFS_VERSION) \
	-no-undefined

COMMON_LIBS    =

if INSTALL_LIBRARY
lib_LTLIBRARIES    += librefs.la
else
noinst_LTLIBRARIES += librefs.la
endif

librefs_la_CFLAGS   = \
	$(COMMON_CFLAGS)
librefs_la_LDFLAGS  = \
	$(COMMON_LDFLAGS)
librefs_la_LIBADD  = \
	$(COMMON_LIBS)
librefs_la_SOURCES = \
	node.c \
	sys.c \
	volume.c
