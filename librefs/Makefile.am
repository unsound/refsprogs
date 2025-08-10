MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if INSTALL_LIBRARY
lib_LTLIBRARIES    =
pkgconfig_DATA     = librefs.pc
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
	fsapi.c \
	node.c \
	rb_tree.c \
	rb_tree.h \
	sys.c \
	volume.c
