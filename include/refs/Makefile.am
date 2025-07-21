MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

publicheaders = \
	fsapi.h \
	layout.h \
	node.h \
	sys.h \
	util.h \
	volume.h

privateheaders =

if INSTALL_LIBRARY
refsincludedir=$(includedir)/refs

refsinclude_HEADERS = $(publicheaders)
else
noinst_HEADERS =  $(publicheaders) $(privateheaders)
endif
