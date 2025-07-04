MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

bin_PROGRAMS	 =
noinst_PROGRAMS  =
man_MANS	 =


refs_common_libs = \
	$(top_builddir)/librefs/librefs.la

refs_common_ldflags  = $(AM_LDFLAGS)
if ENABLE_NFCONV
refs_common_ldflags += -Wl,-framework,CoreFoundation
endif

refs_common_cflags = \
	$(AM_CFLAGS) \
	-I$(top_srcdir)/include/refs


# Development utilities
noinst_PROGRAMS += search_device
search_device_LDADD = \
	$(refs_common_libs)
search_device_LDFLAGS = \
	$(refs_common_ldflags)
search_device_CFLAGS = \
	$(refs_common_cflags)
search_device_SOURCES = \
	search_device.c
