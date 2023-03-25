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


bin_PROGRAMS += redb
redb_LDADD = \
	$(refs_common_libs)
redb_LDFLAGS = \
	$(refs_common_ldflags)
redb_CFLAGS = \
	$(refs_common_cflags)
redb_SOURCES = \
	redb.c

bin_PROGRAMS += refs-fuse
refs_fuse_LDADD = \
	-lfuse \
	$(refs_common_libs)
refs_fuse_LDFLAGS = \
	$(refs_common_ldflags)
refs_fuse_CFLAGS = \
        -D_FILE_OFFSET_BITS=64 \
	$(refs_common_cflags)
refs_fuse_SOURCES = \
	refs-fuse.c

bin_PROGRAMS += refscat
refscat_LDADD = \
	$(refs_common_libs)
refscat_LDFLAGS = \
	$(refs_common_ldflags)
refscat_CFLAGS = \
	$(refs_common_cflags)
refscat_SOURCES = \
	refscat.c

bin_PROGRAMS += refsinfo
refsinfo_LDADD = \
	$(refs_common_libs)
refsinfo_LDFLAGS = \
	$(refs_common_ldflags)
refsinfo_CFLAGS = \
	$(refs_common_cflags)
refsinfo_SOURCES = \
	refsinfo.c

bin_PROGRAMS += refslabel
refslabel_LDADD = \
	$(refs_common_libs)
refslabel_LDFLAGS = \
	$(refs_common_ldflags)
refslabel_CFLAGS = \
	$(refs_common_cflags)
refslabel_SOURCES = \
	refslabel.c

bin_PROGRAMS += refsls
refsls_LDADD = \
	$(refs_common_libs)
refsls_LDFLAGS = \
	$(refs_common_ldflags)
refsls_CFLAGS = \
	$(refs_common_cflags)
refsls_SOURCES = \
	refsls.c
