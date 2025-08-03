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
man_MANS += redb.8
redb_LDADD = \
	$(refs_common_libs)
redb_LDFLAGS = \
	$(refs_common_ldflags)
redb_CFLAGS = \
	$(refs_common_cflags)
redb_SOURCES = \
	redb.c

if ENABLE_REFS_FUSE
bin_PROGRAMS += refs-fuse
man_MANS += refs-fuse.8
refs_fuse_LDADD =
if ENABLE_FUSE3
refs_fuse_LDADD += \
	$(FUSE3_MODULE_LIBS)
else
refs_fuse_LDADD += \
	$(FUSE_MODULE_LIBS)
endif # ENABLE_FUSE3
refs_fuse_LDADD += \
	$(refs_common_libs)
refs_fuse_LDFLAGS = \
	$(refs_common_ldflags)
refs_fuse_CFLAGS =
if ENABLE_FUSE3
refs_fuse_CFLAGS += \
	$(FUSE3_MODULE_CFLAGS) \
	-DFUSE_USE_VERSION=32
else
refs_fuse_CFLAGS += \
	$(FUSE_MODULE_CFLAGS) \
	-DFUSE_USE_VERSION=26
endif # ENABLE_FUSE3
refs_fuse_CFLAGS += \
	$(refs_common_cflags)
refs_fuse_SOURCES = \
	refs-fuse.c
endif # ENABLE_REFS_FUSE

bin_PROGRAMS += refscat
man_MANS += refscat.8
refscat_LDADD = \
	$(refs_common_libs)
refscat_LDFLAGS = \
	$(refs_common_ldflags)
refscat_CFLAGS = \
	$(refs_common_cflags)
refscat_SOURCES = \
	refscat.c

bin_PROGRAMS += refsimage
man_MANS += refsimage.8
refsimage_LDADD = \
	$(refs_common_libs)
refsimage_LDFLAGS = \
	$(refs_common_ldflags)
refsimage_CFLAGS = \
	$(refs_common_cflags)
refsimage_SOURCES = \
	refsimage.c

bin_PROGRAMS += refsinfo
man_MANS += refsinfo.8
refsinfo_LDADD = \
	$(refs_common_libs)
refsinfo_LDFLAGS = \
	$(refs_common_ldflags)
refsinfo_CFLAGS = \
	$(refs_common_cflags)
refsinfo_SOURCES = \
	refsinfo.c

bin_PROGRAMS += refslabel
man_MANS += refslabel.8
refslabel_LDADD = \
	$(refs_common_libs)
refslabel_LDFLAGS = \
	$(refs_common_ldflags)
refslabel_CFLAGS = \
	$(refs_common_cflags)
refslabel_SOURCES = \
	refslabel.c

bin_PROGRAMS += refsls
man_MANS += refsls.8
refsls_LDADD = \
	$(refs_common_libs)
refsls_LDFLAGS = \
	$(refs_common_ldflags)
refsls_CFLAGS = \
	$(refs_common_cflags)
refsls_SOURCES = \
	refsls.c
