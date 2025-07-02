AC_PREREQ(2.59)
AC_INIT([refsprogs],[2025.6.22],[catacombae@gmail.com])
LIBREFS_VERSION="2"
AC_CONFIG_SRCDIR([refsprogs/refsls.c])

# Environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# Automake
AM_INIT_AUTOMAKE([])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE

# Options.
AC_ARG_ENABLE(
	[library],
	[AS_HELP_STRING(
		[--disable-library],
		[do not install librefs but link it statically into the binaries]
	)],
	[],
	[enable_library="yes"]
)

AC_ARG_ENABLE(
	[refs-fuse],
	[AS_HELP_STRING(
		[--disable-refs-fuse],
		[do not build the FUSE driver (eliminates libfuse dependency)]
	)],
	[case $enableval in
	yes)
		enable_refs_fuse="yes"
		;;
	no)
		enable_refs_fuse="no"
		;;
	*)
		AC_MSG_ERROR([[Unknown option to --enable-refs-fuse: $enableval]])
		;;
	esac],
	[enable_refs_fuse="yes"]
)

# Amend default include/library paths depending on the platform.
case "$target_os" in
openbsd*)
	# OpenBSD keeps iconv and other libraries in /usr/local but doesn't add
	# those paths by default when compiling/linking so add them here.
	CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
	LDFLAGS="${LDFLAGS} -L/usr/local/lib"
	;;
solaris*)
	# Solaris doesn't include the /usr/lib/amd64/pkgconfig path by default,
	# so add it automatically or fuse.pc won't be found.
	# Openindiana/OmniOS can use the SFE version of libfuse, which is
	# located in /usr/gnu, so add that one as well.
	if test -z "${PKG_CONFIG_PATH}"; then
		PKG_CONFIG_PATH="/usr/lib/amd64/pkgconfig:/usr/gnu/lib/amd64/pkgconfig"
	else
		PKG_CONFIG_PATH+=":/usr/lib/amd64/pkgconfig:/usr/gnu/lib/amd64/pkgconfig"
	fi
	export PKG_CONFIG_PATH

	# The SFE repository has a broken fuse.pc file in the libfuse package.
	# It claims that libfuse is installed in /usr, but it's really in
	# /usr/gnu. To work around this we add the /usr/gnu/include path
	# manually to CPPFLAGS and the library path /usr/gnu/lib/amd64 to
	# LDFLAGS.
	CPPFLAGS="${CPPFLAGS} -I/usr/gnu/include/fuse"
	LDFLAGS="${LDFLAGS} -L/usr/gnu/lib/amd64"
	;;
*)
	;;
esac

# Programs
AC_PROG_CC(gcc cc)
AC_PROG_LN_S
AM_PROG_CC_C_O

ifdef(
	[LT_INIT],
	[LT_INIT],
	[AC_PROG_LIBTOOL]
)

AC_PROG_INSTALL

PKG_PROG_PKG_CONFIG

# Checks for header files.
AC_CHECK_HEADERS([ \
	errno.h \
	fcntl.h \
	inttypes.h \
	limits.h \
	stdint.h \
	stdio.h \
	stdlib.h \
	stdarg.h \
	string.h \
	time.h \
	unistd.h \
	linux/fs.h \
	sys/disk.h \
	sys/ioctl.h \
	sys/stat.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STAT
AC_CHECK_FUNCS([ \
	flsll \
	strerror \
	strtoull \
])

# Checks for character conversion libraries.
case "$target_os" in
mingw*)
	# No action needed, we use Win32 character conversion APIs.
	;;
*)
	NO_ICONV=0
	AC_SEARCH_LIBS(
		[iconv_open],
		[iconv],
		[],
		[NO_ICONV=1],
		[]
	)

	if test $NO_ICONV -eq 1; then
		NO_ICONV=0
		AC_CHECK_LIB(
			[iconv],
			[libiconv_open],
			[],
			[NO_ICONV=1]
		)
	fi

	if test $NO_ICONV -eq 1; then
		AC_MSG_ERROR([[Unable to locate iconv library.]])
	fi
	;;
esac

if test "x$enable_refs_fuse" = "xyes"; then
	# Checks for FUSE library.
	FUSE_MODULE_CFLAGS=""
	FUSE_MODULE_LIBS=""

	case "$target_os" in
	netbsd*)
		# Use librefuse.
		FUSE_MODULE_LIBS="-lrefuse"
		;;
	mingw*)
		# Dokan is used. Currently the user needs to specify libfuse include and
		# library paths manually.
		;;
	*)
		# Other platforms (Linux, FreeBSD, ...) use pkg-config.
		PKG_CHECK_MODULES(
			[FUSE_MODULE],
			[fuse >= 2.6.0],
			[],
			[]
		)
		;;
	esac
fi

AC_SYS_LARGEFILE

# Settings
AC_SUBST([LIBREFS_VERSION])
AC_SUBST([FUSE_MODULE_CFLAGS])
AC_SUBST([FUSE_MODULE_LIBS])
AM_CONDITIONAL([INSTALL_LIBRARY], [test "${enable_library}" = "yes"])
AM_CONDITIONAL([ENABLE_NFCONV], [test "${enable_nfconv}" = "yes"])
AM_CONDITIONAL([ENABLE_REFS_FUSE], [test "x${enable_refs_fuse}" = "xyes"])

# generate files
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	include/refs/Makefile
	librefs/Makefile
	librefs/librefs.pc
	refsprogs/Makefile
	refsprogs/redb.8
	refsprogs/refs-fuse.8
	refsprogs/refscat.8
	refsprogs/refsinfo.8
	refsprogs/refslabel.8
	refsprogs/refsls.8
])
AC_OUTPUT

echo "You can now type 'make' to build refsprogs."
