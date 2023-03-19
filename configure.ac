AC_PREREQ(2.59)
AC_INIT([refsprogs],[0.1],[catacombae@gmail.com])
LIBREFS_VERSION="1"
AC_CONFIG_SRCDIR([refsprogs/refsls.c])

# Environment
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# Automake
AM_INIT_AUTOMAKE([])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE

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

AC_CHECK_FUNC(
	[iconv_open],
	[],
	[
		AC_CHECK_LIB(
			[iconv],
			[iconv_open],
			,
			AC_MSG_ERROR([[Unable to locate iconv library.]])
		)
	]
)

AC_SYS_LARGEFILE

# Settings
AC_SUBST([LIBREFS_VERSION])
AM_CONDITIONAL([INSTALL_LIBRARY], [test "${enable_library}" = "yes"])
AM_CONDITIONAL([ENABLE_NFCONV], [test "${enable_nfconv}" = "yes"])

# generate files
AC_CONFIG_FILES([
	Makefile
	include/Makefile
	include/refs/Makefile
	librefs/Makefile
	librefs/librefs.pc
	refsprogs/Makefile
])
AC_OUTPUT

echo "You can now type 'make' to build refsprogs."
