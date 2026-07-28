/*-
 * sys.h - Lightweight abstractions for system functionality.
 *
 * Copyright (c) 2022-2025 Erik Larsson
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the source
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _REFS_SYS_H
#define _REFS_SYS_H

#ifndef SYS_LOG_CRITICAL_ENABLED
#define SYS_LOG_CRITICAL_ENABLED 1
#endif

#ifndef SYS_LOG_ERROR_ENABLED
#define SYS_LOG_ERROR_ENABLED 1
#endif

#ifndef SYS_LOG_WARNING_ENABLED
#define SYS_LOG_WARNING_ENABLED 1
#endif

#ifndef SYS_LOG_INFO_ENABLED
#define SYS_LOG_INFO_ENABLED 1
#endif

#ifndef SYS_LOG_DEBUG_ENABLED
#define SYS_LOG_DEBUG_ENABLED 0
#endif

#ifndef SYS_LOG_TRACE_ENABLED
#define SYS_LOG_TRACE_ENABLED 0
#endif

#ifndef SYS_LOG_INDENT
/* Indentation currently requires the __thread attribute to be supported, so
 * that would exclude most kernel mode code. */
#define SYS_LOG_INDENT 0
#endif /* SYS_LOG_INDENT */

#ifndef SYS_LOG_PROFILING
/* Profiling currently requires gettimeofday, which isn't a perfect profiling
 * method (clock_gettime is TODO), however it works well enough for our purposes
 * at the moment. */
#define SYS_LOG_PROFILING 0
#endif

typedef struct sys_iohandler sys_iohandler;

#if SYS_LOG_INDENT
#ifndef SYS_LOG_INDENT_SIZE
#define SYS_LOG_INDENT_SIZE 4
#endif /* !defined(SYS_LOG_INDENT_SIZE) */

#ifndef SYS_LOG_INDENT_CHAR
#define SYS_LOG_INDENT_CHAR ' '
#endif /* !defined(SYS_LOG_INDENT_CHAR) */

#ifndef SYS_LOG_INDENT_MAX
#define SYS_LOG_INDENT_MAX 32
#endif /* !defined(SYS_LOG_INDENT_MAX) */

extern __thread int __sys_log_indent;

#define __sys_log_indent_declarations \
	char __sys_log_indent_buffer[SYS_LOG_INDENT_MAX * \
		SYS_LOG_INDENT_SIZE + 1]

#define __sys_log_indent_prepare \
	do { \
		const int __sys_log_indent_limit = \
			sys_min(__sys_log_indent, SYS_LOG_INDENT_MAX); \
		\
		memset(__sys_log_indent_buffer, SYS_LOG_INDENT_CHAR, \
			__sys_log_indent_limit * SYS_LOG_INDENT_SIZE); \
		__sys_log_indent_buffer[__sys_log_indent_limit * \
			SYS_LOG_INDENT_SIZE] = '\0'; \
	} while(0)

#define __sys_log_indent_fmt "%s"
#define __sys_log_indent_arg __sys_log_indent_buffer
#define __sys_log_indent_increment ++__sys_log_indent
#define __sys_log_indent_decrement --__sys_log_indent
#else
#define __sys_log_indent_declarations \
	do {} while(0)

#define __sys_log_indent_prepare \
	do {} while(0)

#define __sys_log_indent_fmt "%s"
#define __sys_log_indent_arg ""
#define __sys_log_indent_increment do {} while(0)
#define __sys_log_indent_decrement do {} while(0)
#endif /* SYS_LOG_INDENT ... */

/**
 * No-op log handler that only exists to be able to statically check the format
 * string and arguments for errors when logging is turned off.
 *
 * @param[in] fmt
 *      @p printf format string for constructing the log message.
 * @param[in] ...
 *      Arguments to the @p printf format string (if any).
 */
static inline void __sys_log_noop(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static inline void __sys_log_noop(const char *const fmt, ...)
{
	(void) fmt;
}

/**
 * No-op error-suffixed log handler that only exists to be able to statically
 * check the format string and arguments for errors when logging is turned off.
 *
 * @param[in] err
 *      The error thrown by the system.
 * @param[in] fmt
 *      @p printf format string for constructing the log message.
 * @param[in] ...
 *      Arguments to the @p printf format string (if any).
 */
static inline void __sys_log_pnoop(int err, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static inline void __sys_log_pnoop(int err, const char *const fmt, ...)
{
	(void) err;
	(void) fmt;
}

#define __do_sys_log_generic(level, prefix, fmt, ...) \
	do { \
		__sys_log_indent_declarations; \
		__sys_log_indent_prepare; \
		__do_sys_log_##level(__sys_log_indent_fmt prefix fmt, \
			__sys_log_indent_arg, ##__VA_ARGS__); \
	} while(0)

#define __do_sys_log_pgeneric(err, level, prefix, fmt, ...) \
	do { \
		__sys_log_indent_declarations; \
		__sys_log_indent_prepare; \
		__do_sys_log_p##level(err, __sys_log_indent_fmt prefix fmt, \
			__sys_log_indent_arg, ##__VA_ARGS__); \
	} while(0)

#define __sys_log_critical_prefix "[CRITICAL] "
#define __sys_log_error_prefix "[ERROR] "
#define __sys_log_warning_prefix "[WARNING] "
#define __sys_log_info_prefix ""
#define __sys_log_debug_prefix "[DEBUG] "
#define __sys_log_trace_prefix "[TRACE] "

#if SYS_LOG_CRITICAL_ENABLED
#define sys_log_critical(fmt, ...) \
	__do_sys_log_generic(critical, __sys_log_critical_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_critical __sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_error(fmt, ...) \
	__do_sys_log_generic(error, __sys_log_error_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_error __sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_perror(err, fmt, ...) \
	__do_sys_log_pgeneric(err, error, __sys_log_error_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_perror __sys_log_pnoop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_warning(fmt, ...) \
	__do_sys_log_generic(warning, __sys_log_warning_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_warning __sys_log_noop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_pwarning(err, fmt, ...) \
	__do_sys_log_pgeneric(err, warning, __sys_log_warning_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_pwarning __sys_log_pnoop
#endif

#if SYS_LOG_INFO_ENABLED
#define sys_log_info(fmt, ...) \
	__do_sys_log_generic(info, __sys_log_info_prefix, fmt, ##__VA_ARGS__)
#else
#define sys_log_info __sys_log_noop
#endif

#if SYS_LOG_INFO_ENABLED
#define sys_log_pinfo(err, fmt, ...) \
	__do_sys_log_pgeneric(err, info, __sys_log_info_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_pinfo __sys_log_pnoop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_debug(fmt, ...) \
	__do_sys_log_generic(debug, __sys_log_debug_prefix, fmt, ##__VA_ARGS__)
#else
#define sys_log_debug __sys_log_noop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_pdebug(err, fmt, ...) \
	__do_sys_log_pgeneric(err, debug, __sys_log_debug_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_pdebug __sys_log_pnoop
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_trace(fmt, ...) \
	__do_sys_log_generic(trace, __sys_log_trace_prefix, fmt, ##__VA_ARGS__)
#else
#define sys_log_trace __sys_log_noop
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_ptrace(err, fmt, ...) \
	__do_sys_log_pgeneric(err, trace, __sys_log_trace_prefix, fmt, \
		##__VA_ARGS__)
#else
#define sys_log_ptrace __sys_log_pnoop
#endif

#if SYS_LOG_PROFILING
#define __sys_log_enter_time_declarations \
	sys_difftime __sys_log_enter_start_ts; \
	sys_difftime __sys_log_enter_end_ts
#define __sys_log_get_difftime(difftp) \
	gettimeofday((difftp), NULL)
#define __sys_log_profiling_fmt " (%" PRIu64 " ns)"
#define __sys_log_profiling_arg \
	, PRAu64((__sys_log_enter_end_ts.tv_sec * 1000000000ULL + \
	__sys_log_enter_end_ts.tv_usec * 1000ULL) - \
	(__sys_log_enter_start_ts.tv_sec * 1000000000ULL + \
	__sys_log_enter_start_ts.tv_usec * 1000ULL))
#else
#define __sys_log_enter_time_declarations \
	do {} while(0)
#define __sys_log_get_difftime(difftp) \
	do {} while(0)
#define __sys_log_profiling_fmt ""
#define __sys_log_profiling_arg
#endif /* SYS_LOG_PROFILING ... */

#define __sys_log_do_enter(level, fmt, ...) \
	__sys_log_enter_time_declarations; \
	do { \
		sys_log_##level("Entering %s(" fmt ")...", \
			__FUNCTION__, ##__VA_ARGS__); \
		__sys_log_indent_increment; \
		__sys_log_get_difftime(&__sys_log_enter_start_ts); \
	} while(0)

#define __sys_log_do_leave(level, fmt, ...) \
	do { \
		__sys_log_get_difftime(&__sys_log_enter_end_ts); \
		__sys_log_indent_decrement; \
		sys_log_##level("Leaving %s(" fmt ")." \
			__sys_log_profiling_fmt, \
			__FUNCTION__, ##__VA_ARGS__ __sys_log_profiling_arg); \
	} while(0)

#if SYS_LOG_INFO_ENABLED
#define sys_log_enter_info(...) __sys_log_do_enter(info, __VA_ARGS__)
#define sys_log_leave_info(...) __sys_log_do_leave(info, __VA_ARGS__)
#else
#define sys_log_enter_info(...) __sys_log_noop(__VA_ARGS__)
#define sys_log_leave_info(...) __sys_log_noop(__VA_ARGS__)
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_enter_debug(...) __sys_log_do_enter(debug, __VA_ARGS__)
#define sys_log_leave_debug(...) __sys_log_do_leave(debug, __VA_ARGS__)
#else
#define sys_log_enter_debug(...) __sys_log_noop(__VA_ARGS__)
#define sys_log_leave_debug(...) __sys_log_noop(__VA_ARGS__)
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_enter_trace(...) __sys_log_do_enter(trace, __VA_ARGS__)
#define sys_log_leave_trace(...) __sys_log_do_leave(trace, __VA_ARGS__)
#else
#define sys_log_enter_trace(...) __sys_log_noop(__VA_ARGS__)
#define sys_log_leave_trace(...) __sys_log_noop(__VA_ARGS__)
#endif

#define sys_log_enter(...) sys_log_enter_trace(__VA_ARGS__)
#define sys_log_leave(...) sys_log_leave_trace(__VA_ARGS__)

#if defined(__GNUC__)
#if __GNUC__ >= 7
#define SYS_FALLTHROUGH() __attribute__((__fallthrough__))
#endif /* __GNUC__ >= 7 ... */
#endif /* defined(__GNUC__) */

#ifndef SYS_FALLTHROUGH
#define SYS_FALLTHROUGH() do {} while(0)
#endif /* !defined(SYS_FALLTHROUGH) */

#if defined(__linux__) && defined(__KERNEL__)
#include "sys_linux.h"
#else
#include "sys_user.h"
#endif /* defined(__linux__) && defined(__KERNEL__) ... */

#ifdef S_IFLNK
#define SYS_S_IFLNK S_IFLNK
#else
#define SYS_S_IFLNK 0120000
#endif /* defined(S_IFLNK) ... */

#ifndef PRIb8
#define PRIb8 "d%d%d%d%d%d%d%d"

#define PRAb8(arg) \
	(((uint8_t) (arg)) >> 7) & 0x1, \
	(((uint8_t) (arg)) >> 6) & 0x1, \
	(((uint8_t) (arg)) >> 5) & 0x1, \
	(((uint8_t) (arg)) >> 4) & 0x1, \
	(((uint8_t) (arg)) >> 3) & 0x1, \
	(((uint8_t) (arg)) >> 2) & 0x1, \
	(((uint8_t) (arg)) >> 1) & 0x1, \
	((uint8_t) (arg)) & 0x1
#else
#define PRAb8(arg) (u8) (arg)
#endif /* !defined(PRIb8) ... */

#ifndef PRIb16
#define PRIb16 "d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"

#define PRAb16(arg) \
	(((uint16_t) (arg)) >> 15) & 0x1, \
	(((uint16_t) (arg)) >> 14) & 0x1, \
	(((uint16_t) (arg)) >> 13) & 0x1, \
	(((uint16_t) (arg)) >> 12) & 0x1, \
	(((uint16_t) (arg)) >> 11) & 0x1, \
	(((uint16_t) (arg)) >> 10) & 0x1, \
	(((uint16_t) (arg)) >> 9) & 0x1, \
	(((uint16_t) (arg)) >> 8) & 0x1, \
	(((uint16_t) (arg)) >> 7) & 0x1, \
	(((uint16_t) (arg)) >> 6) & 0x1, \
	(((uint16_t) (arg)) >> 5) & 0x1, \
	(((uint16_t) (arg)) >> 4) & 0x1, \
	(((uint16_t) (arg)) >> 3) & 0x1, \
	(((uint16_t) (arg)) >> 2) & 0x1, \
	(((uint16_t) (arg)) >> 1) & 0x1, \
	((uint16_t) (arg)) & 0x1
#else
#define PRAb16(arg) (u16) (arg)
#endif /* !defined(PRIb16) ... */

#ifndef PRIb32
#define PRIb32 "d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"

#define PRAb32(arg) \
	(((uint32_t) (arg)) >> 31) & 0x1, \
	(((uint32_t) (arg)) >> 30) & 0x1, \
	(((uint32_t) (arg)) >> 29) & 0x1, \
	(((uint32_t) (arg)) >> 28) & 0x1, \
	(((uint32_t) (arg)) >> 27) & 0x1, \
	(((uint32_t) (arg)) >> 26) & 0x1, \
	(((uint32_t) (arg)) >> 25) & 0x1, \
	(((uint32_t) (arg)) >> 24) & 0x1, \
	(((uint32_t) (arg)) >> 23) & 0x1, \
	(((uint32_t) (arg)) >> 22) & 0x1, \
	(((uint32_t) (arg)) >> 21) & 0x1, \
	(((uint32_t) (arg)) >> 20) & 0x1, \
	(((uint32_t) (arg)) >> 19) & 0x1, \
	(((uint32_t) (arg)) >> 18) & 0x1, \
	(((uint32_t) (arg)) >> 17) & 0x1, \
	(((uint32_t) (arg)) >> 16) & 0x1, \
	(((uint32_t) (arg)) >> 15) & 0x1, \
	(((uint32_t) (arg)) >> 14) & 0x1, \
	(((uint32_t) (arg)) >> 13) & 0x1, \
	(((uint32_t) (arg)) >> 12) & 0x1, \
	(((uint32_t) (arg)) >> 11) & 0x1, \
	(((uint32_t) (arg)) >> 10) & 0x1, \
	(((uint32_t) (arg)) >> 9) & 0x1, \
	(((uint32_t) (arg)) >> 8) & 0x1, \
	(((uint32_t) (arg)) >> 7) & 0x1, \
	(((uint32_t) (arg)) >> 6) & 0x1, \
	(((uint32_t) (arg)) >> 5) & 0x1, \
	(((uint32_t) (arg)) >> 4) & 0x1, \
	(((uint32_t) (arg)) >> 3) & 0x1, \
	(((uint32_t) (arg)) >> 2) & 0x1, \
	(((uint32_t) (arg)) >> 1) & 0x1, \
	((uint32_t) (arg)) & 0x1
#else
#define PRAb32(arg) (u32) (arg)
#endif /* !defined(PRIb32) ... */

#ifndef PRIb64
#define PRIb64 \
	"d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d" \
	"d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"

#define PRAb64(arg) \
	(((uint64_t) (arg)) >> 63) & 0x1, \
	(((uint64_t) (arg)) >> 62) & 0x1, \
	(((uint64_t) (arg)) >> 61) & 0x1, \
	(((uint64_t) (arg)) >> 60) & 0x1, \
	(((uint64_t) (arg)) >> 59) & 0x1, \
	(((uint64_t) (arg)) >> 58) & 0x1, \
	(((uint64_t) (arg)) >> 57) & 0x1, \
	(((uint64_t) (arg)) >> 56) & 0x1, \
	(((uint64_t) (arg)) >> 55) & 0x1, \
	(((uint64_t) (arg)) >> 54) & 0x1, \
	(((uint64_t) (arg)) >> 53) & 0x1, \
	(((uint64_t) (arg)) >> 52) & 0x1, \
	(((uint64_t) (arg)) >> 51) & 0x1, \
	(((uint64_t) (arg)) >> 50) & 0x1, \
	(((uint64_t) (arg)) >> 49) & 0x1, \
	(((uint64_t) (arg)) >> 48) & 0x1, \
	(((uint64_t) (arg)) >> 47) & 0x1, \
	(((uint64_t) (arg)) >> 46) & 0x1, \
	(((uint64_t) (arg)) >> 45) & 0x1, \
	(((uint64_t) (arg)) >> 44) & 0x1, \
	(((uint64_t) (arg)) >> 43) & 0x1, \
	(((uint64_t) (arg)) >> 42) & 0x1, \
	(((uint64_t) (arg)) >> 41) & 0x1, \
	(((uint64_t) (arg)) >> 40) & 0x1, \
	(((uint64_t) (arg)) >> 40) & 0x1, \
	(((uint64_t) (arg)) >> 39) & 0x1, \
	(((uint64_t) (arg)) >> 38) & 0x1, \
	(((uint64_t) (arg)) >> 37) & 0x1, \
	(((uint64_t) (arg)) >> 36) & 0x1, \
	(((uint64_t) (arg)) >> 35) & 0x1, \
	(((uint64_t) (arg)) >> 34) & 0x1, \
	(((uint64_t) (arg)) >> 33) & 0x1, \
	(((uint64_t) (arg)) >> 32) & 0x1, \
	(((uint64_t) (arg)) >> 31) & 0x1, \
	(((uint64_t) (arg)) >> 30) & 0x1, \
	(((uint64_t) (arg)) >> 29) & 0x1, \
	(((uint64_t) (arg)) >> 28) & 0x1, \
	(((uint64_t) (arg)) >> 27) & 0x1, \
	(((uint64_t) (arg)) >> 26) & 0x1, \
	(((uint64_t) (arg)) >> 25) & 0x1, \
	(((uint64_t) (arg)) >> 24) & 0x1, \
	(((uint64_t) (arg)) >> 23) & 0x1, \
	(((uint64_t) (arg)) >> 22) & 0x1, \
	(((uint64_t) (arg)) >> 21) & 0x1, \
	(((uint64_t) (arg)) >> 20) & 0x1, \
	(((uint64_t) (arg)) >> 19) & 0x1, \
	(((uint64_t) (arg)) >> 18) & 0x1, \
	(((uint64_t) (arg)) >> 17) & 0x1, \
	(((uint64_t) (arg)) >> 16) & 0x1, \
	(((uint64_t) (arg)) >> 15) & 0x1, \
	(((uint64_t) (arg)) >> 14) & 0x1, \
	(((uint64_t) (arg)) >> 13) & 0x1, \
	(((uint64_t) (arg)) >> 12) & 0x1, \
	(((uint64_t) (arg)) >> 11) & 0x1, \
	(((uint64_t) (arg)) >> 10) & 0x1, \
	(((uint64_t) (arg)) >> 9) & 0x1, \
	(((uint64_t) (arg)) >> 8) & 0x1, \
	(((uint64_t) (arg)) >> 7) & 0x1, \
	(((uint64_t) (arg)) >> 6) & 0x1, \
	(((uint64_t) (arg)) >> 5) & 0x1, \
	(((uint64_t) (arg)) >> 4) & 0x1, \
	(((uint64_t) (arg)) >> 3) & 0x1, \
	(((uint64_t) (arg)) >> 2) & 0x1, \
	(((uint64_t) (arg)) >> 1) & 0x1, \
	((uint64_t) (arg)) & 0x1
#else
#define PRAb64(arg) (u64) (arg)
#endif /* !defined(PRIb64) ... */

/**
 * The handler of an I/O operation, implementing a method to process it.
 */
struct sys_iohandler {
	/** The context that is passed to @ref fsapi_iohandler::handle_io. */
	void *context;

	/**
	 * The I/O handler callback function.
	 *
	 * Accepts a device, offset and size and processes I/O as implemented by
	 * the handler.
	 */
	int (*handle_io)(
		void *context,
		sys_device *dev,
		u64 offset,
		size_t size);

	/**
	 * The handler callback function for a hole (a non-allocated part of a
	 * sparse file).
	 *
	 * Accepts a size and processes the hole as implemented by the handler.
	 *
	 * This callback is optional, and should only be non-@p NULL when the
	 * handler has a special way of handling holes.
	 */
	int (*handle_hole)(
		void *context,
		size_t size);

	/**
	 * Copies data from a memory buffer into the I/O handler's backend.
	 */
	int (*copy_data)(
		void *context,
		const void *data,
		size_t size);

	/**
	 * Copies data from the I/O handler's backend to a memory buffer.
	 */
	int (*get_data)(
		void *context,
		void *data,
		size_t size);
};

#endif /* !defined(_REFS_SYS_H) */
