/*-
 * sys_linux.h - Lightweight abstractions for system functionality (Linux).
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

#ifndef _REFS_SYS_LINUX_H
#define _REFS_SYS_LINUX_H

#include <linux/fs.h>
#include <linux/slab.h>

#define UINT32_MAX U32_MAX

#define ENOTSUP ENOTSUPP

typedef __le16 le16;
typedef __le32 le32;
typedef __le64 le64;

typedef le16 refschar;

typedef struct {
	u64 tv_sec;
	u32 tv_nsec;
} sys_timespec;

/* Note: Identical to sys.h, should be in a common header. */
static inline u8 sys_fls64(u64 value)
{
#ifdef HAVE_FLSLL
	return (u8) flsll((long long) value);
#elif defined(__GNUC__)
	return (sizeof(value) * 8) - __builtin_clzll((long long) value);
#else
	u8 index = 1;

	if(!value) {
		return 0;
	}

	if((value & 0xFFFFFFFF00000000ULL)) {
		value >>= 32;
		index += 32;
	}

	if((value & 0xFFFF0000UL)) {
		value >>= 16;
		index += 16;
	}

	if((value & 0xFF00U)) {
		value >>= 8;
		index += 8;
	}

	if((value & 0xF0U)) {
		value >>= 4;
		index += 4;
	}

	if((value & 0xCU)) {
		value >>= 2;
		index += 2;
	}

	if((value & 0x2U)) {
		value >>= 1;
		index += 1;
	}

	return index;
#endif /* defined(HAVE_FLSLL) ... */
}

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

const char* sys_strerror(int err);

/**
 * No-op log handler that only exists to be able to statically check the format
 * string and arguments for errors when logging is turned off.
 *
 * @param[in] fmt
 *      @p printf format string for constructing the log message.
 * @param[in] ...
 *      Arguments to the @p printf format string (if any).
 */
static inline void sys_log_noop(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static inline void sys_log_noop(const char *const fmt, ...)
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
static inline void sys_log_pnoop(int err, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static inline void sys_log_pnoop(int err, const char *const fmt, ...)
{
	(void) err;
	(void) fmt;
}

#if SYS_LOG_CRITICAL_ENABLED
#define sys_log_critical(fmt, ...) \
	printk(KERN_CRIT "[CRITICAL] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_critical sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_error(fmt, ...) \
	printk(KERN_ERR "[ERROR] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_error sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_perror(err, fmt, ...) \
	printk(KERN_ERR "[ERROR] " fmt ": %s\n", ##__VA_ARGS__, \
		sys_strerror(err))
#else
#define sys_log_perror sys_log_pnoop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_warning(fmt, ...) \
	printk(KERN_WARNING "[WARNING] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_warning sys_log_noop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_pwarning(err, fmt, ...) \
	printk(KERN_WARNING "[WARNING] " fmt ": %s\n", ##__VA_ARGS__, \
		sys_strerror(err))
#else
#define sys_log_pwarning sys_log_pnoop
#endif

#if SYS_LOG_INFO_ENABLED
#define sys_log_info(fmt, ...) \
	printk(KERN_INFO fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_info sys_log_noop
#endif

#if SYS_LOG_INFO_ENABLED
#define sys_log_pinfo(err, fmt, ...) \
	printk(KERN_INFO fmt ": %s\n", ##__VA_ARGS__, sys_strerror(err))
#else
#define sys_log_pinfo sys_log_pnoop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_debug(fmt, ...) \
	printk(KERN_DEBUG "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_debug sys_log_noop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_pdebug(err, fmt, ...) \
	printk(KERN_DEBUG "[DEBUG] " fmt ": %s\n", ##__VA_ARGS__, \
		sys_strerror(err))
#else
#define sys_log_pdebug sys_log_pnoop
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_trace(fmt, ...) \
	printk(KERN_DEBUG "[TRACE] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_trace sys_log_noop
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_ptrace(err, fmt, ...) \
	printk(KERN_DEBUG "[TRACE] " fmt ": %s\n", ##__VA_ARGS__, \
		sys_strerror(err))
#else
#define sys_log_ptrace sys_log_pnoop
#endif

#define SYS_TRUE 1
#define SYS_FALSE 0
#define sys_bool u8

#define sys_min(a, b) ((a) < (b) ? (a) : (b))
#define sys_max(a, b) ((a) > (b) ? (a) : (b))

static inline int _sys_malloc(size_t size, void **out_ptr)
{
	return (*out_ptr = kmalloc(size, GFP_KERNEL)) ? 0 : ENOMEM;
}

#define sys_malloc(size, out_ptr) \
	_sys_malloc((size), (void**) (out_ptr))

static inline int _sys_calloc(size_t size, void **out_ptr)
{
	return (*out_ptr = kzalloc(size, GFP_KERNEL)) ? 0 : ENOMEM;
}

#define sys_calloc(size, out_ptr) \
	_sys_calloc((size), (void**) (out_ptr))

static inline int _sys_realloc(void *cur_ptr, size_t size, void **out_ptr)
{
	return (*out_ptr = krealloc(cur_ptr, size, GFP_KERNEL)) ? 0 : ENOMEM;
}

#define sys_realloc(cur_ptr, size, out_ptr) \
	_sys_realloc((cur_ptr), (size), (void**) (out_ptr))

static inline void _sys_free(void **out_ptr)
{
	kfree(*out_ptr);
	*out_ptr = NULL;
}

#define sys_free(out_ptr) \
	_sys_free((void**) (out_ptr))

static inline int sys_strndup(const char *str, size_t len, char **dupstr)
{
	int err = 0;

	if(!(*dupstr = kstrndup(str, len, GFP_KERNEL))) {
		err = ENOMEM;
	}

	return err;
}

#define PRIdz "zd"
#define PRIuz "zu"
#define PRIXz "zX"
#define PRIbs ".*s"
#define PRIo8 "hho"
#define PRId8 "hhd"
#define PRIu8 "hhu"
#define PRIx8 "hhx"
#define PRIX8 "hhX"
#define PRIo16 "ho"
#define PRId16 "hd"
#define PRIu16 "hu"
#define PRIx16 "hx"
#define PRIX16 "hX"
#define PRIo32 "lo"
#define PRId32 "ld"
#define PRIu32 "lu"
#define PRIx32 "lx"
#define PRIX32 "lX"
#define PRIo64 "llo"
#define PRId64 "lld"
#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRIX64 "llX"

#define PRAoz(arg) ((size_t) (arg))
#define PRAdz(arg) ((ssize_t) (arg))
#define PRAuz(arg) ((size_t) (arg))
#define PRAxz(arg) ((size_t) (arg))
#define PRAXz(arg) ((size_t) (arg))
#define PRAbs(precision, arg) ((int) (precision)), ((const char*) (arg))
#define PRAo8(arg) ((unsigned char) (arg))
#define PRAd8(arg) ((char) (arg))
#define PRAu8(arg) ((unsigned char) (arg))
#define PRAx8(arg) ((unsigned char) (arg))
#define PRAX8(arg) ((unsigned char) (arg))
#define PRAo16(arg) ((unsigned short) (arg))
#define PRAd16(arg) ((short) (arg))
#define PRAu16(arg) ((unsigned short) (arg))
#define PRAx16(arg) ((unsigned short) (arg))
#define PRAX16(arg) ((unsigned short) (arg))
#define PRAo32(arg) ((unsigned long) (arg))
#define PRAd32(arg) ((long) (arg))
#define PRAu32(arg) ((unsigned long) (arg))
#define PRAx32(arg) ((unsigned long) (arg))
#define PRAX32(arg) ((unsigned long) (arg))
#define PRAo64(arg) ((unsigned long long) (arg))
#define PRAd64(arg) ((long long) (arg))
#define PRAu64(arg) ((unsigned long long) (arg))
#define PRAx64(arg) ((unsigned long long) (arg))
#define PRAX64(arg) ((unsigned long long) (arg))

#define PRI0PAD(precision) "0" #precision
#define PRIPAD(precision) #precision

int sys_unistr_decode(const refschar *ins, size_t ins_len,
		char **outs, size_t *outs_len);

int sys_unistr_encode(const char *ins, size_t ins_len,
		refschar **outs, size_t *outs_len);

typedef void sys_device;

static inline int sys_device_open(sys_device **const dev,
		struct super_block *const sb)
{
	*dev = (void*) sb;
	return 0;
}

static inline int sys_device_close(sys_device **const dev)
{
	*dev = NULL;
	return 0;
}

int sys_device_pread(sys_device *const dev, const u64 offset,
		const size_t nbytes, void *const buf);

int sys_device_pread_iohandler(sys_device *const dev, const u64 offset,
		const size_t nbytes, sys_iohandler *const iohandler);

int sys_device_get_sector_size(sys_device *const dev,
		u32 *const out_sector_size);

int sys_device_get_size(sys_device *const dev, u64 *const out_size);

#endif /* !defined(_REFS_SYS_H) */
