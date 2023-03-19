/*-
 * sys.h - Lightweight abstractions for system functionality.
 *
 * Copyright (c) 2022-2023 Erik Larsson
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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#ifdef __linux__
#include <linux/fs.h>
#endif
#ifdef __APPLE__
#include <sys/disk.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef u16 le16;
typedef u32 le32;
typedef u64 le64;

typedef le16 refschar;

static inline u16 le16_to_cpup(const le16 *const value)
{
	return (((u16) ((const u8*) value)[1]) << 8) |
		((u16) ((const u8*) value)[0]);
}

static inline u32 le32_to_cpup(const le32 *const value)
{
	return (((u32) ((const u8*) value)[3]) << 24) |
		(((u32) ((const u8*) value)[2]) << 16) |
		(((u32) ((const u8*) value)[1]) << 8) |
		((u32) ((const u8*) value)[0]);
}

static inline u64 le64_to_cpup(const le64 *const value)
{
	return (((u64) ((const u8*) value)[7]) << 56) |
		(((u64) ((const u8*) value)[6]) << 48) |
		(((u64) ((const u8*) value)[5]) << 40) |
		(((u64) ((const u8*) value)[4]) << 32) |
		(((u64) ((const u8*) value)[3]) << 24) |
		(((u64) ((const u8*) value)[2]) << 16) |
		(((u64) ((const u8*) value)[1]) << 8) |
		((u64) ((const u8*) value)[0]);
}

static inline u16 le16_to_cpu(const le16 value)
{
	return le16_to_cpup(&value);
}

static inline u32 le32_to_cpu(const le32 value)
{
	return le32_to_cpup(&value);
}

static inline u64 le64_to_cpu(const le64 value)
{
	return le64_to_cpup(&value);
}

static inline le16 cpu_to_le16(const u16 value)
{
	le16 result = 0;

	((u8*) &result)[0] = value & 0xFF;
	((u8*) &result)[1] = (value >> 8) & 0xFF;

	return result;
}

static inline le32 cpu_to_le32(const u32 value)
{
	le32 result = 0;

	((u8*) &result)[0] = value & 0xFF;
	((u8*) &result)[1] = (value >> 8) & 0xFF;
	((u8*) &result)[2] = (value >> 16) & 0xFF;
	((u8*) &result)[3] = (value >> 24) & 0xFF;

	return result;
}

static inline le64 cpu_to_le64(const u64 value)
{
	le64 result = 0;

	((u8*) &result)[0] = value & 0xFF;
	((u8*) &result)[1] = (value >> 8) & 0xFF;
	((u8*) &result)[2] = (value >> 16) & 0xFF;
	((u8*) &result)[3] = (value >> 24) & 0xFF;
	((u8*) &result)[4] = (value >> 32) & 0xFF;
	((u8*) &result)[5] = (value >> 40) & 0xFF;
	((u8*) &result)[6] = (value >> 48) & 0xFF;
	((u8*) &result)[7] = (value >> 56) & 0xFF;

	return result;
}

static inline u8 sys_fls64(u64 value)
{
#ifdef HAVE_FLSLL
	return (u8) flsll((long long) value);
#elif defined(__GNUC__)
	return (sizeof(value) * 8) - 1 -__builtin_clzll((long long) value);
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

#ifndef SYS_LOG_DEBUG_ENABLED
#define SYS_LOG_DEBUG_ENABLED 0
#endif

#ifndef SYS_LOG_TRACE_ENABLED
#define SYS_LOG_TRACE_ENABLED 0
#endif

static inline void sys_log_noop(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static inline void sys_log_noop(const char *const fmt, ...)
{
	(void) fmt;
}

static inline void sys_log_pnoop(int err, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static inline void sys_log_pnoop(int err, const char *const fmt, ...)
{
	(void) fmt;
}

#if SYS_LOG_CRITICAL_ENABLED
#define sys_log_critical(fmt, ...) \
	fprintf(stderr, "[CRITICAL] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_critical sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_error(fmt, ...) \
	fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_error sys_log_noop
#endif

#if SYS_LOG_ERROR_ENABLED
#define sys_log_perror(err, fmt, ...) \
	fprintf(stderr, "[ERROR] " fmt ": %s\n", ##__VA_ARGS__, strerror(err))
#else
#define sys_log_perror sys_log_pnoop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_warning(fmt, ...) \
	fprintf(stderr, "[WARNING] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_warning sys_log_noop
#endif

#if SYS_LOG_WARNING_ENABLED
#define sys_log_pwarning(err, fmt, ...) \
	fprintf(stderr, "[WARNING] " fmt ": %s\n", ##__VA_ARGS__, strerror(err))
#else
#define sys_log_pwarning sys_log_pnoop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_debug(fmt, ...) \
	fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_debug sys_log_noop
#endif

#if SYS_LOG_DEBUG_ENABLED
#define sys_log_pdebug(err, fmt, ...) \
	fprintf(stderr, "[DEBUG] " fmt ": %s\n", ##__VA_ARGS__, strerror(err))
#else
#define sys_log_pdebug sys_log_pnoop
#endif

#if SYS_LOG_TRACE_ENABLED
#define sys_log_trace(fmt, ...) \
	fprintf(stderr, "[TRACE] " fmt "\n", ##__VA_ARGS__)
#else
#define sys_log_trace sys_log_noop
#endif

#define SYS_TRUE 1
#define SYS_FALSE 0
#define sys_bool u8

#define sys_min(a, b) ((a) < (b) ? (a) : (b))
#define sys_max(a, b) ((a) > (b) ? (a) : (b))

static inline int _sys_malloc(size_t size, void **out_ptr)
{
	return (*out_ptr = malloc(size)) ? 0 : errno;
}

#define sys_malloc(size, out_ptr) \
	_sys_malloc((size), (void**) (out_ptr))

static inline int _sys_calloc(size_t size, void **out_ptr)
{
	return (*out_ptr = calloc(1, size)) ? 0 : errno;
}

#define sys_calloc(size, out_ptr) \
	_sys_calloc((size), (void**) (out_ptr))

static inline int _sys_realloc(void *cur_ptr, size_t size, void **out_ptr)
{
	return (*out_ptr = realloc(cur_ptr, size)) ? 0 : errno;
}

#define sys_realloc(cur_ptr, size, out_ptr) \
	_sys_realloc((cur_ptr), (size), (void**) (out_ptr))

static inline void _sys_free(void **out_ptr)
{
	free(*out_ptr);
	*out_ptr = NULL;
}

#define sys_free(out_ptr) \
	_sys_free((void**) (out_ptr))

#define PRIuz "zu"
#define PRIXz "zX"
#define PRIbs ".*s"

#define PRAuz(arg) ((size_t) (arg))
#define PRAXz(arg) ((size_t) (arg))
#define PRAbs(precision, arg) ((int) (precision)), ((const char*) (arg))
#define PRAu8(arg) ((uint8_t) (arg))
#define PRAX8(arg) ((uint8_t) (arg))
#define PRAu16(arg) ((uint16_t) (arg))
#define PRAX16(arg) ((uint16_t) (arg))
#define PRAd32(arg) ((int32_t) (arg))
#define PRAu32(arg) ((uint32_t) (arg))
#define PRAX32(arg) ((uint32_t) (arg))
#define PRAd64(arg) ((int64_t) (arg))
#define PRAu64(arg) ((uint64_t) (arg))
#define PRAx64(arg) ((uint64_t) (arg))
#define PRAX64(arg) ((uint64_t) (arg))

#define PRI0PAD(precision) "0" #precision
#define PRIPAD(precision) #precision

int sys_unistr_decode(const refschar *ins, size_t ins_len,
		char **outs, size_t *outs_len);

int sys_unistr_encode(const char *ins, size_t ins_len,
		refschar **outs, size_t *outs_len);

typedef void sys_device;

static inline int sys_device_open(sys_device **const dev,
		const char *const path)
{
	int err = 0;
	int fd = -1;

	fd = open(path, O_RDONLY);
	if(fd == -1) {
		err = errno;
	}
	else {
		*dev = (void*) ((intptr_t) fd);
	}

	return err;
}

static inline int sys_device_close(sys_device **const dev)
{
	int err = 0;

	if(close((int) ((intptr_t) *dev))) {
		err = errno;
	}
	else {
		*dev = (void*) ((intptr_t) -1);
	}

	return err;
}

static inline int sys_device_pread(sys_device *const dev, const u64 offset,
		const size_t nbytes, void *const buf)
{
	int err = 0;
	ssize_t res;

	if(offset < 0 || offset > INT64_MAX || nbytes > SSIZE_MAX) {
		return EINVAL;
	}

	res = pread(
		(int) ((intptr_t) dev),
		buf,
		nbytes,
		(off_t) offset);
	if(res < 0) {
		err = errno;
	}
	else if((size_t) res != nbytes) {
		err = EIO;
	}

	return err;
}

static inline int sys_device_get_sector_size(sys_device *const dev,
		u32 *out_sector_size)
{
	int err = 0;

#ifdef __linux__
	int sector_size = 0;

	if(ioctl((int) ((intptr_t) dev), BLKSSZGET, &sector_size)) {
		err = errno;
	}
	else {
		*out_sector_size = sector_size;
	}
#endif

#ifdef __APPLE__
	uint32_t block_size = 0;

	if(ioctl((int) ((intptr_t) dev), DKIOCGETBLOCKSIZE, &block_size)) {
		err = errno;
	}
	else {
		*out_sector_size = block_size;
	}
#endif

	return err;
}

static inline int sys_device_get_size(sys_device *const dev,
		u64 *out_size)
{
	int err = 0;
	struct stat st;

	if(!fstat((int) ((intptr_t) dev), &st) &&
		(st.st_mode & S_IFMT) == S_IFREG)
	{
		/* Regular file, size can be obtained through stat. */
		*out_size = st.st_size;
		return 0;
	}

#ifdef __linux__
	uint64_t device_size = 0;

	if(ioctl((int) ((intptr_t) dev), BLKGETSIZE64, &device_size)) {
		err = errno;
	}
	else {
		*out_size = device_size;
	}
#endif

#ifdef __APPLE__
	uint32_t block_size = 0;

	if(ioctl((int) ((intptr_t) dev), DKIOCGETBLOCKSIZE, &block_size)) {
		err = errno;
	}
	else {
		uint64_t block_count = 0;

		if(ioctl((int) ((intptr_t) dev), DKIOCGETBLOCKCOUNT,
			&block_count))
		{
			err = errno;
		}
		else {
			*out_size = block_size * block_count;
		}
	}
#endif

	return err;
}

#endif /* !defined(_REFS_SYS_H) */
