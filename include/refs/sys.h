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

typedef struct sys_iohandler sys_iohandler;

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

#define PRIb8 "d%d%d%d%d%d%d%d"
#define PRIb16 "d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"
#define PRIb32 "d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"
#define PRIb64 \
	"d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d" \
	"d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d"

#define PRAb8(arg) \
	(((uint8_t) (arg)) >> 7) & 0x1, \
	(((uint8_t) (arg)) >> 6) & 0x1, \
	(((uint8_t) (arg)) >> 5) & 0x1, \
	(((uint8_t) (arg)) >> 4) & 0x1, \
	(((uint8_t) (arg)) >> 3) & 0x1, \
	(((uint8_t) (arg)) >> 2) & 0x1, \
	(((uint8_t) (arg)) >> 1) & 0x1, \
	((uint8_t) (arg)) & 0x1
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
