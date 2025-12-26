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
