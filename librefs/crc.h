/*-
 * crc.h - ReFS metadata checksum declarations.
 *
 * Copyright (c) 2025 Erik Larsson
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

#ifndef _REFS_CRC_H
#define _REFS_CRC_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sys.h"

/**
 * The checksum type stored in a node reference's checksum descriptor.
 *
 * The type is carried in bits 16-23 of the 64-bit field that this code
 * reads as the reference's 'flags', for both v1 and v3 references.
 *
 * Type 2 (CRC-64/NVME) is used by the level 2 and higher blocks, whose
 * checksums are stored in the referencing parent. Nothing verifies those
 * yet, so no CRC-64 implementation is provided here.
 */
#define REFS_CHECKSUM_TYPE_CRC32C 1

#define REFS_CHECKSUM_TYPE_FROM_FLAGS(flags) \
	((u8) (((flags) >> 16) & 0xFFU))

/**
 * Compute a CRC-32C (Castagnoli) checksum.
 *
 * Follows the zlib convention: pass 0 as @crc to start a new checksum and
 * the previous return value to continue one, so that a checksum can be
 * computed over discontiguous pieces.
 *
 * @param crc the running checksum, or 0 to start a new one.
 * @param data the data to checksum.
 * @param size the size of @p data in bytes.
 *
 * @return the updated checksum.
 */
u32 refs_crc32c(u32 crc, const void *data, size_t size);

#endif /* !defined(_REFS_CRC_H) */
