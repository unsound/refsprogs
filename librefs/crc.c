/*-
 * crc.c - ReFS metadata checksum definitions.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "crc.h"

/* Reflected polynomial, matching the reflected input/output form that ReFS
 * uses: CRC-32C 0x1EDC6F41 reflected -> 0x82F63B78, with an all-ones initial
 * value and an all-ones final XOR. */
#define REFS_CRC32C_POLY 0x82F63B78U

/* This is deliberately the simple bitwise formulation. It is only used to
 * validate a bounded number of blocks while selecting a checkpoint, so the
 * table-driven variant is not worth the space here. If checksum verification
 * is ever extended to every block read, revisit this. */

u32 refs_crc32c(u32 crc, const void *const data, const size_t size)
{
	const u8 *const p = (const u8*) data;

	u32 c = ~crc;
	size_t i = 0;
	int k = 0;

	for(i = 0; i < size; ++i) {
		c ^= p[i];
		for(k = 0; k < 8; ++k) {
			c = (c & 1) ? ((c >> 1) ^ REFS_CRC32C_POLY) : (c >> 1);
		}
	}

	return ~c;
}
