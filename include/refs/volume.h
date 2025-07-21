/*-
 * volume.h - ReFS volume handling declarations.
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

#ifndef _REFS_VOLUME_H
#define _REFS_VOLUME_H

typedef struct refs_volume refs_volume;

#include "layout.h"
#include "node.h"
#include "sys.h"

struct refs_volume {
	sys_device *dev;
	REFS_BOOT_SECTOR *bs;
	size_t bs_size;
	u32 sector_size;
	u32 cluster_size;
	u32 metadata_block_size;
	u64 sector_count;
	u64 cluster_count;
	REFS_SUPERBLOCK_HEADER *sb;
	REFS_LEVEL1_NODE *primary_level1_node;
	REFS_LEVEL1_NODE *secondary_level1_node;
	refs_block_map *block_map;
};

int refs_volume_create(
		sys_device *dev,
		refs_volume **out_vol);

void refs_volume_destroy(
		refs_volume **out_vol);

int refs_volume_lookup_by_posix_path(
		refs_volume *vol,
		const char *path,
		size_t path_length,
		const u64 *start_object_id,
		u64 *out_parent_directory_object_id,
		u64 *out_directory_object_id,
		sys_bool *out_is_short_entry,
		u8 **out_key,
		size_t *out_key_size,
		u8 **out_record,
		size_t *out_record_size);

int refs_volume_lookup_by_object_id(
		refs_volume *vol,
		u64 object_id,
		refs_node **out_node);

int refs_volume_generate_metadata_bitmap(
		refs_volume *vol,
		u8 **bitmap,
		size_t *bitmap_size);

static inline refs_node_crawl_context refs_volume_init_node_crawl_context(
		refs_volume *const vol)
{
	return refs_node_crawl_context_init(
		/* sys_device *dev */
		vol->dev,
		/* REFS_BOOT_SECTOR *bs */
		vol->bs,
		/* refs_block_map *block_map */
		vol->block_map,
		/* u32 cluster_size */
		vol->cluster_size,
		/* u32 block_size */
		vol->metadata_block_size,
		/* u32 block_index_unit */
		(vol->bs->version_major == 1) ? 16384 : vol->cluster_size,
		/* u8 version_major */
		vol->bs->version_major,
		/* u8 version_minor */
		vol->bs->version_minor);
}

#endif /* !defined(_REFS_VOLUME_H) */
